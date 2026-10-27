"""RSU for the VANET PQC + IDS demo.

Decrypts/authenticates packets, verifies ML-DSA signatures, runs replay/Sybil/DoS
rules and the existing Random Forest IDS, then forwards valid in-range messages.
Browser-demo packets receive an acknowledgement containing actual RSU stage results.
"""
import json
import os
import socket
import sys
import time

import oqs

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from attacks.dos import DoSDetector
from attacks.replay import ReplayDetector
from attacks.sybil import SybilDetector
from ids.detector import VANETIDS
from ids.risk_response import RiskResponse
from security.secure_channel import KEM_ALGORITHM, decrypt_from_vehicle, verify_mldsa_message
from simulator.geography import distance_m

RSU_HOST = os.environ.get("VANET_RSU_HOST", "127.0.0.1")
RSU_PORT = int(os.environ.get("VANET_RSU_PORT", "5002"))
RSU_X = float(os.environ.get("VANET_RSU_X", "500.0"))
RSU_Y = float(os.environ.get("VANET_RSU_Y", "500.0"))
COMMUNICATION_RANGE_M = float(os.environ.get("VANET_RSU_RANGE_M", "500"))
FORWARD_HOST = os.environ.get("VANET_FORWARD_HOST", "127.0.0.1")
FORWARD_PORT = int(os.environ.get("VANET_FORWARD_PORT", "5200"))
PUBLIC_KEY_PATH = os.path.join(PROJECT_ROOT, "results", "rsu_mlkem_public_key.bin")


def main():
    os.makedirs(os.path.dirname(PUBLIC_KEY_PATH), exist_ok=True)
    with oqs.KeyEncapsulation(KEM_ALGORITHM) as rsu_kem:
        public_key = rsu_kem.generate_keypair()
        temp_path = PUBLIC_KEY_PATH + ".tmp"
        with open(temp_path, "wb") as handle:
            handle.write(public_key)
        os.replace(temp_path, PUBLIC_KEY_PATH)

        replay_detector = ReplayDetector()
        sybil_detector = SybilDetector()
        dos_detector = DoSDetector(max_messages=5, time_window=2)
        risk_engine = RiskResponse()
        try:
            ai_ids = VANETIDS(model_path=os.path.join(PROJECT_ROOT, "results", "vanet_ids_model.pkl"))
        except Exception as exc:
            print(f"[WARNING] AI IDS model unavailable; rule checks remain active: {exc}")
            ai_ids = None

        known_vehicles = {}
        last_message_by_sender = {}
        last_direction_by_sender = {}
        forward_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        receive_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        receive_sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024 * 1024)
        receive_sock.bind((RSU_HOST, RSU_PORT))
        receive_sock.settimeout(1.0)

        def respond(address, demo_id, stages, result):
            if not demo_id:
                return
            packet = {"type": "VANET_RSU_ACK", "demo_id": demo_id,
                      "result": {**result, "stages": stages}}
            try:
                receive_sock.sendto(json.dumps(packet, separators=(",", ":")).encode("utf-8"), address)
            except OSError as exc:
                print(f"[WARNING] Could not send browser acknowledgement: {exc}")

        def stage(stages, name, status, detail):
            stages.append({"name": name, "status": status, "detail": str(detail)})

        def skipped(stages, names, reason):
            for name in names:
                stage(stages, name, "skipped", reason)

        print("=" * 64)
        print("VANET PQC RSU SERVER")
        print(f"Listen endpoint : {RSU_HOST}:{RSU_PORT}")
        print(f"RSU coordinates : ({RSU_X:.1f}, {RSU_Y:.1f}) m")
        print(f"Forwarding range: {COMMUNICATION_RANGE_M:.1f} m")
        print(f"ML-KEM public key: {PUBLIC_KEY_PATH}")
        print("Waiting for encrypted vehicle messages...")
        print("=" * 64)

        try:
            while True:
                try:
                    raw, address = receive_sock.recvfrom(65507)
                except socket.timeout:
                    continue
                except KeyboardInterrupt:
                    break

                demo_id = None
                stages = []
                stage_names_after_crypto = ["Replay detection", "Sybil heuristic", "DoS rate check",
                                            "AI IDS classification", "Risk + geographic forwarding"]
                try:
                    envelope = json.loads(raw.decode("utf-8"))
                    demo_id = envelope.get("_frontend_demo_id")
                    try:
                        payload = decrypt_from_vehicle(envelope, rsu_kem)
                    except Exception as exc:
                        stage(stages, "RSU decapsulation + decryption", "failed", f"Decryption/authentication rejected: {type(exc).__name__}")
                        skipped(stages, ["ML-DSA-65 verification", *stage_names_after_crypto], "Ciphertext was not authenticated")
                        print(f"\n[REJECT] Secure-channel authentication failed from {address}: {type(exc).__name__}")
                        respond(address, demo_id, stages, {"decision": "COMPROMISED PACKET REJECTED", "accepted": False,
                                "reason": "ML-KEM/AES-256-GCM decryption or authentication failed", "event_alert": False, **risk_engine.assess("TAMPERING")})
                        continue

                    message = payload["message"]
                    sender = str(message["sender_id"])
                    pos = message["position"]
                    event = str(message.get("event") or "").strip()
                    is_safety_event = bool(event and str(message.get("message_type", "")).upper() == "DENM")
                    print(f"\n[RECEIVED] {sender} from {address}")
                    print("[CRYPTO] ML-KEM decapsulation + AES-256-GCM authentication passed")
                    stage(stages, "RSU decapsulation + decryption", "passed", "ML-KEM-768 decapsulation and AES-256-GCM authentication passed")

                    try:
                        signature_valid = verify_mldsa_message(message)
                    except Exception:
                        signature_valid = False
                    if not signature_valid:
                        stage(stages, "ML-DSA-65 verification", "failed", "Invalid signature; message rejected")
                        skipped(stages, stage_names_after_crypto, "Invalid ML-DSA-65 signature")
                        print(f"[ALERT] COMPROMISED MESSAGE: invalid ML-DSA-65 signature for {sender}; rejected")
                        result = risk_engine.assess("TAMPERING")
                        print(f"  Risk Level  : {result['risk']}")
                        print(f"  Attack Class: {result['class']}")
                        print(f"  Response    : {result['response']}")
                        print("  Decision    : MESSAGE REJECTED - NOT FORWARDED")
                        respond(address, demo_id, stages, {"decision": "COMPROMISED MESSAGE REJECTED", "accepted": False,
                                "reason": "Invalid ML-DSA-65 signature; message was not forwarded", "event_alert": False,
                                "sender": sender, **result})
                        continue
                    print(f"[CRYPTO] ML-DSA-65 signature verified for {sender}")
                    stage(stages, "ML-DSA-65 verification", "passed", "ML-DSA-65 signature verified")

                    class ReplayRecord: pass
                    replay_record = ReplayRecord()
                    replay_record.sender_id = sender
                    replay_record.sequence_number = int(message["sequence_number"])
                    if not replay_detector.check_message(replay_record):
                        stage(stages, "Replay detection", "alert", "Duplicate or stale sequence number")
                        skipped(stages, ["Sybil heuristic", "DoS rate check", "AI IDS classification", "Risk + geographic forwarding"], "Replay detected; processing stopped")
                        print(f"[ALERT] REPLAY detected: {sender}")
                        result = risk_engine.assess("REPLAY")
                        respond(address, demo_id, stages, {"decision": "REPLAY ATTACK REJECTED", "accepted": False,
                                "reason": "Duplicate or stale sequence number", "event_alert": False, **result})
                        continue
                    stage(stages, "Replay detection", "passed", f"Sequence {replay_record.sequence_number} accepted")

                    # Explicit vehicle-behaviour checks for the controlled demo.
                    # The speed threshold is configurable; direction changes use
                    # the shortest angular difference (e.g. 359° -> 1° is 2°).
                    speed_limit = float(os.environ.get("VANET_SPEED_LIMIT_KMH", "60"))
                    try:
                        speed = float(message.get("speed", 0.0))
                        direction = float(message.get("direction", 0.0)) % 360.0
                    except (TypeError, ValueError):
                        speed, direction = float("inf"), 0.0

                    if speed > speed_limit:
                        detail = f"Reported speed {speed:.1f} km/h exceeds {speed_limit:.1f} km/h"
                        stage(stages, "Vehicle behaviour checks", "alert", detail)
                        skipped(stages, ["Sybil heuristic", "DoS rate check", "AI IDS classification", "Risk + geographic forwarding"], "Overspeed rule triggered; processing stopped")
                        result = risk_engine.assess("OVERSPEED")
                        print(f"[ALERT] OVERSPEED: {sender}")
                        print(f"  Details     : {detail}")
                        print(f"  Risk Level  : {result['risk']}")
                        print(f"  Attack Class: {result['class']}")
                        print(f"  Response    : {result['response']}")
                        print("  Decision    : MESSAGE REJECTED - NOT FORWARDED")
                        respond(address, demo_id, stages, {"decision": "OVERSPEED ALERT - MESSAGE NOT FORWARDED", "accepted": False,
                                "reason": detail, "event_alert": False, "sender": sender, **result})
                        continue

                    previous_direction = last_direction_by_sender.get(sender)
                    if previous_direction is not None:
                        delta = abs(direction - previous_direction)
                        delta = min(delta, 360.0 - delta)
                        direction_limit = float(os.environ.get("VANET_DIRECTION_CHANGE_LIMIT_DEG", "120"))
                        if delta >= direction_limit:
                            detail = f"Direction changed by {delta:.1f} degrees (limit {direction_limit:.1f})"
                            stage(stages, "Vehicle behaviour checks", "alert", detail)
                            skipped(stages, ["Sybil heuristic", "DoS rate check", "AI IDS classification", "Risk + geographic forwarding"], "Sudden direction-change rule triggered; processing stopped")
                            result = risk_engine.assess("SUDDEN_DIRECTION_CHANGE")
                            print(f"[ALERT] SUDDEN DIRECTION CHANGE: {sender}")
                            print(f"  Details     : {detail}")
                            print(f"  Risk Level  : {result['risk']}")
                            print(f"  Attack Class: {result['class']}")
                            print(f"  Response    : {result['response']}")
                            print("  Decision    : MESSAGE REJECTED - NOT FORWARDED")
                            respond(address, demo_id, stages, {"decision": "SUDDEN DIRECTION CHANGE ALERT - MESSAGE NOT FORWARDED", "accepted": False,
                                    "reason": detail, "event_alert": False, "sender": sender, **result})
                            continue
                    last_direction_by_sender[sender] = direction
                    stage(stages, "Vehicle behaviour checks", "passed", f"Speed {speed:.1f} km/h within limit; direction consistent")

                    class LocationRecord: pass
                    location_record = LocationRecord()
                    location_record.sender_id = sender
                    location_record.x = float(pos["x"])
                    location_record.y = float(pos["y"])
                    if not sybil_detector.check_message(location_record):
                        stage(stages, "Sybil heuristic", "alert", f"Multiple pseudonyms claim position ({pos['x']}, {pos['y']})")
                        skipped(stages, ["DoS rate check", "AI IDS classification", "Risk + geographic forwarding"], "Sybil heuristic triggered")
                        print(f"[ALERT] SYBIL heuristic triggered at ({pos['x']}, {pos['y']})")
                        result = risk_engine.assess("SYBIL")
                        respond(address, demo_id, stages, {"decision": "SYBIL ACTIVITY REJECTED", "accepted": False,
                                "reason": "Multiple pseudonyms claimed the same location", "event_alert": False, **result})
                        continue
                    stage(stages, "Sybil heuristic", "passed", "No conflicting pseudonym at this position")

                    if not dos_detector.check_message(sender):
                        stage(stages, "DoS rate check", "alert", "Sender exceeded 5 messages in 2 seconds")
                        skipped(stages, ["AI IDS classification", "Risk + geographic forwarding"], "Flooding threshold exceeded")
                        print(f"[ALERT] DOS/flooding threshold exceeded: {sender}")
                        result = risk_engine.assess("DOS")
                        respond(address, demo_id, stages, {"decision": "DOS/FLOODING REJECTED", "accepted": False,
                                "reason": "Sender exceeded the configured message-rate threshold", "event_alert": False, **result})
                        continue
                    stage(stages, "DoS rate check", "passed", "Sender is within the configured message-rate threshold")

                    ai_result = None
                    if ai_ids is not None:
                        ai_result = ai_ids.predict(message, last_message_by_sender.get(sender))
                        last_message_by_sender[sender] = message
                        ai_detail = f"Random Forest: {ai_result['class']} (confidence={ai_result['confidence']:.3f})"
                        print(f"[AI IDS] {ai_detail}")
                        stage(stages, "AI IDS classification", "passed", ai_detail)
                        if ai_result["class"] != "NORMAL" and not is_safety_event:
                            print(f"[ALERT] AI IDS detected {ai_result['class']} activity; not forwarding")
                            risk = risk_engine.assess(ai_result["class"])
                            stage(stages, "Risk + geographic forwarding", "alert", f"AI IDS classified {ai_result['class']}; message not forwarded")
                            respond(address, demo_id, stages, {"decision": f"{ai_result['class']} ACTIVITY DETECTED", "accepted": False,
                                    "reason": "AI IDS classified the message as anomalous", "event_alert": False,
                                    "ai_class": ai_result["class"], "confidence": ai_result["confidence"], **risk})
                            continue
                    else:
                        stage(stages, "AI IDS classification", "skipped", "AI IDS model unavailable; rule checks completed")

                    now = time.time()
                    known_vehicles[sender] = {"x": float(pos["x"]), "y": float(pos["y"]), "last_seen": now}
                    known_vehicles = {key: value for key, value in known_vehicles.items() if now - value["last_seen"] <= 10.0}
                    rsu_location = {"x": RSU_X, "y": RSU_Y}
                    rsu_distance = distance_m(pos, rsu_location)
                    if rsu_distance > COMMUNICATION_RANGE_M:
                        detail = f"Vehicle is {rsu_distance:.1f} m away, outside {COMMUNICATION_RANGE_M:.1f} m range"
                        stage(stages, "Risk + geographic forwarding", "passed", detail + "; not forwarded")
                        print(f"[GEO] Outside RSU range ({rsu_distance:.1f} m); not forwarded")
                        respond(address, demo_id, stages, {"decision": "ACCEPTED — OUTSIDE RSU RANGE", "accepted": True,
                                "reason": detail, "event_alert": False, "ai_class": ai_result["class"] if ai_result else None,
                                "confidence": ai_result["confidence"] if ai_result else None})
                        continue

                    recipients = [key for key, v in known_vehicles.items()
                                  if key != sender and distance_m(pos, v) <= COMMUNICATION_RANGE_M]
                    forward_packet = {
                        "protocol": "VANET-RSU-FORWARD-v1",
                        "packet_type": "SAFETY_ALERT" if is_safety_event else "VEHICLE_STATUS",
                        "source_pseudonym": sender,
                        "message": message,
                        "event": event if is_safety_event else None,
                        "severity": message.get("severity") if is_safety_event else None,
                        "alert_text": f"{event.replace('_', ' ')} reported by {sender}" if is_safety_event else None,
                        "rsu": {"x": RSU_X, "y": RSU_Y},
                        "source_to_rsu_distance_m": round(rsu_distance, 2),
                        "range_m": COMMUNICATION_RANGE_M,
                        "recipient_pseudonyms": recipients,
                        "forwarded_at": time.time(),
                    }
                    forward_sock.sendto(json.dumps(forward_packet, separators=(",", ":")).encode("utf-8"), (FORWARD_HOST, FORWARD_PORT))
                    detail = (f"{event.replace('_', ' ')} forwarded to nearby vehicles; recipients={len(recipients)}" if is_safety_event
                              else f"Valid status accepted within range ({rsu_distance:.1f} m); forwarding packet sent")
                    stage(stages, "Risk + geographic forwarding", "passed", detail)
                    if is_safety_event:
                        print(f"[SAFETY ALERT] {event} | severity={message.get('severity')} | source={sender} | nearby recipients={len(recipients)}")
                        print("[FORWARD] Safety notification sent to the geographic forwarding channel")
                        decision = "ACCIDENT / SAFETY ALERT FORWARDED"
                    else:
                        print(f"[GEO] Accepted within range ({rsu_distance:.1f} m)")
                        print(f"[FORWARD] Sent geographic forwarding packet; known nearby recipients={len(recipients)}")
                        decision = "NORMAL MESSAGE ACCEPTED"
                    respond(address, demo_id, stages, {"decision": decision, "accepted": True,
                            "reason": detail, "event_alert": is_safety_event, "event": event if is_safety_event else None,
                            "severity": message.get("severity") if is_safety_event else None,
                            "ai_class": ai_result["class"] if ai_result else None,
                            "confidence": ai_result["confidence"] if ai_result else None,
                            "recipient_count": len(recipients)})

                except (KeyError, ValueError, TypeError, json.JSONDecodeError) as exc:
                    print(f"[REJECT] Invalid packet/payload: {exc}")
                    if demo_id:
                        stage(stages, "RSU decapsulation + decryption", "failed", f"Invalid packet/payload: {exc}")
                        skipped(stages, ["ML-DSA-65 verification", *stage_names_after_crypto], "Invalid packet/payload")
                        respond(address, demo_id, stages, {"decision": "INVALID MESSAGE REJECTED", "accepted": False, "reason": str(exc), "event_alert": False})
                except Exception as exc:
                    print(f"[REJECT] Cryptographic or processing failure: {type(exc).__name__}: {exc}")
                    if demo_id:
                        stage(stages, "RSU decapsulation + decryption", "failed", f"Processing failure: {type(exc).__name__}")
                        skipped(stages, ["ML-DSA-65 verification", *stage_names_after_crypto], "RSU processing failure")
                        respond(address, demo_id, stages, {"decision": "PROCESSING FAILURE REJECTED", "accepted": False, "reason": type(exc).__name__, "event_alert": False})
        finally:
            receive_sock.close()
            forward_sock.close()
            print("RSU server stopped.")


if __name__ == "__main__":
    main()
