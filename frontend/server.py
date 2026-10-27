"""Local browser dashboard for the existing VANET PQC + RSU + IDS pipeline.

Run from the project root with: py -3.11 .\\frontend\\server.py
The dashboard binds only to 127.0.0.1 and sends real protected UDP packets to the RSU.
"""
import base64
import json
import os
import socket
import sys
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from security.pseudonym import PseudonymManager
from security.secure_channel import encrypt_for_rsu
from simulator.vehicle import Vehicle

HOST = "127.0.0.1"
PORT = int(os.environ.get("VANET_FRONTEND_PORT", "8765"))
RSU_HOST = os.environ.get("VANET_RSU_HOST", "127.0.0.1")
RSU_PORT = int(os.environ.get("VANET_RSU_PORT", "5002"))
PUBKEY_PATH = os.path.join(PROJECT_ROOT, "results", "rsu_mlkem_public_key.bin")

JOBS = {}
JOBS_LOCK = threading.Lock()
VEHICLE_SESSIONS = {}
VEHICLE_LOCK = threading.Lock()

STEP_DEFS = [
    ("Vehicle identity", "Vehicle selected and temporary pseudonym assigned"),
    ("CAM status message", "Position, speed, direction and sequence number prepared"),
    ("ML-DSA-65 signing", "Vehicle signs the canonical message"),
    ("ML-KEM-768 + AES-256-GCM", "Fresh shared secret, HKDF key derivation and authenticated encryption"),
    ("UDP transmission to RSU", "Encrypted envelope sent to the RSU listener"),
    ("RSU decapsulation + decryption", "RSU decapsulates ML-KEM and authenticates AES-GCM"),
    ("ML-DSA-65 verification", "RSU verifies the message signature"),
    ("Replay detection", "Sequence number checked against previously observed messages"),
    ("Sybil heuristic", "Pseudonym and rounded vehicle location checked"),
    ("DoS rate check", "Sender message rate checked against the configured threshold"),
    ("AI IDS classification", "Random Forest predicts a class and confidence"),
    ("Risk + geographic forwarding", "Risk response and RSU range/forwarding decision"),
]


def new_job():
    return {
        "id": uuid.uuid4().hex[:12],
        "state": "running",
        "created_at": time.time(),
        "vehicle": {},
        "message": {},
        "packet_bytes": None,
        "decision": None,
        "error": None,
        "steps": [
            {"number": i + 1, "name": name, "description": desc,
             "status": "pending", "detail": "Waiting", "duration_ms": None}
            for i, (name, desc) in enumerate(STEP_DEFS)
        ],
    }


def update_step(job_id, index, status, detail, start=None):
    with JOBS_LOCK:
        job = JOBS.get(job_id)
        if not job:
            return
        step = job["steps"][index]
        step["status"] = status
        step["detail"] = str(detail)
        if start is not None:
            step["duration_ms"] = round((time.perf_counter() - start) * 1000, 2)


def update_job(job_id, **values):
    with JOBS_LOCK:
        if job_id in JOBS:
            JOBS[job_id].update(values)



def get_vehicle_session(letter, x, y, speed, direction):
    """Reuse a pseudonym, signer and sequence counter for each demo vehicle."""
    vehicle_id = f"Vehicle {letter}"
    with VEHICLE_LOCK:
        if letter not in VEHICLE_SESSIONS:
            manager = PseudonymManager()
            pseudonym = manager.generate_pseudonym(vehicle_id)
            vehicle = Vehicle(vehicle_id, x, y, speed, direction)
            vehicle.set_pseudonym(pseudonym)
            VEHICLE_SESSIONS[letter] = vehicle
        vehicle = VEHICLE_SESSIONS[letter]
        vehicle.x, vehicle.y = x, y
        vehicle.speed, vehicle.direction = speed, direction
        return vehicle

def set_pending_after(job_id, index, detail="Not reached because an earlier RSU check rejected the message"):
    for i in range(index, len(STEP_DEFS)):
        update_step(job_id, i, "skipped", detail)


def _stage_index(stage_name):
    name = stage_name.lower()
    if "kem" in name or "aes-gcm" in name or "decapsulation" in name:
        return 5
    if "mldsa" in name.replace("-", "") or "signature" in name:
        return 6
    if "replay" in name:
        return 7
    if "sybil" in name:
        return 8
    if "dos" in name or "rate" in name or "flood" in name:
        return 9
    if "ids" in name or "random forest" in name:
        return 10
    if "risk" in name or "geo" in name or "forward" in name or "response" in name:
        return 11
    return None


def run_demo(job_id, params):
    starts = {}
    try:
        if not os.path.isfile(PUBKEY_PATH):
            raise RuntimeError("RSU public key not found. Start simulator/rsu_server.py first and wait for it to publish its key.")
        with open(PUBKEY_PATH, "rb") as handle:
            rsu_public_key = handle.read()
        if not rsu_public_key:
            raise RuntimeError("RSU public key file is empty. Restart the RSU server and try again.")

        vehicle_letter = params.get("vehicle", "A")
        vehicle_id = f"Vehicle {vehicle_letter}"
        x = float(params.get("x", 420.0))
        y = float(params.get("y", 420.0))
        speed = max(0.0, min(250.0, float(params.get("speed", 45.0))))
        direction = float(params.get("direction", 90.0)) % 360
        scenario = str(params.get("scenario", "NORMAL")).upper()
        if scenario not in {"NORMAL", "ACCIDENT", "COMPROMISED", "REPLAY", "SYBIL", "DOS"}:
            scenario = "NORMAL"
        event = "ACCIDENT" if scenario == "ACCIDENT" else ""
        severity = str(params.get("severity", "HIGH")).upper()
        if severity not in {"LOW", "MEDIUM", "HIGH"}:
            severity = "LOW"

        starts[0] = time.perf_counter()
        vehicle = get_vehicle_session(vehicle_letter, x, y, speed, direction)
        pseudonym = vehicle.pseudonym
        update_job(job_id, vehicle={"id": vehicle_id, "pseudonym": pseudonym, "x": x, "y": y,
                                    "speed": speed, "direction": direction})
        update_step(job_id, 0, "passed", f"{vehicle_id} assigned pseudonym {pseudonym}", starts[0])

        starts[1] = time.perf_counter()
        if event:
            message = vehicle.create_event_message(event, severity)
        else:
            message = vehicle.create_status_message()
        message_dict = message.to_dict()
        update_job(job_id, message=message_dict)
        with JOBS_LOCK:
            JOBS[job_id]["steps"][1]["name"] = "DENM accident event" if event else "CAM status message"
        update_step(job_id, 1, "passed", f"{message.message_type} | scenario={scenario} | seq={message.sequence_number} | position=({x:.2f}, {y:.2f}) m", starts[1])

        starts[2] = time.perf_counter()
        vehicle.sign_message(message)
        message_dict = message.to_dict()
        signature_size = len(base64.b64decode(message_dict["signature"]))
        if scenario == "COMPROMISED":
            # Demonstration of a compromised sender: mutate signed data after signing.
            # The encrypted packet is intact, but the RSU must reject its invalid signature.
            message.speed = min(250.0, float(message.speed) + 77.0)
            message_dict = message.to_dict()
            update_job(job_id, message=message_dict)
        update_job(job_id, message=message_dict)
        update_step(job_id, 2, "passed", f"ML-DSA-65 signature generated ({signature_size:,} bytes); signature and public key included", starts[2])
        if scenario == "COMPROMISED":
            update_job(job_id, message=message_dict)
            update_step(job_id, 2, "passed", "Signed with ML-DSA-65, then speed was altered; RSU must reject this signature", starts[2])

        starts[3] = time.perf_counter()
        envelope = encrypt_for_rsu({"message": message_dict}, rsu_public_key)
        # Metadata is outside the ciphertext and is used only to route a local demo acknowledgement.
        envelope["_frontend_demo_id"] = job_id
        wire_bytes = json.dumps(envelope, separators=(",", ":")).encode("utf-8")
        update_job(job_id, packet_bytes=len(wire_bytes))
        update_step(job_id, 3, "passed", f"ML-KEM-768 encapsulation completed; AES-256-GCM envelope created ({len(wire_bytes):,} bytes)", starts[3])

        # Attack scenarios are executed through this same dashboard job, so their
        # packets carry the job ID and the final RSU verdict is rendered in-browser.
        packets = [wire_bytes]
        attack_notes = []
        if scenario == "REPLAY":
            # Re-send the exact same authenticated envelope and sequence number.
            packets = [wire_bytes, wire_bytes]
            attack_notes.append("Replay test: the identical signed/encrypted packet is sent twice")
        elif scenario == "SYBIL":
            # Use a fresh, uncommon location for this run to avoid state left by
            # earlier demonstrations, then send a second pseudonym at that location.
            unique_x = 300.0 + (int(job_id[-4:], 16) % 150)
            unique_y = 300.0 + (int(job_id[-8:-4], 16) % 150)
            vehicle.x, vehicle.y = unique_x, unique_y
            message.x, message.y = unique_x, unique_y
            message_dict = message.to_dict()
            vehicle.sign_message(message)
            message_dict = message.to_dict()
            envelope = encrypt_for_rsu({"message": message_dict}, rsu_public_key)
            envelope["_frontend_demo_id"] = job_id
            wire_bytes = json.dumps(envelope, separators=(",", ":")).encode("utf-8")
            update_job(job_id, vehicle={"id": vehicle_id, "pseudonym": pseudonym, "x": unique_x, "y": unique_y,
                                        "speed": speed, "direction": direction}, message=message_dict,
                       packet_bytes=len(wire_bytes))
            attacker_letter = next(letter for letter in ("A", "B", "C") if letter != vehicle_letter)
            attacker = get_vehicle_session(attacker_letter, unique_x, unique_y, speed, direction)
            attacker_message = attacker.create_status_message()
            attacker.sign_message(attacker_message)
            attacker_envelope = encrypt_for_rsu({"message": attacker_message.to_dict()}, rsu_public_key)
            attacker_envelope["_frontend_demo_id"] = job_id
            attacker_bytes = json.dumps(attacker_envelope, separators=(",", ":")).encode("utf-8")
            packets = [wire_bytes, attacker_bytes]
            update_job(job_id, message=attacker_message.to_dict())
            attack_notes.append(f"Sybil test: {pseudonym} and {attacker.pseudonym} claim ({unique_x:.0f}, {unique_y:.0f}) m")
        elif scenario == "DOS":
            # Six individually signed/encrypted messages from one sender in a short
            # burst; the RSU's configured threshold is >5 messages within 2 seconds.
            packets = [wire_bytes]
            last_burst_message = message
            for _ in range(5):
                burst_message = vehicle.create_status_message()
                vehicle.sign_message(burst_message)
                burst_envelope = encrypt_for_rsu({"message": burst_message.to_dict()}, rsu_public_key)
                burst_envelope["_frontend_demo_id"] = job_id
                burst_bytes = json.dumps(burst_envelope, separators=(",", ":")).encode("utf-8")
                packets.append(burst_bytes)
                last_burst_message = burst_message
            update_job(job_id, message=last_burst_message.to_dict())
            attack_notes.append("DoS test: six signed/encrypted CAMs are sent rapidly from one sender")

        starts[4] = time.perf_counter()
        update_step(job_id, 4, "running", f"Sending {len(packets)} UDP packet(s) to {RSU_HOST}:{RSU_PORT}")
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(12.0)
            presence_count = 0
            if scenario == "ACCIDENT":
                # Refresh nearby vehicle CAMs so the RSU has real recipients for forwarding.
                default_positions = {"A": (420.0, 420.0), "B": (440.0, 420.0), "C": (420.0, 440.0)}
                for other_letter in ("A", "B", "C"):
                    if other_letter == vehicle_letter:
                        continue
                    ox, oy = default_positions[other_letter]
                    neighbor = get_vehicle_session(other_letter, ox, oy, 40.0, 90.0)
                    neighbor_message = neighbor.create_status_message()
                    neighbor.sign_message(neighbor_message)
                    neighbor_envelope = encrypt_for_rsu({"message": neighbor_message.to_dict()}, rsu_public_key)
                    neighbor_bytes = json.dumps(neighbor_envelope, separators=(",", ":")).encode("utf-8")
                    sock.sendto(neighbor_bytes, (RSU_HOST, RSU_PORT))
                    presence_count += 1
                    time.sleep(0.12)
            raw_ack = None
            for packet_index, packet_bytes in enumerate(packets):
                sock.sendto(packet_bytes, (RSU_HOST, RSU_PORT))
                try:
                    raw_ack, _ = sock.recvfrom(65507)
                except socket.timeout:
                    raise RuntimeError("Packet was sent, but no RSU acknowledgement arrived within 12 seconds. Ensure the RSU server is running on port 5002.")
                if packet_index < len(packets) - 1 and scenario == "DOS":
                    time.sleep(0.08)
            tx_detail = f"Sent {len(packets)} packet(s), {sum(len(p) for p in packets):,} total bytes to {RSU_HOST}:{RSU_PORT}"
            if presence_count:
                tx_detail += f"; refreshed {presence_count} nearby vehicle CAMs for accident forwarding"
            if attack_notes:
                tx_detail += "; " + "; ".join(attack_notes)
            update_step(job_id, 4, "passed", tx_detail, starts[4])

        ack = json.loads(raw_ack.decode("utf-8"))
        if ack.get("type") != "VANET_RSU_ACK":
            raise RuntimeError("Received an unexpected UDP response. Check that port 5002 belongs to the updated RSU server.")
        result = ack.get("result", {})
        rsu_stages = result.get("stages", [])
        handled = set()
        for stage in rsu_stages:
            index = _stage_index(stage.get("name", ""))
            if index is None or index in handled:
                continue
            handled.add(index)
            status = stage.get("status", "passed")
            detail = stage.get("detail", stage.get("name", "RSU check completed"))
            # Present the RSU's returned stage results sequentially in the UI.
            # These are statuses reported by the live RSU acknowledgement.
            update_step(job_id, index, "running", f"RSU result received: {stage.get('name', 'security stage')}…")
            time.sleep(0.45)
            update_step(job_id, index, status, detail)
            if status in {"failed", "rejected", "alert", "blocked"}:
                set_pending_after(job_id, index + 1)
                break
        for index in range(5, 12):
            with JOBS_LOCK:
                current_status = JOBS[job_id]["steps"][index]["status"]
            if current_status == "pending":
                update_step(job_id, index, "skipped", "RSU did not report this stage")

        update_job(job_id, state="complete", decision=result, completed_at=time.time())
    except Exception as exc:
        with JOBS_LOCK:
            existing = JOBS.get(job_id, {})
            stage5_status = existing.get("steps", [{}] * 5)[4].get("status") if len(existing.get("steps", [])) >= 5 else None
        if stage5_status in ("running", "pending"):
            update_step(job_id, 4, "failed", str(exc))
            set_pending_after(job_id, 5, "Stopped because transmission/RSU processing did not complete")
        else:
            with JOBS_LOCK:
                steps = JOBS.get(job_id, {}).get("steps", [])
                failed_index = next((i for i, step in enumerate(steps) if step["status"] == "pending"), None)
            if failed_index is not None:
                update_step(job_id, failed_index, "failed", str(exc))
                set_pending_after(job_id, failed_index + 1, "Stopped after an error")
        update_job(job_id, state="error", error=str(exc), completed_at=time.time())


class Handler(BaseHTTPRequestHandler):
    server_version = "VANET-PQC-Demo/1.0"

    def log_message(self, fmt, *args):
        print("[FRONTEND] " + (fmt % args))

    def send_json(self, code, data):
        raw = json.dumps(data).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/api/health":
            self.send_json(200, {
                "frontend": "online",
                "public_key_available": os.path.isfile(PUBKEY_PATH) and os.path.getsize(PUBKEY_PATH) > 0,
                "rsu_endpoint": f"{RSU_HOST}:{RSU_PORT}",
            })
            return
        if parsed.path == "/api/status":
            job_id = parse_qs(parsed.query).get("id", [""])[0]
            with JOBS_LOCK:
                job = JOBS.get(job_id)
                snapshot = json.loads(json.dumps(job)) if job else None
            if snapshot is None:
                self.send_json(404, {"error": "Unknown job"})
            else:
                self.send_json(200, snapshot)
            return
        if parsed.path in ("/", "/index.html"):
            html_path = os.path.join(os.path.dirname(__file__), "index.html")
            with open(html_path, "rb") as handle:
                raw = handle.read()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
            return
        self.send_json(404, {"error": "Not found"})

    def do_POST(self):
        if urlparse(self.path).path != "/api/demo":
            self.send_json(404, {"error": "Not found"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            params = json.loads(self.rfile.read(length).decode("utf-8")) if length else {}
            job = new_job()
            with JOBS_LOCK:
                JOBS[job["id"]] = job
            threading.Thread(target=run_demo, args=(job["id"], params), daemon=True).start()
            self.send_json(202, {"id": job["id"]})
        except Exception as exc:
            self.send_json(400, {"error": str(exc)})


def main():
    print("=" * 64)
    print("VANET PQC IDS — DEMO FRONTEND")
    print(f"Dashboard: http://{HOST}:{PORT}")
    print(f"RSU target: {RSU_HOST}:{RSU_PORT}")
    print("Start simulator/rsu_server.py in another terminal first.")
    print("Press Ctrl+C to stop the dashboard.")
    print("=" * 64)
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[FRONTEND] Stopping dashboard...")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
