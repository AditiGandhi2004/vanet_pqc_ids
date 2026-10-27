r"""Send controlled security test packets to a running local VANET RSU.

Start simulator/rsu_server.py first. This uses the real ML-DSA/ML-KEM/AES-GCM
code path; it does not disable cryptographic checks. Run from the project root:
    py -3.11 .\simulator\security_demo.py
"""
import copy
import json
import os
import socket
import time

from security.secure_channel import encrypt_for_rsu
from security.pseudonym import PseudonymManager
from simulator.vehicle import Vehicle

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PUBKEY_PATH = os.path.join(ROOT, "results", "rsu_mlkem_public_key.bin")
HOST = os.environ.get("VANET_RSU_HOST", "127.0.0.1")
PORT = int(os.environ.get("VANET_RSU_PORT", "5002"))


def make_signed_message(sender, x, y, sequence, event=None):
    vehicle = Vehicle(sender, x, y, 45.0, 90.0)
    vehicle.set_pseudonym(sender)
    vehicle.sequence_number = sequence - 1
    message = vehicle.create_status_message()
    if event:
        message.event = event
        message.severity = "HIGH"
    vehicle.sign_message(message)
    return vehicle, message.to_dict()


def send_payload(sock, public_key, message, label):
    envelope = encrypt_for_rsu({"message": message}, public_key)
    packet = json.dumps(envelope, separators=(",", ":")).encode("utf-8")
    sock.sendto(packet, (HOST, PORT))
    print(f"[TEST SEND] {label}: sender={message.get('sender_id')} seq={message.get('sequence_number')} bytes={len(packet)}")
    return envelope


def main():
    if not os.path.isfile(PUBKEY_PATH):
        raise FileNotFoundError(f"RSU public key not found: {PUBKEY_PATH}. Start simulator/rsu_server.py first.")
    with open(PUBKEY_PATH, "rb") as f:
        public_key = f.read()
    pseudonyms = PseudonymManager()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    print("=" * 68)
    print("CONTROLLED VANET SECURITY DEMONSTRATION")
    print("This sends real cryptographically protected test packets to the local RSU.")
    print("Observe the RSU console for the corresponding decisions.")
    print("=" * 68)
    try:
        # 1. Legitimate signed/encrypted message, then replay the exact same envelope.
        sender = pseudonyms.generate_pseudonym("replay-test")
        _, normal = make_signed_message(sender, 400.0, 400.0, 1)
        replay_envelope = send_payload(sock, public_key, normal, "1/5 NORMAL message")
        time.sleep(0.35)
        sock.sendto(json.dumps(replay_envelope, separators=(",", ":")).encode("utf-8"), (HOST, PORT))
        print("[TEST SEND] 2/5 REPLAY: resent the exact same protected envelope")
        time.sleep(0.6)

        # 2. Tamper with signed content after signing, then encrypt the altered message.
        sender = pseudonyms.generate_pseudonym("tamper-test")
        _, tampered = make_signed_message(sender, 420.0, 420.0, 1)
        tampered["speed"] = 199.0  # signature deliberately remains from original speed
        send_payload(sock, public_key, tampered, "3/5 TAMPERING: changed signed speed after signing")
        time.sleep(0.6)

        # 3. Sybil heuristic: distinct pseudonyms report the same exact position.
        for i, point in enumerate(("sybil-A", "sybil-B"), start=1):
            sender = pseudonyms.generate_pseudonym(point)
            _, msg = make_signed_message(sender, 300.0, 300.0, 1)
            send_payload(sock, public_key, msg, f"4/5 SYBIL candidate {i}: same position, different pseudonym")
            time.sleep(0.35)
        time.sleep(0.6)

        # 4. Burst enough messages from one sender to exercise the configured rate rule.
        sender = pseudonyms.generate_pseudonym("dos-test")
        print("[TEST] 5/5 DOS/FLOODING: sending a short burst; observe configured rate threshold.")
        for sequence in range(1, 9):
            _, msg = make_signed_message(sender, 450.0 + sequence, 450.0, sequence)
            send_payload(sock, public_key, msg, f"DOS burst {sequence}/8")
            time.sleep(0.08)
        time.sleep(0.5)
        print("[DONE] Security test packets sent. Review RSU logs for detection and response.")
    finally:
        sock.close()


if __name__ == "__main__":
    main()
