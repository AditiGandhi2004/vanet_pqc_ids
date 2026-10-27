"""Send one vehicle-behaviour anomaly to the live RSU.

Start simulator/rsu_server.py first. From the project root run one scenario:
  py -3.11 -m attacks.test_vehicle_anomalies --scenario speed
  py -3.11 -m attacks.test_vehicle_anomalies --scenario direction
  py -3.11 -m attacks.test_vehicle_anomalies --scenario compromised

The RSU has explicit demo rules for speed > 60 km/h and a direction change >= 120 degrees.
The compromised scenario changes signed content after signing; ML-DSA verification must reject it.
"""
import argparse
import json
import os
import socket
import time
import uuid

from security.secure_channel import encrypt_for_rsu
from simulator.vehicle import Vehicle

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PUBKEY_PATH = os.path.join(ROOT, "results", "rsu_mlkem_public_key.bin")
HOST = os.environ.get("VANET_RSU_HOST", "127.0.0.1")
PORT = int(os.environ.get("VANET_RSU_PORT", "5002"))


def signed_status(sender, speed, direction, sequence, x, y):
    vehicle = Vehicle(sender, x, y, speed, direction)
    vehicle.set_pseudonym(sender)
    vehicle.sequence_number = sequence - 1
    message = vehicle.create_status_message()
    vehicle.sign_message(message)
    return message.to_dict()


def send(sock, public_key, message, label):
    envelope = encrypt_for_rsu({"message": message}, public_key)
    packet = json.dumps(envelope, separators=(",", ":")).encode("utf-8")
    sock.sendto(packet, (HOST, PORT))
    print(f"[VEHICLE ANOMALY TEST] {label}: sender={message['sender_id']} speed={message['speed']} km/h direction={message['direction']}°")


def main():
    parser = argparse.ArgumentParser(description="Send one controlled vehicle anomaly to the live RSU")
    parser.add_argument("--scenario", required=True, choices=("speed", "direction", "compromised"),
                        help="speed: overspeed; direction: abrupt turn; compromised: invalid message signature")
    scenario = parser.parse_args().scenario
    if not os.path.isfile(PUBKEY_PATH):
        raise FileNotFoundError(f"RSU public key not found: {PUBKEY_PATH}. Start simulator/rsu_server.py first.")
    with open(PUBKEY_PATH, "rb") as f:
        public_key = f.read()

    sender = f"PSEUDO_{scenario.upper()}_{uuid.uuid4().hex[:6]}"
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        if scenario == "speed":
            msg = signed_status(sender, 85.0, 90.0, 1, 420.0, 430.0)
            send(sock, public_key, msg, "OVERSPEED scenario")
            print("Expected RSU result: OVERSPEED alert; message not forwarded.")
        elif scenario == "direction":
            first = signed_status(sender, 40.0, 0.0, 1, 430.0, 440.0)
            second = signed_status(sender, 40.0, 180.0, 2, 431.0, 440.0)
            send(sock, public_key, first, "Direction baseline (0°)")
            time.sleep(0.6)
            send(sock, public_key, second, "SUDDEN DIRECTION CHANGE (180°)")
            print("Expected RSU result: second message triggers direction-change alert; not forwarded.")
        else:
            msg = signed_status(sender, 45.0, 90.0, 1, 440.0, 450.0)
            msg["speed"] = 150.0  # intentionally change a signed field after signing
            send(sock, public_key, msg, "COMPROMISED message (speed changed after signing)")
            print("Expected RSU result: invalid ML-DSA-65 signature; message rejected.")

    print("Observe the RSU terminal for the actual result. This test does not fabricate an RSU response.")


if __name__ == "__main__":
    main()
