
import json
import socket
import time

from simulator.security_demo import make_signed_message
from security.secure_channel import encrypt_for_rsu
from security.pseudonym import PseudonymManager

HOST = "127.0.0.1"
PORT = 5002
PUBKEY_PATH = "results/rsu_mlkem_public_key.bin"


def main():
    with open(PUBKEY_PATH, "rb") as file:
        public_key = file.read()

    sender = PseudonymManager().generate_pseudonym("replay-test")
    _, message = make_signed_message(
        sender, 400.0, 400.0, 1
    )

    envelope = encrypt_for_rsu(
        {"message": message}, public_key
    )
    packet = json.dumps(
        envelope, separators=(",", ":")
    ).encode("utf-8")

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.sendto(packet, (HOST, PORT))
        print("[REPLAY TEST] Original packet sent.")
        time.sleep(1)

        sock.sendto(packet, (HOST, PORT))
        print("[REPLAY TEST] Identical packet replayed.")

    print("[REPLAY TEST] Check the RSU terminal for the replay alert.")


if __name__ == "__main__":
    main()
