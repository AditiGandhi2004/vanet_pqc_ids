
import json
import socket
import time

from simulator.security_demo import make_signed_message
from security.secure_channel import encrypt_for_rsu

HOST = "127.0.0.1"
PORT = 5002
PUBKEY_PATH = "results/rsu_mlkem_public_key.bin"


def main():
    with open(PUBKEY_PATH, "rb") as file:
        public_key = file.read()

    sender = "PSEUDO_DOS_TEST"

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        for sequence in range(1, 9):
            _, message = make_signed_message(
                sender, 400.0, 400.0, sequence
            )
            envelope = encrypt_for_rsu(
                {"message": message}, public_key
            )
            packet = json.dumps(
                envelope, separators=(",", ":")
            ).encode("utf-8")

            sock.sendto(packet, (HOST, PORT))
            print(
                f"[DOS TEST] Message {sequence}/8 sent."
            )
            time.sleep(0.1)

    print("[DOS TEST] Check the RSU terminal for a flooding alert.")


if __name__ == "__main__":
    main()
