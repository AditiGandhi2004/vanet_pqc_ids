
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

    # Two different pseudonyms claiming the same position
    _, message1 = make_signed_message(
        "PSEUDO_SYBIL_A", 400.0, 400.0, 1
    )
    _, message2 = make_signed_message(
        "PSEUDO_SYBIL_B", 400.0, 400.0, 1
    )

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        for label, message in [
            ("Vehicle A", message1),
            ("Vehicle B", message2),
        ]:
            packet = json.dumps(
                encrypt_for_rsu({"message": message}, public_key),
                separators=(",", ":"),
            ).encode("utf-8")
            sock.sendto(packet, (HOST, PORT))
            print(f"[SYBIL TEST] {label} sent from the same claimed position.")
            time.sleep(0.5)

    print("[SYBIL TEST] Check the RSU terminal for a Sybil alert.")


if __name__ == "__main__":
    main()
