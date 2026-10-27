
import json
import socket

from simulator.security_demo import make_signed_message
from security.secure_channel import encrypt_for_rsu

HOST = "127.0.0.1"
PORT = 5002
PUBKEY_PATH = "results/rsu_mlkem_public_key.bin"


def main():
    with open(PUBKEY_PATH, "rb") as file:
        public_key = file.read()

    _, message = make_signed_message(
        "PSEUDO_FALSE_TEST", 400.0, 400.0, 1
    )

    # Alter a signed field after signing, invalidating the signature.
    if "speed" in message:
        message["speed"] = 999.0
    else:
        print("[FALSE MESSAGE TEST] No speed field found.")
        print("Cannot tamper with the expected field.")
        return

    envelope = encrypt_for_rsu(
        {"message": message}, public_key
    )
    packet = json.dumps(
        envelope, separators=(",", ":")
    ).encode("utf-8")

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.sendto(packet, (HOST, PORT))

    print("[FALSE MESSAGE TEST] Tampered message sent.")
    print("[FALSE MESSAGE TEST] Check the RSU terminal for signature rejection.")


if __name__ == "__main__":
    main()
