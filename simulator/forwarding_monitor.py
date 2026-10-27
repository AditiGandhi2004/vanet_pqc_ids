"""Console monitor for RSU geographic forwarding on UDP 5200."""
import json
import os
import socket

HOST = os.environ.get("VANET_FORWARD_HOST", "127.0.0.1")
PORT = int(os.environ.get("VANET_FORWARD_PORT", "5200"))


def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((HOST, PORT))
    print(f"Forwarding monitor listening on {HOST}:{PORT}")
    try:
        while True:
            data, address = sock.recvfrom(65507)
            try:
                packet = json.loads(data.decode("utf-8"))
                if packet.get("packet_type") == "SAFETY_ALERT":
                    print("\n" + "!" * 64)
                    print(f"[SAFETY ALERT RECEIVED] {packet.get('alert_text')}")
                    print(f"Severity: {packet.get('severity')} | source={packet.get('source_pseudonym')}")
                    print(f"Nearby recipients: {packet.get('recipient_pseudonyms', [])}")
                    print("!" * 64 + "\n")
                else:
                    print(f"[FORWARDED STATUS] source={packet.get('source_pseudonym')} "
                          f"distance={packet.get('source_to_rsu_distance_m')}m "
                          f"recipients={packet.get('recipient_pseudonyms', [])} from={address}")
            except (UnicodeDecodeError, json.JSONDecodeError):
                print(f"[INVALID] malformed forwarding packet from {address}")
    except KeyboardInterrupt:
        print("Forwarding monitor stopped.")
    finally:
        sock.close()


if __name__ == "__main__":
    main()
