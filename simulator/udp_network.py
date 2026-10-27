import socket
import json


class UDPNetwork:

    def __init__(self, host="127.0.0.1", port=5000):
        self.host = host
        self.port = port
        self.receive_sock = None

    def send_message(self, message, receiver_port):

        sock = socket.socket(
            socket.AF_INET,
            socket.SOCK_DGRAM
        )

        data = json.dumps(
            message.to_dict()
        ).encode("utf-8")

        sock.sendto(
            data,
            (self.host, receiver_port)
        )

        sock.close()

        print(
            f"✓ UDP packet sent to "
            f"{self.host}:{receiver_port}"
        )

    def receive_message(self):

        # Create and bind the receiving socket only once
        if self.receive_sock is None:

            self.receive_sock = socket.socket(
                socket.AF_INET,
                socket.SOCK_DGRAM
            )

            self.receive_sock.setsockopt(
                socket.SOL_SOCKET,
                socket.SO_RCVBUF,
                1024 * 1024
            )

            self.receive_sock.bind(
                (self.host, self.port)
            )

            print(
                f"Listening for UDP packets on "
                f"{self.host}:{self.port}..."
            )

        data, address = self.receive_sock.recvfrom(16384)

        message = json.loads(
            data.decode("utf-8")
        )

        print(
            f"\n✓ UDP packet received from {address}"
        )

        return message