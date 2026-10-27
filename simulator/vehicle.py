import math
from security.ml_dsa import MLDSA
import base64

class Vehicle:

    def __init__(self, vehicle_id, x, y, speed, direction):
        self.vehicle_id = vehicle_id
        self.pseudonym = None
        self.sequence_number = 0

        self.x = x
        self.y = y
        self.speed = speed
        self.direction = direction
        self.crypto = MLDSA()
    def sign_message(self, message):
        signature = self.crypto.sign(message.signing_data())
        message.signature = base64.b64encode(signature).decode("utf-8")
        message.public_key = base64.b64encode(
        self.crypto.public_key
        ).decode("utf-8")
        return message

    def move(self, time_seconds):
        speed_mps = self.speed / 3.6
        angle = math.radians(self.direction)

        self.x += speed_mps * math.cos(angle) * time_seconds
        self.y += speed_mps * math.sin(angle) * time_seconds

    def distance_to(self, other):
        return math.sqrt(
            (self.x - other.x) ** 2 +
            (self.y - other.y) ** 2
        )

    def can_communicate(self, other, communication_range=300):
        return self.distance_to(other) <= communication_range

    def set_pseudonym(self, pseudonym):
        self.pseudonym = pseudonym

    def create_status_message(self):
        from simulator.message import VANETMessage

        self.sequence_number += 1

        return VANETMessage(
            sender_id=self.pseudonym,
            message_type="CAM",
            x=self.x,
            y=self.y,
            speed=self.speed,
            direction=self.direction,
            sequence_number=self.sequence_number
        )

    def create_event_message(self, event, severity):
        from simulator.message import VANETMessage

        self.sequence_number += 1

        return VANETMessage(
            sender_id=self.pseudonym,
            message_type="DENM",
            x=self.x,
            y=self.y,
            speed=self.speed,
            direction=self.direction,
            event=event,
            severity=severity,
            sequence_number=self.sequence_number
        )

    def __str__(self):
        return (
            f"{self.vehicle_id}: "
            f"Position=({self.x:.1f}, {self.y:.1f}), "
            f"Speed={self.speed} km/h, "
            f"Direction={self.direction}°"
        )
