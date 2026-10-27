import time
import uuid
import json


class VANETMessage:
    def __init__(
        self, sender_id, message_type, x, y, speed, direction,
        event=None, severity=None, sequence_number=0
    ):
        self.message_id = str(uuid.uuid4())[:8]
        self.sender_id = sender_id
        self.message_type = message_type
        self.x = x
        self.y = y
        self.speed = speed
        self.direction = direction
        self.event = event
        self.severity = severity
        self.timestamp = time.time()
        self.sequence_number = sequence_number

        # ML-DSA fields
        self.signature = None
        self.public_key = None

    def to_dict(self):
        return {
            "message_id": self.message_id,
            "sender_id": self.sender_id,
            "message_type": self.message_type,
            "position": {
                "x": round(self.x, 2),
                "y": round(self.y, 2)
            },
            "speed": self.speed,
            "direction": self.direction,
            "event": self.event,
            "severity": self.severity,
            "timestamp": round(self.timestamp, 2),
            "sequence_number": self.sequence_number,
            "signature": self.signature,
            "public_key": self.public_key
        }

    def signing_data(self):
        data = {
            "message_id": self.message_id,
            "sender_id": self.sender_id,
            "message_type": self.message_type,
            "position": {
                "x": round(self.x, 2),
                "y": round(self.y, 2)
            },
            "speed": self.speed,
            "direction": self.direction,
            "event": self.event,
            "severity": self.severity,
            "timestamp": round(self.timestamp, 2),
            "sequence_number": self.sequence_number
        }

        return json.dumps(
            data,
            sort_keys=True
        ).encode("utf-8")

    def __str__(self):
        return str(self.to_dict())