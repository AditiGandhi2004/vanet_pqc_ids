from attacks.sybil import SybilDetector


class TestMessage:
    def __init__(self, sender_id, x, y):
        self.sender_id = sender_id
        self.x = x
        self.y = y


detector = SybilDetector()

# Legitimate vehicle
message1 = TestMessage(
    "PSEUDO_A",
    100,
    50
)

print(
    "Message 1:",
    detector.check_message(message1)
)

# Same location, different pseudonym
message2 = TestMessage(
    "PSEUDO_B",
    100,
    50
)

print(
    "Message 2:",
    detector.check_message(message2)
)