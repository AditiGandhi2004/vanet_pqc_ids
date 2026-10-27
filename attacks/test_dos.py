from attacks.dos import DoSDetector


detector = DoSDetector(
    max_messages=5,
    time_window=2
)

sender = "PSEUDO_ATTACKER"

for i in range(10):
    result = detector.check_message(sender)

    print(
        f"Message {i + 1}:",
        "ACCEPTED" if result else "DOS DETECTED"
    )