from ids.detector import VANETIDS


def create_message(
    speed=60,
    direction=0,
    x=100,
    y=50,
    sequence_number=1,
    event="ACCIDENT",
    severity="HIGH",
    timestamp=1000.0
):
    return {
        "message_id": "TEST001",
        "sender_id": "PSEUDO_TEST",
        "message_type": "DENM",
        "position": {
            "x": x,
            "y": y
        },
        "speed": speed,
        "direction": direction,
        "event": event,
        "severity": severity,
        "timestamp": timestamp,
        "sequence_number": sequence_number
    }


def main():

    ids = VANETIDS()

    message = create_message()

    result = ids.predict(message)

    print("\n========== AI IDS TEST ==========")
    print("Predicted class :", result["class"])
    print("Confidence      :", f"{result['confidence']:.4f}")

    print("\nExtracted features:")

    for name, value in result["features"].items():
        print(f"{name}: {value}")


if __name__ == "__main__":
    main()