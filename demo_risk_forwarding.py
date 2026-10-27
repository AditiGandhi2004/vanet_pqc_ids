
import math

RSU_X = 0.0
RSU_Y = 0.0
MAX_FORWARD_DISTANCE = 500.0

RESPONSE_POLICY = {
    "Normal": ("LOW", "ACCEPT"),
    "Replay": ("HIGH", "REJECT"),
    "Sybil": ("HIGH", "REJECT"),
    "DoS": ("HIGH", "BLOCK_SENDER"),
    "Tampering": ("CRITICAL", "REJECT"),
}


def process_test_case(name, label, vehicle_x, vehicle_y):
    distance = math.sqrt(
        (vehicle_x - RSU_X) ** 2 +
        (vehicle_y - RSU_Y) ** 2
    )

    risk, response = RESPONSE_POLICY[label]
    eligible = distance <= MAX_FORWARD_DISTANCE

    # Security response takes precedence over forwarding eligibility.
    forwarded = response == "ACCEPT" and eligible

    print(f"\nTest case: {name}")
    print(f"Detected class: {label}")
    print(f"Risk level: {risk}")
    print(f"Response: {response}")
    print(f"Vehicle-to-RSU distance: {distance:.2f} m")
    print(f"Forwarding range: {MAX_FORWARD_DISTANCE:.0f} m")
    print(f"Geographically eligible: {'YES' if eligible else 'NO'}")
    print(f"Final decision: {'FORWARD' if forwarded else 'DO NOT FORWARD'}")


def main():
    print("=" * 48)
    print("VANET RISK RESPONSE AND FORWARDING DEMO")
    print("Controlled policy test; not a live RSU test")
    print("=" * 48)

    process_test_case(
        "Normal vehicle within range", "Normal", 120, 160
    )
    process_test_case(
        "Normal vehicle outside range", "Normal", 600, 0
    )
    process_test_case(
        "Replay attack", "Replay", 100, 100
    )
    process_test_case(
        "Sybil behavior", "Sybil", 200, 100
    )
    process_test_case(
        "DoS behavior", "DoS", 50, 50
    )
    process_test_case(
        "Tampered message", "Tampering", 80, 60
    )


if __name__ == "__main__":
    main()
