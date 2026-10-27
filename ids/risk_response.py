class RiskResponse:

    def __init__(self):
        self.risk_levels = {
            "NORMAL": "LOW",
            "REPLAY": "HIGH",
            "SYBIL": "HIGH",
            "DOS": "HIGH",
            "TAMPERING": "CRITICAL",
            "OVERSPEED": "HIGH",
            "SUDDEN_DIRECTION_CHANGE": "HIGH"
        }

        self.responses = {
            "NORMAL": "ACCEPT",
            "REPLAY": "REJECT",
            "SYBIL": "REJECT",
            "DOS": "BLOCK_SENDER",
            "TAMPERING": "REJECT",
            "OVERSPEED": "REJECT",
            "SUDDEN_DIRECTION_CHANGE": "REJECT"
        }

    def assess(self, attack_class):

        attack_class = attack_class.upper()

        risk = self.risk_levels.get(
            attack_class,
            "UNKNOWN"
        )

        response = self.responses.get(
            attack_class,
            "REJECT"
        )

        return {
            "class": attack_class,
            "risk": risk,
            "response": response
        }


if __name__ == "__main__":

    engine = RiskResponse()

    test_classes = [
        "NORMAL",
        "REPLAY",
        "SYBIL",
        "DOS",
        "TAMPERING"
    ]

    print("\n========== RISK / RESPONSE TEST ==========")

    for attack_class in test_classes:

        result = engine.assess(attack_class)

        print(
            f"{result['class']:10} | "
            f"Risk: {result['risk']:8} | "
            f"Response: {result['response']}"
        )