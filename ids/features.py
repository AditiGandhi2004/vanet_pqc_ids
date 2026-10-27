class VANETFeatureExtractor:

    def extract(self, message, previous_message=None, current_time=None):
        features = {}

        # Basic message features
        features["speed"] = message.get("speed", 0)
        features["direction"] = message.get("direction", 0)

        position = message.get("position", {})
        features["x"] = position.get("x", 0)
        features["y"] = position.get("y", 0)

        features["sequence_number"] = message.get(
            "sequence_number", 0
        )

        # Event and severity
        features["has_event"] = (
            1 if message.get("event") else 0
        )

        severity = message.get("severity")

        severity_map = {
            "LOW": 1,
            "MEDIUM": 2,
            "HIGH": 3
        }

        features["severity"] = severity_map.get(
            severity, 0
        )

        # Sequence-number behavior
        if previous_message is not None:
            previous_sequence = previous_message.get(
                "sequence_number", 0
            )

            features["sequence_gap"] = (
                features["sequence_number"]
                - previous_sequence
            )
        else:
            features["sequence_gap"] = 0

        # Message timing
        if previous_message is not None:
            previous_timestamp = previous_message.get(
                "timestamp", 0
            )

            current_timestamp = message.get(
                "timestamp", 0
            )

            features["inter_arrival_time"] = (
                current_timestamp - previous_timestamp
            )
        else:
            features["inter_arrival_time"] = 0

        return features