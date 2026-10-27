class SybilDetector:
    def __init__(self):
        self.pseudonym_locations = {}

    def check_message(self, message):
        pseudonym = message.sender_id

        location = (
            round(message.x, 2),
            round(message.y, 2)
        )

        if location not in self.pseudonym_locations:
            self.pseudonym_locations[location] = set()

        self.pseudonym_locations[location].add(pseudonym)

        pseudonyms = self.pseudonym_locations[location]

        if len(pseudonyms) > 1:
            return False

        return True