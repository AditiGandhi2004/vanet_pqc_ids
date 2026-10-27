class ReplayDetector:

    def __init__(self):
        self.last_sequence = {}

    def check_message(self, message):

        sender = message.sender_id
        sequence = message.sequence_number

        if sender not in self.last_sequence:
            self.last_sequence[sender] = sequence
            return True

        if sequence <= self.last_sequence[sender]:
            return False

        self.last_sequence[sender] = sequence

        return True
