import time


class DoSDetector:
    def __init__(self, max_messages=5, time_window=2):
        self.max_messages = max_messages
        self.time_window = time_window
        self.message_times = {}

    def check_message(self, sender_id):
        current_time = time.time()

        if sender_id not in self.message_times:
            self.message_times[sender_id] = []

        # Keep only messages inside the current time window
        self.message_times[sender_id] = [
            timestamp
            for timestamp in self.message_times[sender_id]
            if current_time - timestamp <= self.time_window
        ]

        self.message_times[sender_id].append(current_time)

        if len(self.message_times[sender_id]) > self.max_messages:
            return False

        return True