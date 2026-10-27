from attacks.replay import ReplayDetector


class VANETNetwork:

    def __init__(self, communication_range=300):
        self.communication_range = communication_range
        self.vehicles = []
        self.replay_detector = ReplayDetector()

    def add_vehicle(self, vehicle):
        self.vehicles.append(vehicle)

    def broadcast(self, sender, message):

        print(
            f"\n[{sender.vehicle_id}] Broadcasting "
            f"{message.message_type} message..."
        )

        for receiver in self.vehicles:

            if receiver.vehicle_id == sender.vehicle_id:
                continue

            distance = sender.distance_to(receiver)

            if distance <= self.communication_range:
                print(
                    f"  ✓ {receiver.vehicle_id} received message "
                    f"(distance: {distance:.1f} m)"
                )

                self.process_message(receiver, message, distance)

            else:
                print(
                    f"  ✗ {receiver.vehicle_id} is out of range "
                    f"(distance: {distance:.1f} m)"
                )

    def process_message(self, receiver, message, distance):

        valid = self.replay_detector.check_message(message)

        if not valid:
            print("     ❌ REPLAY DETECTED — Message rejected")
            return

        print("     ✓ Message freshness verified")

        if message.message_type == "DENM":
            print(f"     ⚠️ {message.event} WARNING")
            print(f"     From: {message.sender_id}")
            print(f"     Distance: {distance:.1f} m")
            print(f"     Severity: {message.severity}")

        elif message.message_type == "CAM":
            print(
                f"     Vehicle {receiver.vehicle_id} "
                f"received status from {message.sender_id}"
            )
