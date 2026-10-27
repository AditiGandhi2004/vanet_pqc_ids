from simulator.vehicle import Vehicle
from simulator.udp_network import UDPNetwork


vehicle = Vehicle(
    "V01",
    0,
    0,
    60,
    0
)

vehicle.set_pseudonym("PSEUDO_V01")

# Create ONE message
message = vehicle.create_event_message(
    "ACCIDENT",
    "HIGH"
)

# Sign ONE message
message = vehicle.sign_message(message)

network = UDPNetwork()

print("\n--- Sending original message ---")

network.send_message(
    message,
    receiver_port=5002
)

print("\n--- Replaying the same message ---")

network.send_message(
    message,
    receiver_port=5002
)