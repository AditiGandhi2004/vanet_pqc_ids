from simulator.vehicle import Vehicle


vehicle = Vehicle(
    "V01",
    0,
    0,
    60,
    0
)

vehicle.set_pseudonym("PSEUDO_V01")

message = vehicle.create_event_message(
    "ACCIDENT",
    "HIGH"
)

message = vehicle.sign_message(message)

print("\nVANET MESSAGE:")
print(message)

print("\nSignature attached:", message.signature is not None)
print("Public key attached:", message.public_key is not None)