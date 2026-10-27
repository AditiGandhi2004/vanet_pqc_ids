from simulator.vehicle import Vehicle
from security.ml_dsa import MLDSA
import base64


# Create vehicle
vehicle = Vehicle(
    "V01",
    0,
    0,
    60,
    0
)

vehicle.set_pseudonym("PSEUDO_V01")

# Create VANET event message
message = vehicle.create_event_message(
    "ACCIDENT",
    "HIGH"
)

# Sign message
message = vehicle.sign_message(message)

# Create verifier
verifier = MLDSA()

# Replace verifier public key with sender's public key
sender_public_key = base64.b64decode(message.public_key)
signature = base64.b64decode(message.signature)

# Verify using sender's public key
valid = verifier.signer.verify(
    message.signing_data(),
    signature,
    sender_public_key
)

print("Original message verification:", valid)


# Modify the message
message.severity = "LOW"

modified_valid = verifier.signer.verify(
    message.signing_data(),
    signature,
    sender_public_key
)

print("Modified message verification:", modified_valid)