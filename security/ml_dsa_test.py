import oqs

MESSAGE = b"VANET safety message: ACCIDENT detected"

print("Available ML-DSA algorithms:")
for alg in oqs.get_enabled_sig_mechanisms():
    if alg.startswith("ML-DSA"):
        print(" -", alg)

print("\nUsing ML-DSA-65")

# Create signer and generate key pair
signer = oqs.Signature("ML-DSA-65")

public_key = signer.generate_keypair()

print("Public key generated.")
print("Public key size:", len(public_key), "bytes")

# Sign message
signature = signer.sign(MESSAGE)

print("Message signed.")
print("Signature size:", len(signature), "bytes")

# Verify signature
valid = signer.verify(MESSAGE, signature, public_key)

print("Signature valid:", valid)

# Test that a modified message fails
modified_message = b"VANET safety message: NORMAL"

invalid = signer.verify(modified_message, signature, public_key)

print("Modified message valid:", invalid)