from ml_dsa import MLDSA


crypto = MLDSA()

message = "VANET ACCIDENT WARNING"

signature = crypto.sign(message)

print("Algorithm:", crypto.algorithm)
print("Public key size:", len(crypto.public_key), "bytes")
print("Signature size:", len(signature), "bytes")

result = crypto.verify(message, signature)

print("Verification:", result)