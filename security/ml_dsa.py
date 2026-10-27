import oqs


class MLDSA:
    def __init__(self, algorithm="ML-DSA-65"):
        self.algorithm = algorithm
        self.signer = oqs.Signature(algorithm)

        self.public_key = self.signer.generate_keypair()

    def sign(self, message):
        if isinstance(message, str):
            message = message.encode("utf-8")

        return self.signer.sign(message)

    def verify(self, message, signature):
        if isinstance(message, str):
            message = message.encode("utf-8")

        return self.signer.verify(
            message,
            signature,
            self.public_key
        )