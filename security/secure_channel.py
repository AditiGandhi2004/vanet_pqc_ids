"""ML-KEM-768 + HKDF-SHA256 + AES-256-GCM transport helpers.

The sender encapsulates a fresh shared secret to the RSU public key for each
packet. The RSU decapsulates it, derives the same AES key, then decrypts the
payload. ML-DSA signatures are carried inside the encrypted payload and are
verified by the RSU after decryption.
"""

import base64
import json
import os
from typing import Any, Dict, Tuple

import oqs
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

PROTOCOL = "VANET-PQC-IDS-v1"
KEM_ALGORITHM = "ML-KEM-768"
AAD = PROTOCOL.encode("ascii")


def _derive_aes_key(shared_secret: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=AAD,
    ).derive(shared_secret)


def encrypt_for_rsu(payload: Dict[str, Any], rsu_public_key: bytes) -> Dict[str, str]:
    """Return a JSON-serializable envelope encrypted for the RSU."""
    with oqs.KeyEncapsulation(KEM_ALGORITHM) as kem:
        kem_ciphertext, shared_secret = kem.encap_secret(rsu_public_key)

    key = _derive_aes_key(shared_secret)
    nonce = os.urandom(12)
    plaintext = json.dumps(
        payload, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, AAD)

    return {
        "protocol": PROTOCOL,
        "kem": KEM_ALGORITHM,
        "aead": "AES-256-GCM",
        "kem_ciphertext": base64.b64encode(kem_ciphertext).decode("ascii"),
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
    }


def decrypt_from_vehicle(envelope: Dict[str, Any], rsu_kem) -> Dict[str, Any]:
    """Decrypt one envelope using the live RSU KEM object/private key."""
    if envelope.get("protocol") != PROTOCOL:
        raise ValueError("Unsupported secure-channel protocol")
    if envelope.get("kem") != KEM_ALGORITHM:
        raise ValueError("Unexpected KEM algorithm")
    if envelope.get("aead") != "AES-256-GCM":
        raise ValueError("Unexpected AEAD algorithm")

    kem_ciphertext = base64.b64decode(envelope["kem_ciphertext"], validate=True)
    nonce = base64.b64decode(envelope["nonce"], validate=True)
    ciphertext = base64.b64decode(envelope["ciphertext"], validate=True)
    if len(nonce) != 12:
        raise ValueError("AES-GCM nonce must be 12 bytes")

    shared_secret = rsu_kem.decap_secret(kem_ciphertext)
    key = _derive_aes_key(shared_secret)
    plaintext = AESGCM(key).decrypt(nonce, ciphertext, AAD)
    decoded = json.loads(plaintext.decode("utf-8"))
    if not isinstance(decoded, dict):
        raise ValueError("Decrypted payload must be a JSON object")
    return decoded


def verify_mldsa_message(message: Dict[str, Any]) -> bool:
    """Verify the canonical VANETMessage.signing_data representation."""
    public_key = base64.b64decode(message["public_key"], validate=True)
    signature = base64.b64decode(message["signature"], validate=True)
    position = message["position"]
    signing_data = {
        "message_id": message["message_id"],
        "sender_id": message["sender_id"],
        "message_type": message["message_type"],
        "position": {
            "x": round(float(position["x"]), 2),
            "y": round(float(position["y"]), 2),
        },
        "speed": message["speed"],
        "direction": message["direction"],
        "event": message.get("event"),
        "severity": message.get("severity"),
        "timestamp": round(float(message["timestamp"]), 2),
        "sequence_number": message["sequence_number"],
    }
    signed_bytes = json.dumps(signing_data, sort_keys=True).encode("utf-8")
    with oqs.Signature("ML-DSA-65") as verifier:
        return bool(verifier.verify(signed_bytes, signature, public_key))
