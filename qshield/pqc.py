"""ML-KEM-768 (FIPS 203) and X25519 wrappers, via the `cryptography` library."""

from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.mlkem import (
    MLKEM768PrivateKey,
    MLKEM768PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives import serialization

MLKEM768_PK_BYTES = 1184
MLKEM768_CT_BYTES = 1088


class MLKEMResponder:
    """Gateway side: owns an ephemeral ML-KEM-768 keypair."""

    def __init__(self) -> None:
        self._sk = MLKEM768PrivateKey.generate()
        self.public_bytes = self._sk.public_key().public_bytes_raw()

    def decapsulate(self, ciphertext: bytes) -> bytes:
        return self._sk.decapsulate(ciphertext)


def mlkem_encapsulate(public_bytes: bytes) -> tuple[bytes, bytes]:
    """Device side. Returns (shared_secret, ciphertext)."""
    pk = MLKEM768PublicKey.from_public_bytes(public_bytes)
    shared_secret, ciphertext = pk.encapsulate()
    return shared_secret, ciphertext


def x25519_exchange() -> tuple[bytes, bytes, int]:
    """Classical ECDH baseline. Returns (secret_device, secret_gateway, wire_bytes)."""
    a, b = X25519PrivateKey.generate(), X25519PrivateKey.generate()
    raw = serialization.Encoding.Raw, serialization.PublicFormat.Raw
    a_pub = a.public_key().public_bytes(*raw)
    b_pub = b.public_key().public_bytes(*raw)
    s_a = a.exchange(X25519PublicKey.from_public_bytes(b_pub))
    s_b = b.exchange(X25519PublicKey.from_public_bytes(a_pub))
    return s_a, s_b, len(a_pub) + len(b_pub)
