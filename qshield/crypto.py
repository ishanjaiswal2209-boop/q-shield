"""Data-plane crypto: HKDF key derivation and AES-256-GCM message envelopes.

Wire format (secure):  [2B header_len][header JSON][12B nonce][ciphertext||tag]
The header (device, domain, seq, key_id, mode) is bound as AAD, so any change
to it, to the ciphertext or to the nonce makes decryption fail.

Wire format (plain control, for attack demos only):  [2B header_len][header JSON][body JSON]
"""

from __future__ import annotations

import json
import os
import struct

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

NONCE_BYTES = 12
TAG_BYTES = 16


class DecryptError(Exception):
    pass


def hkdf(secret: bytes, info: bytes, length: int = 32, salt: bytes | None = None) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info).derive(secret)


def _pack(header: dict) -> tuple[bytes, bytes]:
    hb = json.dumps(header, separators=(",", ":"), sort_keys=True).encode()
    return struct.pack(">H", len(hb)), hb


def seal(key: bytes, header: dict, plaintext: bytes) -> bytes:
    length, hb = _pack(header)
    nonce = os.urandom(NONCE_BYTES)
    ct = AESGCM(key).encrypt(nonce, plaintext, hb)
    return length + hb + nonce + ct


def plain_pack(header: dict, plaintext: bytes) -> bytes:
    length, hb = _pack(header)
    return length + hb + plaintext


def split_header(wire: bytes) -> tuple[dict, bytes, bytes]:
    """Return (header, header_bytes, rest). Header is NOT authenticated yet."""
    try:
        (hl,) = struct.unpack(">H", wire[:2])
        hb = wire[2:2 + hl]
        header = json.loads(hb)
        return header, hb, wire[2 + hl:]
    except Exception as exc:  # malformed frame
        raise DecryptError(f"malformed frame: {exc}") from exc


def open_sealed(key: bytes, hb: bytes, rest: bytes) -> bytes:
    nonce, ct = rest[:NONCE_BYTES], rest[NONCE_BYTES:]
    try:
        return AESGCM(key).decrypt(nonce, ct, hb)
    except InvalidTag as exc:
        raise DecryptError("authentication failed") from exc
    except Exception as exc:
        raise DecryptError(f"decrypt error: {exc}") from exc
