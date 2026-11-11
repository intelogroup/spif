"""Weak (small-order) ed25519 signer keys must never verify.

A small-order public key can make cofactored ed25519 verification
accept a forged signature for a fraction of messages — concretely, an
all-zero key with an all-zero signature verified against ~1 in 4
document bodies through both OpenSSL (this package) and ed25519-dalek
(spif-rust) before the guard landed. The migration to wire 0x03
surfaced it by dealing an existing forged-signature test a triggering
body; the hole itself predates the migration.
"""

from __future__ import annotations

import base64
import hashlib
import struct

import cbor2
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from spif import SPIFReader, SPIFSignatureError
from spif.crypto import is_weak_ed25519_public_key
from spif.format import (
    CHUNK_CHECKSUM,
    CHUNK_HEADER,
    CHUNK_PAYLOAD,
    CHUNK_SIGNATURE,
    FORMAT_VERSION,
    MAGIC,
    TAG_DISTRIBUTION,
    cbor_deterministic,
)

ZERO_KEY_B64 = base64.b64encode(b"\x00" * 32).decode()


def _zero_signed_doc(value: str) -> bytes:
    node = {
        "id": "n1",
        "type": "text",
        "value": value,
        "confidence": cbor2.CBORTag(
            TAG_DISTRIBUTION,
            {"mean": 0.9, "var": 0.0, "shape": "point",
             "semantics": "epistemic"},
        ),
        "refs": [],
    }
    payload = cbor_deterministic([node])
    header = cbor_deterministic(
        {"version": FORMAT_VERSION, "flags": 0, "flags2": 0,
         "created_ms": 1779379200000}
    )
    body = (
        MAGIC + bytes([FORMAT_VERSION, 0])
        + struct.pack(">BI", CHUNK_HEADER, len(header)) + header
        + struct.pack(">BI", CHUNK_PAYLOAD, len(payload)) + payload
    )
    sig_payload = cbor_deterministic(
        {"algorithm": "ed25519", "signer": ZERO_KEY_B64,
         "signature": b"\x00" * 64, "key_id": ""}
    )
    doc = body + struct.pack(">BI", CHUNK_SIGNATURE, len(sig_payload)) + sig_payload
    doc += struct.pack(">BI", CHUNK_CHECKSUM, 32) + hashlib.sha256(doc).digest()
    return doc


def test_helper_flags_known_weak_keys():
    assert is_weak_ed25519_public_key(b"\x00" * 32)          # y = 0 point
    assert is_weak_ed25519_public_key(b"\x01" + b"\x00" * 31)  # identity
    assert is_weak_ed25519_public_key(b"\x00" * 31 + b"\x80")  # sign variant


def test_helper_passes_real_keys():
    for _ in range(5):
        raw = Ed25519PrivateKey.generate().public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw
        )
        assert not is_weak_ed25519_public_key(raw)


def test_zero_key_forgery_never_verifies():
    # Several bodies: before the guard, roughly one in four verified.
    reader = SPIFReader()
    for i in range(8):
        with pytest.raises(SPIFSignatureError):
            reader.verify_signature(_zero_signed_doc(f"forged-{i}"))
