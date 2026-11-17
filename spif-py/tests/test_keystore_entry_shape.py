"""Permanent regression suite for SPIF-KEYSTORE-ENTRY-SHAPE-001.

Converted from the loop probe test_loop_keystore_entry_shape_probe.py
(cycle 2026-11-16-1422; preserved under the loop goal's
hidden_files/evidence/2026-11-16-1422/spif/, and re-preserved as the
2026-11-17-0222 regression bundle). Probe legs are verbatim after
this docstring; the final legs were added at conversion for the
get_key / add_hybrid_key paths the same fix pass hardens.

Invariant: a malformed key entry (wrong-length .pub file
planted/truncated on disk, or non-bytes key material handed to
add_key) fails closed with a clean SPIFSignatureError / clean
rejection -- never a bare ValueError from the cryptography layer,
never a coerced entry, never acceptance.

Fix: get_key length-checks the raw classical entry (32 bytes exactly,
else SPIFSignatureError), mirroring get_hybrid_key; the add paths
route key material through _raw_key_bytes, which accepts only an
Ed25519PublicKey or bytes-like material and refuses anything else
with ValueError instead of coercing it via bytes(...).
"""
from __future__ import annotations

import struct

import pytest
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from spif import SPIFWriter, SPIFDocument, Node, Distribution
from spif.keystore import SPIFKeyStore
from spif.reader import SPIFSignatureError
from spif.crypto import derive_key_from_mnemonic
from spif.types import Signature


def _pub(key) -> bytes:
    return key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def _sign(private_key, signer_id: str) -> bytes:
    doc = SPIFDocument(payload=[
        Node(id="r", type="text", value="Hello keystore",
             confidence=Distribution(mean=0.9, var=0.05))
    ])
    writer = SPIFWriter()
    doc.signature = Signature(algorithm="ed25519", signer=signer_id, signature=b"\x00" * 64)
    dummy = writer.encode(doc)
    offset = len(b"\x89SPIF\r\n\x1a\n") + 2
    sig_offset = None
    while offset < len(dummy):
        ct, ln = struct.unpack_from(">BI", dummy, offset)
        if ct == 0x07:
            sig_offset = offset
            break
        if ct == 0xFF:
            break
        offset += 5 + ln
    assert sig_offset is not None
    doc.signature = Signature(algorithm="ed25519", signer=signer_id,
                              signature=private_key.sign(dummy[:sig_offset]))
    return writer.encode(doc)


@pytest.fixture
def setup(tmp_path):
    ks = SPIFKeyStore(tmp_path / "keys")
    key = derive_key_from_mnemonic("alice test mnemonic")
    ks.add_key("alice", _pub(key))
    return ks, _sign(key, "alice"), tmp_path / "keys" / "alice.pub"


def test_control_valid_entry_verifies(setup):
    ks, raw, _ = setup
    assert ks.verify(raw) is True


def test_control_wrong_32byte_key_clean_rejection(setup):
    ks, raw, entry = setup
    other = derive_key_from_mnemonic("bob test mnemonic")
    entry.write_bytes(_pub(other))
    with pytest.raises(SPIFSignatureError):
        ks.verify(raw)


@pytest.mark.parametrize("n", [0, 1, 31, 33, 64])
def test_corrupted_entry_length_fails_closed_cleanly(setup, n):
    ks, raw, entry = setup
    entry.write_bytes(b"\x07" * n)
    with pytest.raises(SPIFSignatureError):
        ks.verify(raw)


def test_truncated_hybrid_entry_returns_none(tmp_path):
    ks = SPIFKeyStore(tmp_path / "keys")
    (tmp_path / "keys" / "alice.hyb").write_bytes(b"\x07" * 100)
    assert ks.get_hybrid_key("alice") is None


def test_add_key_int_material_not_coerced(tmp_path):
    ks = SPIFKeyStore(tmp_path / "keys")
    with pytest.raises((ValueError, TypeError)):
        ks.add_key("mallory", 32)  # bytes(32) would be a 32-byte zero key
    assert ks.get_key("mallory") is None


# --- added at conversion: get_key / hybrid add paths -------------------
# The preserved probe exercises verify() and add_key. The fix also
# length-checks at get_key itself and validates hybrid key material,
# so those paths are pinned here.

@pytest.mark.parametrize("n", [0, 31, 33])
def test_get_key_corrupted_entry_raises_spif_error(setup, n):
    ks, _raw, entry = setup
    entry.write_bytes(b"\x07" * n)
    with pytest.raises(SPIFSignatureError):
        ks.get_key("alice")


def test_add_hybrid_key_int_material_not_coerced(tmp_path):
    from spif.pq_hybrid import ML_DSA_65_PUBLIC_KEY_LEN

    ks = SPIFKeyStore(tmp_path / "keys")
    with pytest.raises(ValueError):
        ks.add_hybrid_key("mallory", 32, b"M" * ML_DSA_65_PUBLIC_KEY_LEN)
    with pytest.raises(ValueError):
        ks.add_hybrid_key("mallory", b"K" * 32, 1952)
    assert ks.get_hybrid_key("mallory") is None


def test_add_key_string_material_rejected(tmp_path):
    ks = SPIFKeyStore(tmp_path / "keys")
    with pytest.raises(ValueError):
        ks.add_key("mallory", "not-a-key")
    assert ks.get_key("mallory") is None
