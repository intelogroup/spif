"""ed25519 signature: roundtrip, tamper detection, verification."""

import base64
import pytest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from spfx import (
    SPIFDocument, Node, SPIFWriter, SPIFReader,
    Signature, SPIFChecksumError, SPIFSignatureError,
)
from spfx.format import MAGIC


def _make_key():
    key = Ed25519PrivateKey.generate()
    pub_b64 = base64.b64encode(
        key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    ).decode()
    return key, pub_b64


def _sign_doc(doc: SPIFDocument, key, signer_id: str) -> bytes:
    """
    Two-pass signing:
    1. Encode with a dummy 64-byte signature to lock in the final body structure
       (including FLAG_SIGNATURE in the header).
    2. Find the SIGNATURE chunk offset → body_to_sign = everything before it.
    3. Sign body_to_sign with the real key.
    4. Re-encode with the real signature (same body layout, same chunk offsets).
    """
    import struct
    writer = SPIFWriter()

    # Pass 1: dummy sig to get correct body structure
    doc.signature = Signature(algorithm="ed25519", signer=signer_id, signature=b"\x00" * 64)
    dummy = writer.encode(doc)

    # Find SIGNATURE chunk offset in dummy
    offset = len(MAGIC) + 2
    sig_offset = None
    while offset < len(dummy):
        ct, ln = struct.unpack_from(">BI", dummy, offset)
        if ct == 0x07:  # CHUNK_SIGNATURE
            sig_offset = offset
            break
        if ct == 0xFF:
            break
        offset += 5 + ln
    assert sig_offset is not None, "SIGNATURE chunk not found in dummy encoding"

    body_to_sign = dummy[:sig_offset]

    # Pass 2: sign and re-encode
    raw_sig = key.sign(body_to_sign)
    doc.signature = Signature(algorithm="ed25519", signer=signer_id, signature=raw_sig)
    return writer.encode(doc)


def test_signed_document_roundtrip():
    key, pub_b64 = _make_key()
    doc = SPIFDocument(payload=[Node(id="n1", type="fact", value="Signed claim.")])
    data = _sign_doc(doc, key, pub_b64)
    restored = SPIFReader().decode(data)
    assert restored.signature is not None
    assert restored.signature.algorithm == "ed25519"
    assert len(restored.signature.signature) == 64


def test_signature_verify_valid():
    key, pub_b64 = _make_key()
    doc = SPIFDocument(payload=[Node(id="n1", type="fact", value="Verified claim.")])
    data = _sign_doc(doc, key, pub_b64)
    # verify_signature returns True for a valid signed document
    assert SPIFReader().verify_signature(data) is True


def test_signature_verify_tampered_body():
    key, pub_b64 = _make_key()
    doc = SPIFDocument(payload=[Node(id="n1", type="fact", value="Original claim.")])
    data = bytearray(_sign_doc(doc, key, pub_b64))
    # Flip a byte well inside the PAYLOAD CBOR data (past preamble + HEADER chunk + PAYLOAD length field)
    data[len(MAGIC) + 2 + 50] ^= 0x01
    # Checksum will catch this first
    with pytest.raises(SPIFChecksumError):
        SPIFReader().verify_signature(bytes(data))


def test_verify_signature_with_wrong_key():
    """verify_signature raises SPIFSignatureError when signer field holds wrong public key."""
    import struct
    key, pub_b64 = _make_key()
    wrong_key, wrong_pub_b64 = _make_key()
    doc = SPIFDocument(payload=[Node(id="n1", type="fact", value="Claim.")])
    # Sign with correct key, but store the WRONG public key in signer field
    writer = SPIFWriter()
    doc.signature = Signature(algorithm="ed25519", signer=wrong_pub_b64, signature=b"\x00" * 64)
    dummy = writer.encode(doc)
    offset = len(MAGIC) + 2
    sig_offset = None
    while offset < len(dummy):
        ct, ln = struct.unpack_from(">BI", dummy, offset)
        if ct == 0x07:
            sig_offset = offset
            break
        if ct == 0xFF:
            break
        offset += 5 + ln
    body_to_sign = dummy[:sig_offset]
    raw_sig = key.sign(body_to_sign)
    doc.signature = Signature(algorithm="ed25519", signer=wrong_pub_b64, signature=raw_sig)
    data = writer.encode(doc)
    # verify_signature uses signer field (wrong pub key) → must raise
    with pytest.raises(SPIFSignatureError):
        SPIFReader().verify_signature(data)


def test_unsigned_document_verify_returns_false():
    doc = SPIFDocument(payload=[Node(id="n1", type="fact", value="Unsigned.")])
    data = SPIFWriter().encode(doc)
    result = SPIFReader().verify_signature(data)
    assert result is False


def test_verify_signature_rejects_wrong_algorithm_label():
    import struct

    key, pub_b64 = _make_key()
    doc = SPIFDocument(payload=[Node(id="n1", type="fact", value="Claim.")])
    writer = SPIFWriter()
    doc.signature = Signature(algorithm="rsa", signer=pub_b64, signature=b"\x00" * 64)
    dummy = writer.encode(doc)
    offset = len(MAGIC) + 2
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
    body_to_sign = dummy[:sig_offset]
    raw_sig = key.sign(body_to_sign)
    doc.signature = Signature(algorithm="rsa", signer=pub_b64, signature=raw_sig)
    data = writer.encode(doc)

    with pytest.raises(SPIFSignatureError, match="Unsupported signature algorithm"):
        SPIFReader().verify_signature(data)


def test_stale_signature_rejected_by_decode():
    """Attack 3 regression: tamper payload + recompute checksum, keep stale sig bytes.

    Before the fix, decode(require_signature=True) only checked signature presence,
    not cryptographic validity. An attacker who recomputed the SHA-256 checksum after
    modifying content would bypass tamper detection entirely.
    """
    import hashlib
    import struct

    key, pub_b64 = _make_key()
    doc = SPIFDocument(payload=[Node(id="n1", type="fact", value="original")])
    data = _sign_doc(doc, key, pub_b64)

    assert SPIFReader().verify_signature(data) is True

    # Locate SIGNATURE chunk and CHECKSUM chunk offsets
    offset = len(MAGIC) + 2
    sig_offset = checksum_offset = None
    while offset < len(data):
        ct, ln = struct.unpack_from(">BI", data, offset)
        if ct == 0x07:   # CHUNK_SIGNATURE
            sig_offset = offset
        if ct == 0xFF:   # CHUNK_CHECKSUM
            checksum_offset = offset
            break
        offset += 5 + ln

    assert sig_offset is not None and checksum_offset is not None

    # Attacker: mutate one byte inside the signing body, keep original sig chunk intact
    body = bytearray(data[:checksum_offset])
    target = data.index(b"original")   # CBOR text bytes — no length prefix here
    assert target < sig_offset, "target byte must be inside the signing body"
    body[target] = ord("X")            # "original" → "Xriginal", same length, valid UTF-8

    # Recompute checksum so SPIFChecksumError is not raised
    new_body = bytes(body)
    new_checksum = hashlib.sha256(new_body).digest()
    tampered = new_body + struct.pack(">BI", 0xFF, len(new_checksum)) + new_checksum

    # Checksum is now valid. Signature must still be rejected.
    with pytest.raises(SPIFSignatureError, match="Signature verification failed"):
        SPIFReader(require_signature=True).decode(tampered)


def test_checksum_covers_signature_chunk():
    """The CHECKSUM must cover the SIGNATURE chunk bytes."""
    key, pub_b64 = _make_key()
    doc = SPIFDocument(payload=[Node(id="n1", type="fact", value="Check coverage.")])
    data = bytearray(_sign_doc(doc, key, pub_b64))
    # Find SIGNATURE chunk and tamper it
    import struct
    offset = len(MAGIC) + 2
    while offset < len(data):
        ct, ln = struct.unpack_from(">BI", data, offset)
        if ct == 0x07:  # CHUNK_SIGNATURE
            # Flip a byte inside the signature chunk data
            data[offset + 5] ^= 0x01
            break
        if ct == 0xFF:
            break
        offset += 5 + ln
    with pytest.raises(SPIFChecksumError):
        SPIFReader().decode(bytes(data))
