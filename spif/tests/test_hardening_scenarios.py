"""
Dedicated unit tests for advanced security hardening scenarios, including:
1. Extreme clock skew/drift for time-bounded signature checks.
2. CBOR decoder stack/recursion depth exhaustion (DoS prevention).
3. Key ID / Signer ID spoofing/mismatch with keystores.
4. Canonical CBOR enforcement behavior (malleability/re-serialization protection).
5. Signature algorithm downgrade rejection.
"""

from __future__ import annotations
import base64
import hashlib
import struct
import time
from unittest.mock import patch
import pytest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

import cbor2
from spif import (
    SPIFDocument, Node, Provenance, Distribution, Signature,
    SPIFWriter, SPIFReader, SPIFSignatureError, SPIFFormatError,
)
from spif.format import CHUNK_SIGNATURE, CHUNK_CHECKSUM, MAGIC, FORMAT_VERSION, CHUNK_HEADER, CHUNK_PAYLOAD, TAG_DISTRIBUTION
from spif.keystore import SPIFKeyStore


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_key():
    key = Ed25519PrivateKey.generate()
    pub_bytes = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    pub_b64 = base64.b64encode(pub_bytes).decode("ascii")
    return key, pub_b64


def _sign_doc(doc: SPIFDocument, key: Ed25519PrivateKey, signer_id: str) -> bytes:
    writer = SPIFWriter()
    doc.signature = Signature(algorithm="ed25519", signer=signer_id, signature=b"\x00" * 64)
    dummy = writer.encode(doc)

    offset = len(MAGIC) + 2
    sig_offset = None
    while offset < len(dummy):
        ct, ln = struct.unpack_from(">BI", dummy, offset)
        if ct == CHUNK_SIGNATURE:
            sig_offset = offset
            break
        if ct == CHUNK_CHECKSUM:
            break
        offset += 5 + ln
    assert sig_offset is not None

    body_to_sign = dummy[:sig_offset]
    real_sig = key.sign(body_to_sign)
    doc.signature = Signature(algorithm="ed25519", signer=signer_id, signature=real_sig)
    return writer.encode(doc)


def _find_chunk_offset_unchecked(data: bytes, chunk_type: int) -> int | None:
    offset = len(MAGIC) + 2
    while offset < len(data):
        if offset + 5 > len(data):
            break
        ct, ln = struct.unpack_from(">BI", data, offset)
        if ct == chunk_type:
            return offset
        offset += 5 + ln
    return None


def _recompute_checksum(body: bytes) -> bytes:
    checksum = hashlib.sha256(body).digest()
    header = struct.pack(">BI", CHUNK_CHECKSUM, len(checksum))
    return body + header + checksum


def _replace_chunk_data(data: bytes, chunk_type: int, new_cbor: bytes) -> bytes:
    checksum_offset = _find_chunk_offset_unchecked(data, CHUNK_CHECKSUM)
    assert checksum_offset is not None
    body = data[:checksum_offset]

    offset = len(MAGIC) + 2
    while offset < len(body):
        if offset + 5 > len(body):
            break
        ct, ln = struct.unpack_from(">BI", body, offset)
        if ct == chunk_type:
            chunk_start = offset
            chunk_end = offset + 5 + ln
            new_header = struct.pack(">BI", chunk_type, len(new_cbor))
            new_body = body[:chunk_start] + new_header + new_cbor + body[chunk_end:]
            return _recompute_checksum(new_body)
        offset += 5 + ln
    raise AssertionError(f"Chunk 0x{chunk_type:02x} not found")


# ---------------------------------------------------------------------------
# 1. Extreme Clock Skew and Drift
# ---------------------------------------------------------------------------

def test_extreme_clock_skew_and_drift():
    """Verify time-bounded signature checks under extreme clock drift/skew conditions."""
    key, pub_b64 = _make_key()
    doc_ts_ms = 1779379200000  # 2026-05-21

    doc = SPIFDocument(
        payload=[Node(id="n1", type="fact", value="Clock test.")],
        provenance=Provenance(source_model="gpt-4", timestamp_ms=doc_ts_ms)
    )
    signed_data = _sign_doc(doc, key, pub_b64)

    # Positive skew: System clock is far ahead of the document timestamp (expired)
    # The document was signed at 1779379200000. System clock is 1779379200000 + 15000 ms.
    with patch("time.time", return_value=(doc_ts_ms + 15000) / 1000.0):
        reader = SPIFReader(max_signature_age_seconds=10)
        with pytest.raises(SPIFSignatureError, match="Signature expired"):
            reader.decode(signed_data)

    # Negative skew: System clock is behind the document timestamp (future signature)
    # 1. 10 seconds behind (should be rejected since it exceeds 5-second tolerance)
    with patch("time.time", return_value=(doc_ts_ms - 10000) / 1000.0):
        reader = SPIFReader(max_signature_age_seconds=10)
        with pytest.raises(SPIFSignatureError, match="Signature is post-dated"):
            reader.decode(signed_data)

    # 2. 2 seconds behind (should be accepted due to 5-second skew tolerance)
    with patch("time.time", return_value=(doc_ts_ms - 2000) / 1000.0):
        reader = SPIFReader(max_signature_age_seconds=10)
        decoded = reader.decode(signed_data)
        assert decoded.payload[0].value == "Clock test."


# ---------------------------------------------------------------------------
# 2. CBOR Decoder Stack/Recursion Depth Exhaustion (DoS)
# ---------------------------------------------------------------------------

def test_cbor_decoder_deep_nesting_exhaustion():
    """Verify that deep nested CBOR objects inside chunks do not crash the parser process."""
    # Construct a CBOR payload that is nested 1500 levels deep.
    # An array of length 1 is 0x81.
    deep_cbor = b"\x81" * 1500 + b"\x01"

    # Assemble a valid SPIF stream structure manually.
    flags = 0
    header_chunk_data = cbor2.dumps({
        "version": FORMAT_VERSION,
        "flags": flags,
        "flags2": 0,
        "created_ms": 1779379200000,
    }, canonical=True)

    header_chunk = struct.pack(">BI", CHUNK_HEADER, len(header_chunk_data)) + header_chunk_data
    payload_chunk = struct.pack(">BI", CHUNK_PAYLOAD, len(deep_cbor)) + deep_cbor

    body = MAGIC + bytes([FORMAT_VERSION, flags]) + header_chunk + payload_chunk
    checksum = hashlib.sha256(body).digest()
    checksum_chunk = struct.pack(">BI", CHUNK_CHECKSUM, len(checksum)) + checksum

    malicious_data = body + checksum_chunk

    # Verify that SPIFReader.decode safely catches the RecursionError / Exception and raises SPIFFormatError
    reader = SPIFReader()
    with pytest.raises(SPIFFormatError, match="Malformed CBOR in PAYLOAD chunk"):
        reader.decode(malicious_data)


# ---------------------------------------------------------------------------
# 3. Key ID / Signer ID Spoofing/Mismatch
# ---------------------------------------------------------------------------

def test_key_id_spoofing_mismatch(tmp_path):
    """Verify that spoofing signer IDs inside the document causes keystore validation to fail."""
    key_alice, pub_alice = _make_key()
    key_bob, pub_bob = _make_key()

    # Initialize a keystore and register Alice and Bob
    ks = SPIFKeyStore(tmp_path / "keystore")
    ks.add_key("alice", key_alice.public_key())
    ks.add_key("bob", key_bob.public_key())

    # Alice signs the document
    doc = SPIFDocument(
        payload=[Node(id="n1", type="fact", value="Signed by Alice.")],
        provenance=Provenance(source_model="gpt-4", timestamp_ms=1779379200000)
    )
    signed_by_alice = _sign_doc(doc, key_alice, "alice")

    # Verify signature against keystore (should pass, alice is valid)
    assert ks.verify(signed_by_alice) is True

    # Decode and change the signer field to "bob", but leave the signature bytes (made by Alice) unchanged
    decoded = SPIFReader().decode(signed_by_alice)
    assert decoded.signature is not None
    decoded.signature.signer = "bob"

    # Re-encode
    spoofed_bytes = _sign_doc(decoded, key_alice, "bob")  # signed with alice's key but claims to be bob

    # Keystore should lookup Bob's public key, try to verify Alice's signature, and fail
    with pytest.raises(SPIFSignatureError, match="Signature by 'bob' is cryptographically invalid"):
        ks.verify(spoofed_bytes)


# ---------------------------------------------------------------------------
# 4. Canonical CBOR Strictness Enforcement
# ---------------------------------------------------------------------------

def test_canonical_cbor_strictness_enforcement():
    """Verify that non-canonical CBOR causes signature verification mismatch on roundtrip."""
    key, pub_b64 = _make_key()

    # We manually build a list of nodes where the dictionary representing the node has non-canonical key order.
    # Sorted canonical order: "confidence" (length 10), "id" (length 2), "refs" (length 4), "type" (length 4), "value" (length 5)
    # Non-canonical order: we put "value" (length 5) first, then "id" (length 2) etc.
    # Since cbor2.dumps(..., canonical=False) preserves dict insertion order, this is non-canonical.
    node_dict = {}
    node_dict["value"] = "Non-canonical Node"
    node_dict["type"] = "fact"
    node_dict["confidence"] = cbor2.CBORTag(TAG_DISTRIBUTION, {"mean": 0.95, "var": 0.0, "shape": "point", "semantics": "factual_accuracy"})
    node_dict["refs"] = []
    node_dict["id"] = "n1"

    non_canonical_payload_cbor = cbor2.dumps([node_dict], canonical=False)

    # Form a document body manually with non-canonical chunk data
    flags = 0
    header_chunk_data = cbor2.dumps({
        "version": FORMAT_VERSION,
        "flags": flags,
        "flags2": 0,
        "created_ms": 1779379200000,
    }, canonical=True)

    header_chunk = struct.pack(">BI", CHUNK_HEADER, len(header_chunk_data)) + header_chunk_data
    payload_chunk = struct.pack(">BI", CHUNK_PAYLOAD, len(non_canonical_payload_cbor)) + non_canonical_payload_cbor

    body = MAGIC + bytes([FORMAT_VERSION, flags]) + header_chunk + payload_chunk

    # Sign the body (which contains non-canonical bytes)
    sig_val = key.sign(body)

    # Wrap the signature in CHUNK_SIGNATURE
    sig_payload = cbor2.dumps({
        "algorithm": "ed25519",
        "signer": pub_b64,
        "signature": sig_val,
        "key_id": "key-01"
    }, canonical=True)
    sig_chunk = struct.pack(">BI", CHUNK_SIGNATURE, len(sig_payload)) + sig_payload

    # Append checksum
    checksum_body = body + sig_chunk
    checksum_val = hashlib.sha256(checksum_body).digest()
    checksum_chunk = struct.pack(">BI", CHUNK_CHECKSUM, len(checksum_val)) + checksum_val

    signed_non_canonical_bytes = checksum_body + checksum_chunk

    # 1. Verification succeeds on the raw bytes as received (because the signature matches those bytes)
    reader = SPIFReader()
    assert reader.verify_signature(signed_non_canonical_bytes) is True

    # 2. Re-serialization enforced by SPIFWriter always outputs canonical CBOR.
    # If we decode the document and immediately write it back:
    doc_decoded = reader.decode(signed_non_canonical_bytes)
    re_serialized_bytes = SPIFWriter().encode(doc_decoded)

    # 3. Verify that the signature verification now fails on the canonical representation
    # because the canonicalized bytes of the payload chunk are different from the non-canonical ones.
    with pytest.raises(SPIFSignatureError, match="[Ss]ignature verification failed"):
        reader.verify_signature(re_serialized_bytes)


# ---------------------------------------------------------------------------
# 5. Signature Algorithm Downgrade Rejection
# ---------------------------------------------------------------------------

def test_algorithm_downgrade_attacks():
    """Verify that changing signature algorithm to unsupported/weak formats is strictly rejected."""
    key, pub_b64 = _make_key()
    doc = SPIFDocument(
        payload=[Node(id="n1", type="fact", value="Downgrade test.")],
        provenance=Provenance(source_model="gpt-4", timestamp_ms=1779379200000)
    )
    signed_data = _sign_doc(doc, key, pub_b64)

    # Find signature chunk offset and extract its CBOR payload
    sig_offset = _find_chunk_offset_unchecked(signed_data, CHUNK_SIGNATURE)
    assert sig_offset is not None
    _, sig_len = struct.unpack_from(">BI", signed_data, sig_offset)
    sig_cbor = signed_data[sig_offset + 5: sig_offset + 5 + sig_len]

    # Decode signature chunk payload
    sig_obj_dict = cbor2.loads(sig_cbor)
    assert sig_obj_dict["algorithm"] == "ed25519"

    # Try modifying algorithm to unsupported types
    reader = SPIFReader()
    for weak_algo in ["none", "RSA", "ECDSA"]:
        sig_obj_dict["algorithm"] = weak_algo
        new_sig_cbor = cbor2.dumps(sig_obj_dict, canonical=True)

        # Replace chunk data and recompute checksum
        weak_signed_bytes = _replace_chunk_data(signed_data, CHUNK_SIGNATURE, new_sig_cbor)

        # Decode should fail or verify_signature should fail with Unsupported signature algorithm
        with pytest.raises(SPIFSignatureError, match="Unsupported signature algorithm"):
            reader.verify_signature(weak_signed_bytes)


# ---------------------------------------------------------------------------
# 6. Parser Differential / Duplicate Chunks (Semantic Discrepancy)
# ---------------------------------------------------------------------------

def test_duplicate_chunks_semantic_discrepancy():
    """Demonstrate that the parser currently permits duplicate chunks without raising an error."""
    key, pub_b64 = _make_key()
    doc = SPIFDocument(
        payload=[Node(id="n1", type="fact", value="Genuine Payload")]
    )
    signed_data = _sign_doc(doc, key, pub_b64)

    # Construct a second, malicious payload chunk
    malicious_payload_cbor = cbor2.dumps([
        {
            "id": "n1",
            "type": "fact",
            "value": "Malicious Second Payload",
            "confidence": cbor2.CBORTag(TAG_DISTRIBUTION, {"mean": 0.01, "var": 0.0, "shape": "point", "semantics": "factual_accuracy"}),
            "refs": []
        }
    ], canonical=True)
    malicious_chunk = struct.pack(">BI", CHUNK_PAYLOAD, len(malicious_payload_cbor)) + malicious_payload_cbor

    # Find the offset of the first CHUNK_PAYLOAD and insert the duplicate payload chunk right after it
    payload_offset = _find_chunk_offset_unchecked(signed_data, CHUNK_PAYLOAD)
    assert payload_offset is not None
    _, payload_len = struct.unpack_from(">BI", signed_data, payload_offset)
    insert_point = payload_offset + 5 + payload_len

    modified_body = signed_data[:insert_point] + malicious_chunk + signed_data[insert_point:]

    # Since we modified the body, we need to sign and recompute checksum for this new body.
    # The signature chunk is located after the payload chunks. Let's find it in modified_body.
    sig_offset = _find_chunk_offset_unchecked(modified_body, CHUNK_SIGNATURE)
    assert sig_offset is not None

    # Sign everything before the signature chunk
    body_to_sign = modified_body[:sig_offset]
    new_sig_val = key.sign(body_to_sign)

    # Re-serialize the signature chunk with the new signature
    sig_payload = cbor2.dumps({
        "algorithm": "ed25519",
        "signer": pub_b64,
        "signature": new_sig_val,
        "key_id": "key-01"
    }, canonical=True)
    
    # Replace the signature chunk in modified_body and recompute checksum
    final_bytes = _replace_chunk_data(modified_body, CHUNK_SIGNATURE, sig_payload)

    # The document must be rejected due to duplicate CHUNK_PAYLOAD
    reader = SPIFReader()
    with pytest.raises(SPIFFormatError, match="Duplicate chunk of type 0x04"):
        reader.decode(final_bytes)


# ---------------------------------------------------------------------------
# 7. zlib Decompression Bomb (DoS)
# ---------------------------------------------------------------------------

def test_decompression_bomb_denial_of_service():
    """Verify that zlib decompression enforces a maximum decompressed size limit of 10MB."""
    import zlib
    # Create 12 Megabytes of zeroes (exceeding the 10MB safety limit)
    large_payload = b"\x00" * (12 * 1024 * 1024)
    compressed_payload = zlib.compress(large_payload)

    # Let's wrap this compressed payload in a CHUNK_PAYLOAD chunk.
    # We will assemble a valid SPIF structure manually.
    flags = 0
    # Set compression flag in header: FLAG_COMPRESSED (0x02) in flags2 inside HEADER chunk
    from spif.format import FLAG_COMPRESSED
    header_chunk_data = cbor2.dumps({
        "version": FORMAT_VERSION,
        "flags": flags,
        "flags2": FLAG_COMPRESSED,
        "created_ms": 1779379200000,
    }, canonical=True)

    header_chunk = struct.pack(">BI", CHUNK_HEADER, len(header_chunk_data)) + header_chunk_data
    payload_chunk = struct.pack(">BI", CHUNK_PAYLOAD, len(compressed_payload)) + compressed_payload

    body = MAGIC + bytes([FORMAT_VERSION, flags]) + header_chunk + payload_chunk
    checksum = hashlib.sha256(body).digest()
    checksum_chunk = struct.pack(">BI", CHUNK_CHECKSUM, len(checksum)) + checksum

    data = body + checksum_chunk

    # The reader must reject the decompression bomb and raise SPIFFormatError about exceeding safety limit
    reader = SPIFReader()
    with pytest.raises(SPIFFormatError, match="Decompressed data size exceeds safety limit"):
        reader.decode(data)
