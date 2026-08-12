"""
Security audit test suite for SIF.

Tests the threat model for the binary format and cryptographic layer:
  - Replay attacks (timestamp coverage)
  - Signature stripping (graceful degradation)
  - Length extension (trailing garbage detection)
  - Malformed CBOR in each chunk type
  - Truncation robustness
  - Wrong key / key mismatch
  - Multi-signature roundtrip and failure modes
  - Timing-safe checksum comparison
"""
from __future__ import annotations
import base64
import hashlib
import json
import struct
import tempfile
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from spif import (
    SPIFDocument, Node, Provenance, Distribution, Signature,
    SPIFWriter, SPIFReader,
    SPIFError, SPIFChecksumError, SPIFSignatureError,
)
from spif.format import CHUNK_SIGNATURE, CHUNK_MULTISIG, CHUNK_CHECKSUM, MAGIC


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_key():
    key = Ed25519PrivateKey.generate()
    pub_b64 = base64.b64encode(
        key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    ).decode()
    return key, pub_b64


def _minimal_doc(ts: int = 1_700_000_000_000) -> SPIFDocument:
    return SPIFDocument(
        payload=[Node(
            id="n1",
            type="fact",
            value="test",
            confidence=Distribution(mean=0.9, semantics="factual_accuracy"),
        )],
        provenance=Provenance(source_model="test-model", timestamp_ms=ts),
    )


def _recompute_checksum(body: bytes) -> bytes:
    """Return body + fresh CHECKSUM chunk."""
    checksum = hashlib.sha256(body).digest()
    header = struct.pack(">BI", CHUNK_CHECKSUM, len(checksum))
    return body + header + checksum


def _sign_doc(doc: SPIFDocument, key: Ed25519PrivateKey, pub_b64: str) -> bytes:
    """Two-pass signing — mirrors test_signature.py helper."""
    writer = SPIFWriter()
    doc.signature = Signature(algorithm="ed25519", signer=pub_b64, signature=b"\x00" * 64)
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
    doc.signature = Signature(algorithm="ed25519", signer=pub_b64, signature=real_sig)
    return writer.encode(doc)


def _multisign_doc(doc: SPIFDocument, keys_and_ids: list[tuple]) -> bytes:
    """Two-pass multi-signing."""
    writer = SPIFWriter()
    # Pass 1: dummy sigs
    doc.signatures = [
        Signature(algorithm="ed25519", signer=pub_b64, signature=b"\x00" * 64)
        for _, pub_b64 in keys_and_ids
    ]
    dummy = writer.encode(doc)

    # Find MULTISIG chunk offset
    offset = len(MAGIC) + 2
    ms_offset = None
    while offset < len(dummy):
        ct, ln = struct.unpack_from(">BI", dummy, offset)
        if ct == CHUNK_MULTISIG:
            ms_offset = offset
            break
        if ct == CHUNK_CHECKSUM:
            break
        offset += 5 + ln
    assert ms_offset is not None

    body_to_sign = dummy[:ms_offset]
    doc.signatures = [
        Signature(algorithm="ed25519", signer=pub_b64, signature=key.sign(body_to_sign))
        for key, pub_b64 in keys_and_ids
    ]
    return writer.encode(doc)


def _find_chunk_offset(data: bytes, chunk_type: int) -> int | None:
    """Return byte offset of first occurrence of chunk_type (or None)."""
    offset = len(MAGIC) + 2
    while offset < len(data):
        if offset + 5 > len(data):
            break
        ct, ln = struct.unpack_from(">BI", data, offset)
        if ct == chunk_type:
            return offset
        if ct == CHUNK_CHECKSUM:
            break
        offset += 5 + ln
    return None


def _replace_chunk_data(data: bytes, chunk_type: int, new_cbor: bytes) -> bytes:
    """
    Replace the CBOR payload of chunk_type with new_cbor,
    recompute the checksum, and return the new document bytes.
    """
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


def _find_chunk_offset_unchecked(data: bytes, chunk_type: int) -> int | None:
    """Like _find_chunk_offset but also finds CHUNK_CHECKSUM."""
    offset = len(MAGIC) + 2
    while offset < len(data):
        if offset + 5 > len(data):
            break
        ct, ln = struct.unpack_from(">BI", data, offset)
        if ct == chunk_type:
            return offset
        offset += 5 + ln
    return None


# ---------------------------------------------------------------------------
# 1. Replay attack
# ---------------------------------------------------------------------------

class TestReplayAttack:
    def test_different_timestamps_produce_different_checksum(self):
        """
        Same payload, different provenance.timestamp_ms → different checksums.
        The timestamp is covered by the SHA-256, so replaying old bytes with a
        different timestamp is detectable.
        """
        doc1 = _minimal_doc(ts=1_000_000)
        doc2 = _minimal_doc(ts=2_000_000)
        data1 = SPIFWriter().encode(doc1)
        data2 = SPIFWriter().encode(doc2)
        # Extract checksums
        off1 = _find_chunk_offset_unchecked(data1, CHUNK_CHECKSUM)
        off2 = _find_chunk_offset_unchecked(data2, CHUNK_CHECKSUM)
        assert off1 is not None and off2 is not None
        ck1 = data1[off1 + 5: off1 + 5 + 32]
        ck2 = data2[off2 + 5: off2 + 5 + 32]
        assert ck1 != ck2, "Different timestamps must produce different checksums"

    def test_payload_change_changes_checksum(self):
        """Any change to payload changes the checksum."""
        doc1 = _minimal_doc()
        doc1.payload[0].id = "nodeA"
        doc2 = _minimal_doc()
        doc2.payload[0].id = "nodeB"
        data1 = SPIFWriter().encode(doc1)
        data2 = SPIFWriter().encode(doc2)
        assert data1 != data2


# ---------------------------------------------------------------------------
# 2. Signature stripping
# ---------------------------------------------------------------------------

class TestSignatureStripping:
    def test_strip_sig_chunk_verify_returns_false(self):
        """
        Remove CHUNK_SIGNATURE from a signed document, recompute checksum.
        verify_signature must return False (no sig present), not raise.
        """
        key, pub_b64 = _make_key()
        doc = _minimal_doc()
        data = _sign_doc(doc, key, pub_b64)

        # Find and excise SIGNATURE chunk
        sig_off = _find_chunk_offset(data, CHUNK_SIGNATURE)
        assert sig_off is not None, "Document should have SIGNATURE chunk"
        _, sig_len = struct.unpack_from(">BI", data, sig_off)
        sig_end = sig_off + 5 + sig_len

        # Remove sig chunk from body (before checksum)
        checksum_off = _find_chunk_offset_unchecked(data, CHUNK_CHECKSUM)
        body = data[:checksum_off]
        stripped_body = body[:sig_off] + body[sig_end:]

        # Also clear FLAG_SIGNATURE (byte 9, bit 0x20) and re-encode the version+flags byte
        # Actually just recompute checksum and decode — the flag mismatch is OK for our test
        stripped = _recompute_checksum(stripped_body)

        reader = SPIFReader()
        # decode succeeds (checksum now valid for stripped body)
        result = reader.verify_signature(stripped)
        assert result is False, "verify_signature must return False for unsigned doc"

    def test_unsigned_doc_verify_returns_false(self):
        """Unsigning a document from the start returns False, not raises."""
        doc = _minimal_doc()
        data = SPIFWriter().encode(doc)
        assert SPIFReader().verify_signature(data) is False


# ---------------------------------------------------------------------------
# 3. Length extension
# ---------------------------------------------------------------------------

class TestLengthExtension:
    def test_garbage_after_checksum_is_ignored_safely(self):
        """
        The SIF reader stops reading at the CHECKSUM chunk. Appending garbage
        after it must not cause an unhandled exception — the document decodes
        normally (trailing bytes are not processed).
        """
        doc = _minimal_doc()
        data = SPIFWriter().encode(doc)
        tampered = data + b"\x00" * 100

        # The reader should succeed — it stops at CHECKSUM
        decoded = SPIFReader().decode(tampered)
        assert len(decoded.payload) == 1

    def test_checksum_chunk_body_replacement_detected(self):
        """
        Changing the stored checksum bytes to garbage is detected as SPIFChecksumError.
        """
        doc = _minimal_doc()
        data = SPIFWriter().encode(doc)
        # Replace checksum bytes with zeros
        ck_off = _find_chunk_offset_unchecked(data, CHUNK_CHECKSUM)
        assert ck_off is not None
        tampered = bytearray(data)
        for i in range(ck_off + 5, ck_off + 5 + 32):
            tampered[i] = 0x00
        with pytest.raises(SPIFChecksumError):
            SPIFReader().decode(bytes(tampered))


# ---------------------------------------------------------------------------
# 4. Malformed CBOR
# ---------------------------------------------------------------------------

class TestMalformedCBOR:
    """
    Inject invalid CBOR (0xff 0xff is not valid CBOR) into each chunk type.
    Recompute checksum so the checksum passes, then decode → must raise a
    SPIFError subclass, never a raw Python exception like AttributeError.
    """
    INVALID_CBOR = b"\xff\xff"

    def _inject_and_decode(self, chunk_type: int) -> None:
        from spif.format import CHUNK_SIGNATURE
        doc = _minimal_doc()
        # Add trace + signature so those chunks exist
        from spif import TraceStep
        doc.trace = [
            TraceStep(id="s0", type="evidence", content="test",
                      confidence=Distribution(mean=0.8, semantics="epistemic"), deps=[]),
        ]
        key, pub_b64 = _make_key()
        if chunk_type == CHUNK_SIGNATURE:
            data = _sign_doc(doc, key, pub_b64)
        else:
            data = SPIFWriter().encode(doc)

        tampered = _replace_chunk_data(data, chunk_type, self.INVALID_CBOR)
        with pytest.raises(SPIFError):
            SPIFReader().decode(tampered)

    def test_malformed_payload_cbor(self):
        from spif.format import CHUNK_PAYLOAD
        self._inject_and_decode(CHUNK_PAYLOAD)

    def test_malformed_provenance_cbor(self):
        from spif.format import CHUNK_PROVENANCE
        self._inject_and_decode(CHUNK_PROVENANCE)

    def test_malformed_trace_cbor(self):
        from spif.format import CHUNK_TRACE
        self._inject_and_decode(CHUNK_TRACE)

    def test_malformed_signature_cbor(self):
        self._inject_and_decode(CHUNK_SIGNATURE)


# ---------------------------------------------------------------------------
# 5. Truncation
# ---------------------------------------------------------------------------

class TestTruncation:
    def test_truncation_at_every_10th_byte_raises_sif_error(self):
        """
        Truncating the document at any point must raise a SPIFError subclass,
        never a raw AttributeError, IndexError, or other unhandled exception.
        """
        doc = _minimal_doc()
        data = SPIFWriter().encode(doc)
        reader = SPIFReader()

        failures = []
        for cut in range(1, len(data), 10):
            try:
                reader.decode(data[:cut])
            except SPIFError:
                pass  # expected
            except Exception as e:
                failures.append((cut, type(e).__name__, str(e)))

        assert not failures, (
            "Non-SPIFError exceptions on truncation:\n"
            + "\n".join(f"  cut={c}: {t}: {m}" for c, t, m in failures)
        )


# ---------------------------------------------------------------------------
# 6. Wrong key
# ---------------------------------------------------------------------------

class TestWrongKeyID:
    def test_wrong_key_raises_sig_error(self):
        """
        Sign with key A, but put key B's public key as the signer.
        verify_signature must raise SPIFSignatureError.
        """
        key_a, _pub_a = _make_key()
        key_b, pub_b = _make_key()

        # Sign with A but record B's public key as signer
        doc = _minimal_doc()
        data = _sign_doc(doc, key_a, pub_b)  # intentional mismatch

        with pytest.raises(SPIFSignatureError):
            SPIFReader().verify_signature(data)

    def test_correct_key_passes(self):
        key, pub_b64 = _make_key()
        doc = _minimal_doc()
        data = _sign_doc(doc, key, pub_b64)
        assert SPIFReader().verify_signature(data) is True


# ---------------------------------------------------------------------------
# 7. Multi-signature
# ---------------------------------------------------------------------------

class TestMultiSignature:
    def test_multisig_roundtrip(self):
        """Multi-sig document survives encode → decode with all signatures preserved."""
        key1, pub1 = _make_key()
        key2, pub2 = _make_key()
        doc = _minimal_doc()
        data = _multisign_doc(doc, [(key1, pub1), (key2, pub2)])

        decoded = SPIFReader().decode(data)
        assert len(decoded.signatures) == 2
        assert decoded.signatures[0].signer == pub1
        assert decoded.signatures[1].signer == pub2

    def test_multisig_all_valid_returns_true(self):
        """All-valid multi-sig: verify_signature returns True."""
        key1, pub1 = _make_key()
        key2, pub2 = _make_key()
        doc = _minimal_doc()
        data = _multisign_doc(doc, [(key1, pub1), (key2, pub2)])
        assert SPIFReader().verify_signature(data) is True

    def test_multisig_one_invalid_raises(self):
        """If one signature in CHUNK_MULTISIG is wrong, verify raises SPIFSignatureError."""
        key1, pub1 = _make_key()
        key2, pub2 = _make_key()
        key_bad, _ = _make_key()

        doc = _minimal_doc()
        # Sign with key1 + key_bad, but record pub2 as second signer (mismatch)
        data = _multisign_doc(doc, [(key1, pub1), (key_bad, pub2)])

        with pytest.raises(SPIFSignatureError):
            SPIFReader().verify_signature(data)

    def test_multisig_revoked_signer_raises(self):
        """Revoked signer ID raises SPIFSignatureError even if sig is cryptographically valid."""
        key1, pub1 = _make_key()
        key2, pub2 = _make_key()
        doc = _minimal_doc()
        data = _multisign_doc(doc, [(key1, pub1), (key2, pub2)])

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({"revoked": [pub1]}, f)
            revocation_path = f.name

        try:
            with pytest.raises(SPIFSignatureError, match="revoked"):
                SPIFReader().verify_signature(data, revocation_list_path=revocation_path)
        finally:
            Path(revocation_path).unlink(missing_ok=True)

    def test_multisig_key_id_roundtrips(self):
        """key_id field on Signature survives encode → decode."""
        key, pub = _make_key()
        doc = _minimal_doc()
        # Build MULTISIG with key_id
        from spif import SPIFWriter, SPIFReader
        writer = SPIFWriter()
        doc.signatures = [
            Signature(algorithm="ed25519", signer=pub, signature=b"\x00" * 64,
                      key_id="rotation-v2"),
        ]
        dummy = writer.encode(doc)
        # Find MULTISIG offset
        ms_off = _find_chunk_offset(dummy, CHUNK_MULTISIG)
        assert ms_off is not None
        body_to_sign = dummy[:ms_off]
        real_sig = key.sign(body_to_sign)
        doc.signatures = [
            Signature(algorithm="ed25519", signer=pub, signature=real_sig,
                      key_id="rotation-v2"),
        ]
        data = writer.encode(doc)
        decoded = SPIFReader().decode(data)
        assert decoded.signatures[0].key_id == "rotation-v2"

    def test_signature_and_multisig_share_first_auth_boundary(self):
        """
        When both SIGNATURE and MULTISIG are present, all signatures must verify
        against the same body: bytes before the first auth chunk.
        """
        key1, pub1 = _make_key()
        key2, pub2 = _make_key()
        doc = _minimal_doc()

        writer = SPIFWriter()
        doc.signature = Signature(algorithm="ed25519", signer=pub1, signature=b"\x00" * 64)
        doc.signatures = [Signature(algorithm="ed25519", signer=pub2, signature=b"\x00" * 64)]
        dummy = writer.encode(doc)

        sig_off = _find_chunk_offset(dummy, CHUNK_SIGNATURE)
        assert sig_off is not None
        body_to_sign = dummy[:sig_off]

        doc.signature = Signature(
            algorithm="ed25519",
            signer=pub1,
            signature=key1.sign(body_to_sign),
        )
        doc.signatures = [Signature(
            algorithm="ed25519",
            signer=pub2,
            signature=key2.sign(body_to_sign),
        )]

        data = writer.encode(doc)
        assert SPIFReader().verify_signature(data) is True


# ---------------------------------------------------------------------------
# 8. Timing safety
# ---------------------------------------------------------------------------

class TestTimingSafety:
    def test_hmac_imported_in_reader(self):
        """
        Structural test: the reader module must import hmac and use compare_digest
        for the checksum comparison (timing-safe).
        """
        import spif.reader as reader_module
        import inspect
        source = inspect.getsource(reader_module)
        assert "import hmac" in source, "reader.py must import hmac"
        assert "compare_digest" in source, "reader.py must use hmac.compare_digest"

    def test_checksum_tamper_raises_not_asserts(self):
        """
        A single-byte flip in the checksum bytes raises SPIFChecksumError specifically
        (not AssertionError or any other unhandled exception).
        """
        doc = _minimal_doc()
        data = SPIFWriter().encode(doc)
        ck_off = _find_chunk_offset_unchecked(data, CHUNK_CHECKSUM)
        assert ck_off is not None
        tampered = bytearray(data)
        tampered[ck_off + 5] ^= 0xFF  # flip first byte of stored checksum
        with pytest.raises(SPIFChecksumError):
            SPIFReader().decode(bytes(tampered))


# ---------------------------------------------------------------------------
# 9. Crypto module
# ---------------------------------------------------------------------------

class TestCryptoModule:
    def test_derive_key_deterministic(self):
        """Same mnemonic always produces the same ed25519 key."""
        import warnings
        from spif.crypto import derive_key_from_mnemonic
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            k1 = derive_key_from_mnemonic("abandon abandon abandon")
            k2 = derive_key_from_mnemonic("abandon abandon abandon")
        pub1 = k1.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        pub2 = k2.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        assert pub1 == pub2

    def test_derive_key_different_mnemonic(self):
        """Different mnemonics produce different keys."""
        import warnings
        from spif.crypto import derive_key_from_mnemonic
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            k1 = derive_key_from_mnemonic("abandon abandon abandon")
            k2 = derive_key_from_mnemonic("zoo zoo zoo")
        pub1 = k1.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        pub2 = k2.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        assert pub1 != pub2

    def test_derive_key_passphrase_changes_key(self):
        """Same mnemonic, different passphrase → different key."""
        import warnings
        from spif.crypto import derive_key_from_mnemonic
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            k1 = derive_key_from_mnemonic("abandon abandon abandon", passphrase="")
        k2 = derive_key_from_mnemonic("abandon abandon abandon", passphrase="secret")
        pub1 = k1.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        pub2 = k2.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        assert pub1 != pub2

    def test_derive_key_empty_passphrase_warns(self):
        """Empty passphrase fires UserWarning about static salt."""
        import warnings
        from spif.crypto import derive_key_from_mnemonic
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            derive_key_from_mnemonic("abandon abandon abandon", passphrase="")
        assert any(issubclass(x.category, UserWarning) and "passphrase" in str(x.message) for x in w)

    def test_rotate_key_returns_valid_record(self):
        """rotate_key returns a JSON-serializable record with required fields."""
        import warnings
        from spif.crypto import rotate_key, derive_key_from_mnemonic
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            old_key = derive_key_from_mnemonic("old old old")
            new_key = derive_key_from_mnemonic("new new new")
        record = rotate_key(old_key, new_key, "old-signer", "new-signer")
        assert record["old_signer"] == "old-signer"
        assert record["superseded_by"] == "new-signer"
        assert "proof" in record
        assert "timestamp_ms" in record
        json.dumps(record)  # must be serializable

    def test_revocation_list_empty_on_missing_file(self):
        """load_revocation_list returns empty set for non-existent file."""
        from spif.crypto import load_revocation_list
        result = load_revocation_list("/tmp/nonexistent_sif_revocation_xyz.json")
        assert result == set()

    def test_revocation_list_loads_correctly(self):
        from spif.crypto import load_revocation_list, check_revocation
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({"revoked": ["signer-a", "signer-b"]}, f)
            path = f.name
        try:
            revoked = load_revocation_list(path)
            assert "signer-a" in revoked
            assert "signer-b" in revoked
            assert "signer-c" not in revoked
            with pytest.raises(SPIFSignatureError):
                check_revocation("signer-a", revoked)
            check_revocation("signer-c", revoked)  # should not raise
        finally:
            Path(path).unlink(missing_ok=True)

    def test_content_id_stable(self):
        """compute_content_id returns the same value for identical documents."""
        from spif.writer import compute_content_id
        doc = _minimal_doc()
        assert compute_content_id(doc) == compute_content_id(doc)

    def test_content_id_changes_with_payload(self):
        """compute_content_id changes when payload content changes."""
        from spif.writer import compute_content_id
        doc1 = _minimal_doc()
        doc2 = _minimal_doc()
        doc2.payload[0].value = "different value"
        assert compute_content_id(doc1) != compute_content_id(doc2)

    def test_content_id_independent_of_signature(self):
        """compute_content_id is unaffected by adding a signature."""
        from spif.writer import compute_content_id
        doc = _minimal_doc()
        id_before = compute_content_id(doc)
        doc.signature = Signature(
            algorithm="ed25519", signer="test", signature=b"\x00" * 64
        )
        id_after = compute_content_id(doc)
        assert id_before == id_after
