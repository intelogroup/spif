"""
Tests for SPIFKeyStore — file-based public key management and verification.
"""

from __future__ import annotations

import json
import time
import base64
import pytest
from pathlib import Path
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from spif import SPIFWriter, SPIFReader, SPIFDocument, Node, Distribution
from spif.keystore import SPIFKeyStore, verify_with_keystore, _key_slug
from spif.reader import SPIFSignatureError
from spif.crypto import derive_key_from_mnemonic
from spif.types import Signature


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def tmp_ks(tmp_path):
    return SPIFKeyStore(tmp_path / "keys")


@pytest.fixture
def alice_key():
    return derive_key_from_mnemonic("alice test mnemonic")


@pytest.fixture
def bob_key():
    return derive_key_from_mnemonic("bob test mnemonic")


def _alice_pub(alice_key) -> bytes:
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    return alice_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def _make_doc() -> SPIFDocument:
    return SPIFDocument(payload=[
        Node(id="r", type="text", value="Hello keystore",
             confidence=Distribution(mean=0.9, var=0.05))
    ])


def _sign_doc(doc: SPIFDocument, private_key, signer_id: str) -> bytes:
    """
    Two-pass signing matching the SPIF wire contract.

    The signature covers all bytes before the first auth chunk. The checksum is
    emitted after the signature chunk and therefore covers the signature bytes.
    """
    import struct

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
    body_to_sign = dummy[:sig_offset]
    real_sig = private_key.sign(body_to_sign)
    doc.signature = Signature(algorithm="ed25519", signer=signer_id, signature=real_sig)
    return writer.encode(doc)


# ---------------------------------------------------------------------------
# Key management
# ---------------------------------------------------------------------------

class TestKeyManagement:
    def test_add_and_get_key(self, tmp_ks, alice_key):
        pub = _alice_pub(alice_key)
        tmp_ks.add_key("alice", pub)
        assert tmp_ks.get_key("alice") == pub

    def test_add_key_from_ed25519publickey(self, tmp_ks, alice_key):
        tmp_ks.add_key("alice", alice_key.public_key())
        assert tmp_ks.get_key("alice") is not None

    def test_get_missing_key_returns_none(self, tmp_ks):
        assert tmp_ks.get_key("nobody") is None

    def test_has_key(self, tmp_ks, alice_key):
        assert not tmp_ks.has_key("alice")
        tmp_ks.add_key("alice", _alice_pub(alice_key))
        assert tmp_ks.has_key("alice")

    def test_remove_key(self, tmp_ks, alice_key):
        tmp_ks.add_key("alice", _alice_pub(alice_key))
        assert tmp_ks.remove_key("alice") is True
        assert tmp_ks.has_key("alice") is False
        assert tmp_ks.remove_key("alice") is False  # already gone

    def test_list_keys(self, tmp_ks, alice_key, bob_key):
        tmp_ks.add_key("alice", _alice_pub(alice_key))
        tmp_ks.add_key("bob", _alice_pub(bob_key))
        keys = tmp_ks.list_keys()
        assert "alice" in keys
        assert "bob" in keys

    def test_invalid_key_length_rejected(self, tmp_ks):
        with pytest.raises(ValueError, match="32 bytes"):
            tmp_ks.add_key("bad", b"\x00" * 31)

    def test_auto_create_directory(self, tmp_path):
        new_dir = tmp_path / "new" / "keys"
        assert not new_dir.exists()
        SPIFKeyStore(new_dir)
        assert new_dir.exists()

    def test_missing_directory_raises_without_auto_create(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            SPIFKeyStore(tmp_path / "nonexistent", auto_create=False)

    def test_key_id_with_special_chars(self, tmp_ks, alice_key):
        key_id = "https://keys.example.com/alice.pub"
        tmp_ks.add_key(key_id, _alice_pub(alice_key))
        assert tmp_ks.has_key(key_id)
        assert tmp_ks.get_key(key_id) == _alice_pub(alice_key)


# ---------------------------------------------------------------------------
# Revocation
# ---------------------------------------------------------------------------

class TestRevocation:
    def test_revoke_and_check(self, tmp_ks, alice_key):
        tmp_ks.add_key("alice", _alice_pub(alice_key))
        assert not tmp_ks.is_revoked("alice")
        tmp_ks.revoke("alice")
        assert tmp_ks.is_revoked("alice")

    def test_revoke_persists_to_disk(self, tmp_path, alice_key):
        ks1 = SPIFKeyStore(tmp_path / "k")
        ks1.add_key("alice", _alice_pub(alice_key))
        ks1.revoke("alice", revoked_at_ms=12345)

        ks2 = SPIFKeyStore(tmp_path / "k")
        assert ks2.is_revoked("alice")
        assert ks2.revoked_keys()["alice"] == 12345

    def test_unrevoke(self, tmp_ks, alice_key):
        tmp_ks.revoke("alice")
        assert tmp_ks.unrevoke("alice") is True
        assert not tmp_ks.is_revoked("alice")
        assert tmp_ks.unrevoke("alice") is False  # not in list

    def test_revoked_keys_returns_dict(self, tmp_ks):
        tmp_ks.revoke("alice", revoked_at_ms=111)
        tmp_ks.revoke("bob", revoked_at_ms=222)
        rk = tmp_ks.revoked_keys()
        assert rk["alice"] == 111
        assert rk["bob"] == 222

    def test_corrupted_revocation_file_fails_closed(self, tmp_ks, alice_key):
        """A truncated or tampered revoked.json now raises instead of being
        silently treated as "nobody is revoked" — fails closed, not open."""
        from spif.reader import SPIFSignatureError

        signer_id = "alice@example.com"
        tmp_ks.add_key(signer_id, _alice_pub(alice_key))
        tmp_ks.revoke(signer_id)
        assert tmp_ks.is_revoked(signer_id) is True

        # Simulate corruption/truncation of the revocation file.
        tmp_ks._revocation_path.write_text("{not valid json")

        with pytest.raises(SPIFSignatureError, match="malformed"):
            tmp_ks.is_revoked(signer_id)

    def test_no_revocation_file_returns_empty(self, tmp_ks):
        assert tmp_ks.revoked_keys() == {}
        assert not tmp_ks.is_revoked("nobody")


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------

class TestVerification:
    def test_unsigned_doc_returns_false(self, tmp_ks):
        doc = _make_doc()
        assert tmp_ks.verify(doc) is False

    def test_verify_with_keystore_helper_unsigned(self, tmp_ks):
        doc = _make_doc()
        assert verify_with_keystore(doc, tmp_ks) is False

    def test_missing_key_raises(self, tmp_ks, alice_key):
        # Sign but don't add alice's key to the store
        doc = _make_doc()
        pub_b64 = base64.b64encode(
            alice_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        ).decode()
        signed_bytes = _sign_doc(doc, alice_key, pub_b64)
        # Don't add to keystore — should raise
        with pytest.raises(SPIFSignatureError, match="No public key"):
            tmp_ks.verify(signed_bytes)

    def test_revoked_signer_raises(self, tmp_ks, alice_key):
        doc = _make_doc()
        signer_id = "alice@example.com"
        tmp_ks.add_key(signer_id, _alice_pub(alice_key))
        tmp_ks.revoke(signer_id)

        signed_bytes = _sign_doc(doc, alice_key, signer_id)
        with pytest.raises(SPIFSignatureError, match="revoked"):
            tmp_ks.verify(signed_bytes)

    def test_signed_document_requires_raw_bytes(self, tmp_ks, alice_key):
        signer_id = "alice@example.com"
        signed_doc = _make_doc()
        signed_doc.signature = Signature(
            algorithm="ed25519",
            signer=signer_id,
            signature=b"\x00" * 64,
        )
        with pytest.raises(SPIFSignatureError, match="requires raw SPIF bytes"):
            tmp_ks.verify(signed_doc)


# ---------------------------------------------------------------------------
# Algorithm downgrade — keystore.verify() vs SPIFReader._verify_sig_inner()
#
# SPIFReader.strict()/require_signature=True rejects any Signature whose
# algorithm != "ed25519" (reader.py:726). SPIFKeyStore.verify() never checks
# sig.algorithm at all — it treats the signature bytes as ed25519 regardless
# of the declared algorithm. A cryptographically-valid ed25519 signature
# mislabeled with a bogus algorithm string is therefore accepted by the
# keystore path while the reader path rejects the same bytes outright.
# ---------------------------------------------------------------------------

def _sign_doc_with_algorithm(doc, private_key, signer_id: str, algorithm: str) -> bytes:
    """Same two-pass contract as _sign_doc, but with a caller-chosen algorithm
    label on the Signature chunk (checksum is recomputed over the real body
    so the resulting bytes are a well-formed, checksum-valid SPIF document)."""
    import struct
    writer = SPIFWriter()
    doc.signature = Signature(algorithm=algorithm, signer=signer_id, signature=b"\x00" * 64)
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
    body_to_sign = dummy[:sig_offset]
    real_sig = private_key.sign(body_to_sign)
    doc.signature = Signature(algorithm=algorithm, signer=signer_id, signature=real_sig)
    return writer.encode(doc)


class TestAlgorithmDowngrade:
    def test_keystore_rejects_non_ed25519_labeled_signature(
        self, tmp_ks, alice_key
    ):
        signer_id = "alice@example.com"
        tmp_ks.add_key(signer_id, _alice_pub(alice_key))

        doc = _make_doc()
        # Cryptographically real ed25519 signature, but the Signature chunk
        # declares a bogus algorithm — simulates an attacker (or a buggy
        # signer) mislabeling the algorithm while reusing a real signature.
        forged_bytes = _sign_doc_with_algorithm(doc, alice_key, signer_id, "hmac256")

        decoded = SPIFReader().decode(forged_bytes)
        assert decoded.signature.algorithm == "hmac256"

        # Reader in strict mode must reject the non-ed25519 algorithm.
        with pytest.raises(SPIFSignatureError, match="Unsupported signature algorithm"):
            SPIFReader.strict().decode(forged_bytes)

        # Keystore.verify() must reject it the same way — no more asymmetry.
        with pytest.raises(SPIFSignatureError, match="Unsupported signature algorithm"):
            tmp_ks.verify(forged_bytes)


# ---------------------------------------------------------------------------
# Key slug
# ---------------------------------------------------------------------------

class TestKeySlug:
    def test_simple_id(self):
        assert _key_slug("alice") == "alice"

    def test_url_encoded(self):
        slug = _key_slug("https://keys.example.com/alice.pub")
        # Slashes should be encoded, safe chars preserved
        assert "/" not in slug
        assert "." in slug  # dot is safe

    def test_roundtrip_via_store(self, tmp_ks, alice_key):
        key_id = "https://keys.example.com/alice?v=1"
        tmp_ks.add_key(key_id, _alice_pub(alice_key))
        assert tmp_ks.get_key(key_id) == _alice_pub(alice_key)


# ---------------------------------------------------------------------------
# Role authorization
# ---------------------------------------------------------------------------

def _dummy_sig(signer_id: str) -> Signature:
    return Signature(algorithm="ed25519", signer=signer_id, signature=b"\x00" * 64)


class TestRoleAuthorization:
    def test_unregistered_role_is_not_enforced(self, tmp_ks):
        doc = SPIFDocument(payload=[
            Node(id="n1", type="text", value="hi", confidence=Distribution(mean=0.9, var=0.01))
        ], signer_roles={"model-key": "model"}, signature=_dummy_sig("model-key"))
        tmp_ks.check_roles(doc)  # must not raise

    def test_unauthorized_signer_for_registered_role_rejected(self, tmp_ks):
        tmp_ks.authorize_role("human_reviewer", "reviewer-key-42")
        doc = SPIFDocument(payload=[
            Node(id="n1", type="text", value="hi", confidence=Distribution(mean=0.9, var=0.01))
        ], signer_roles={"model-key": "human_reviewer"}, signature=_dummy_sig("model-key"))
        with pytest.raises(SPIFSignatureError, match="not authorized"):
            tmp_ks.check_roles(doc)

    def test_authorized_signer_accepted(self, tmp_ks):
        tmp_ks.authorize_role("human_reviewer", "reviewer-key-42")
        doc = SPIFDocument(payload=[
            Node(id="n1", type="text", value="hi", confidence=Distribution(mean=0.9, var=0.01))
        ], signer_roles={"reviewer-key-42": "human_reviewer"}, signature=_dummy_sig("reviewer-key-42"))
        tmp_ks.check_roles(doc)  # must not raise

    def test_deauthorize_revokes_access(self, tmp_ks):
        tmp_ks.authorize_role("human_reviewer", "reviewer-key-42")
        assert tmp_ks.deauthorize_role("human_reviewer", "reviewer-key-42") is True
        assert tmp_ks.deauthorize_role("human_reviewer", "reviewer-key-42") is False
        doc = SPIFDocument(payload=[
            Node(id="n1", type="text", value="hi", confidence=Distribution(mean=0.9, var=0.01))
        ], signer_roles={"reviewer-key-42": "human_reviewer"}, signature=_dummy_sig("reviewer-key-42"))
        with pytest.raises(SPIFSignatureError, match="not authorized"):
            tmp_ks.check_roles(doc)

    def test_corrupted_roles_file_fails_closed(self, tmp_ks):
        doc = SPIFDocument(payload=[
            Node(id="n1", type="text", value="hi", confidence=Distribution(mean=0.9, var=0.01))
        ], signer_roles={"model-key": "model"}, signature=_dummy_sig("model-key"))
        tmp_ks._roles_path.write_text("{not valid json")
        with pytest.raises(SPIFSignatureError, match="malformed"):
            tmp_ks.check_roles(doc)

    def test_unbound_role_claim_rejected(self, tmp_ks):
        """A role claim for a signer_id that never actually signed the doc must be rejected."""
        tmp_ks.authorize_role("human_reviewer", "reviewer-key-42")
        doc = SPIFDocument(payload=[
            Node(id="n1", type="text", value="hi", confidence=Distribution(mean=0.9, var=0.01))
        ], signer_roles={"reviewer-key-42": "human_reviewer"})  # no signature at all
        with pytest.raises(SPIFSignatureError, match="declared signer"):
            tmp_ks.check_roles(doc)

    def test_roles_json_null_value_rejected(self, tmp_ks):
        tmp_ks._roles_path.write_text('{"roles": {"human_reviewer": null}}')
        doc = SPIFDocument(payload=[
            Node(id="n1", type="text", value="hi", confidence=Distribution(mean=0.9, var=0.01))
        ], signer_roles={"model-key": "human_reviewer"}, signature=_dummy_sig("model-key"))
        with pytest.raises(SPIFSignatureError, match="malformed"):
            tmp_ks.check_roles(doc)

    def test_role_claims_survive_sign_and_verify_roundtrip(self, tmp_ks, alice_key):
        signer_id = "alice@example.com"
        tmp_ks.add_key(signer_id, _alice_pub(alice_key))
        tmp_ks.authorize_role("model", signer_id)

        doc = _make_doc()
        doc.signer_roles = {signer_id: "model"}
        signed_bytes = _sign_doc(doc, alice_key, signer_id)

        decoded = SPIFReader().decode(signed_bytes)
        assert decoded.signer_roles == {signer_id: "model"}
        assert tmp_ks.verify(signed_bytes) is True
        tmp_ks.check_roles(decoded)  # must not raise

    def test_roles_chunk_after_signature_rejected(self, tmp_ks, alice_key):
        """A ROLES chunk appended after SIGNATURE (post-sign tamper) must be rejected,
        even with a recomputed checksum — it's outside the signed body."""
        import hashlib
        import struct
        from spif.format import CHUNK_ROLES, CHUNK_CHECKSUM
        from spif import SPIFChecksumError
        from spif.reader import SPIFFormatError

        signer_id = "alice@example.com"
        tmp_ks.add_key(signer_id, _alice_pub(alice_key))
        doc = _make_doc()
        signed_bytes = _sign_doc(doc, alice_key, signer_id)  # no signer_roles yet

        _chunk_struct = struct.Struct(">BI")
        roles_payload = __import__("cbor2").dumps({signer_id: "human_reviewer"})
        roles_chunk = _chunk_struct.pack(CHUNK_ROLES, len(roles_payload)) + roles_payload

        # strip the trailing CHECKSUM chunk, append ROLES after it (i.e. after SIGNATURE),
        # then recompute the checksum over the new body
        checksum_marker = signed_bytes.rfind(_chunk_struct.pack(CHUNK_CHECKSUM, 32))
        body_without_checksum = signed_bytes[:checksum_marker]
        new_body = body_without_checksum + roles_chunk
        new_checksum = hashlib.sha256(new_body).digest()
        tampered = new_body + _chunk_struct.pack(CHUNK_CHECKSUM, len(new_checksum)) + new_checksum

        with pytest.raises((SPIFFormatError, SPIFChecksumError)):
            SPIFReader().decode(tampered)
