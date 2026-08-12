"""
Tests for spif.crypto key-ceremony helpers: rotate_key() + verify_rotation().
"""

from __future__ import annotations

import base64

import pytest

from spif.crypto import derive_key_from_mnemonic, rotate_key, verify_rotation


@pytest.fixture
def old_key():
    return derive_key_from_mnemonic("old signing key", passphrase="p1")


@pytest.fixture
def new_key():
    return derive_key_from_mnemonic("new signing key", passphrase="p2")


class TestRotateKeyVerification:
    def test_rotation_record_has_counter_signature_from_new_key(self, old_key, new_key):
        """rotate_key() now has new_key counter-sign the rotation record, proving
        the new key consents to receiving trust — not just old_key's word for it."""
        record = rotate_key(old_key, new_key, "old@example.com", "new@example.com")
        assert set(record.keys()) == {
            "old_signer", "superseded_by", "timestamp_ms", "proof", "new_key_proof",
        }

    def test_verify_rotation_accepts_genuine_record(self, old_key, new_key):
        record = rotate_key(old_key, new_key, "old@example.com", "new@example.com")
        assert verify_rotation(record, old_key.public_key(), new_key.public_key()) is True

    def test_verify_rotation_rejects_forged_old_proof(self, old_key, new_key):
        record = rotate_key(old_key, new_key, "old@example.com", "new@example.com")
        forged = dict(record)
        forged["proof"] = base64.b64encode(b"\x00" * 64).decode("ascii")
        assert verify_rotation(forged, old_key.public_key(), new_key.public_key()) is False

    def test_verify_rotation_rejects_forged_new_key_proof(self, old_key, new_key):
        """The attacker-named-signer scenario: old_key is genuine but
        new_key_proof is forged (attacker doesn't hold new_signer's key) —
        verify_rotation must catch this, not just the old-side proof."""
        record = rotate_key(old_key, new_key, "old@example.com", "attacker@example.com")
        forged = dict(record)
        forged["new_key_proof"] = base64.b64encode(b"\x00" * 64).decode("ascii")
        assert verify_rotation(forged, old_key.public_key(), new_key.public_key()) is False

    def test_verify_rotation_rejects_tampered_superseded_by(self, old_key, new_key):
        """Changing superseded_by after signing invalidates both signatures,
        since the payload they signed is bound to the exact field values."""
        record = rotate_key(old_key, new_key, "old@example.com", "new@example.com")
        tampered = dict(record)
        tampered["superseded_by"] = "attacker@example.com"
        assert verify_rotation(tampered, old_key.public_key(), new_key.public_key()) is False
