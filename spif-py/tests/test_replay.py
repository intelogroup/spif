"""
Tests for spif.replay.ReplayGuard — nonce-based replay protection.

Prior to this file, no test imported spif.replay at all; existing "replay"
references elsewhere in tests/ are unrelated reimplementations of a toy
nonce set, not this module.
"""

from __future__ import annotations

import pytest

from spif import SPIFDocument, Node, Distribution, Provenance
from spif.replay import ReplayGuard, SPIFReplayError
from spif.types import Signature


def _doc(nonce: str = "n1", signer=None, multisig=None) -> SPIFDocument:
    doc = SPIFDocument(
        payload=[Node(id="r", type="text", value="hi", confidence=Distribution(mean=0.9, var=0.05))],
        provenance=Provenance(source_model="test", timestamp_ms=0, nonce=nonce),
    )
    if signer is not None:
        doc.signature = Signature(algorithm="ed25519", signer=signer, signature=b"\x00" * 64)
    if multisig is not None:
        doc.signatures = [
            Signature(algorithm="ed25519", signer=s, signature=b"\x00" * 64) for s in multisig
        ]
    return doc


class TestReplayGuardBasic:
    def test_first_use_passes(self):
        ReplayGuard().check(_doc(nonce="abc", signer="alice"))

    def test_repeat_nonce_same_signer_raises(self):
        guard = ReplayGuard()
        doc = _doc(nonce="abc", signer="alice")
        guard.check(doc)
        with pytest.raises(SPIFReplayError, match="Replay detected"):
            guard.check(doc)

    def test_same_nonce_different_signer_is_not_a_replay(self):
        guard = ReplayGuard()
        guard.check(_doc(nonce="abc", signer="alice"))
        guard.check(_doc(nonce="abc", signer="bob"))  # distinct (signer, nonce) key

    def test_missing_nonce_raises(self):
        doc = _doc(nonce="", signer="alice")
        with pytest.raises(SPIFReplayError, match="no provenance.nonce"):
            ReplayGuard().check(doc)

    def test_missing_provenance_raises(self):
        doc = SPIFDocument(payload=[Node(id="r", type="text", value="hi",
                                          confidence=Distribution(mean=0.9, var=0.05))])
        with pytest.raises(SPIFReplayError, match="no provenance.nonce"):
            ReplayGuard().check(doc)


class TestReplayGuardMultisig:
    def test_distinct_multisig_signers_same_nonce_both_accepted(self):
        guard = ReplayGuard()
        doc_alice = _doc(nonce="n1", multisig=["alice"])
        doc_bob = _doc(nonce="n1", multisig=["bob"])

        guard.check(doc_alice)
        guard.check(doc_bob)  # distinct signer set -> distinct key, not a replay

    def test_multisig_signer_identity_reflected_in_seen_set(self):
        guard = ReplayGuard()
        guard.check(_doc(nonce="n1", multisig=["alice"]))
        assert ("alice", "n1") in guard._seen
        assert ("", "n1") not in guard._seen

    def test_repeat_same_multisig_set_and_nonce_raises(self):
        guard = ReplayGuard()
        doc = _doc(nonce="n1", multisig=["alice", "bob"])
        guard.check(doc)
        with pytest.raises(SPIFReplayError):
            guard.check(_doc(nonce="n1", multisig=["bob", "alice"]))  # order-independent


class TestReplayGuardBoundedGrowth:
    def test_seen_set_is_capped_with_fifo_eviction(self):
        guard = ReplayGuard(max_entries=10)
        for i in range(1000):
            guard.check(_doc(nonce=f"n{i}", signer="alice"))
        assert len(guard._seen) == 10
        # oldest entries evicted -> re-using an old nonce is no longer flagged as replay
        guard.check(_doc(nonce="n0", signer="alice"))
