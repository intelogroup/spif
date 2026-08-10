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


class TestReplayGuardMultisigBug:
    """
    ReplayGuard.check() only reads doc.signature.signer, ignoring
    doc.signatures (the multisig list) entirely. A multisig-only document
    (doc.signature is None) is tracked under the empty-string signer for
    every distinct multisig signer set, so two genuinely different signers'
    first-ever nonces collide under key ("", nonce) and the second is
    wrongly treated as a replay of the first.
    """

    def test_distinct_multisig_signers_collide_under_empty_signer_key(self):
        guard = ReplayGuard()
        doc_alice = _doc(nonce="n1", multisig=["alice"])
        doc_bob = _doc(nonce="n1", multisig=["bob"])

        guard.check(doc_alice)  # tracked as ("", "n1")
        # BUG: bob's distinct multisig signature is rejected as a replay of
        # alice's, purely because both are multisig-only and share a nonce.
        with pytest.raises(SPIFReplayError):
            guard.check(doc_bob)

    def test_multisig_signer_identity_not_reflected_in_seen_set(self):
        guard = ReplayGuard()
        guard.check(_doc(nonce="n1", multisig=["alice"]))
        # BUG: internal state has no trace of "alice" — only the empty string.
        assert ("", "n1") in guard._seen
        assert not any("alice" in key for key in guard._seen)


class TestReplayGuardUnboundedGrowth:
    def test_seen_set_grows_without_bound_or_eviction(self):
        # ponytail: documents the missing TTL/eviction, not a full DoS repro.
        guard = ReplayGuard()
        for i in range(1000):
            guard.check(_doc(nonce=f"n{i}", signer="alice"))
        assert len(guard._seen) == 1000  # no cap, no eviction — grows linearly forever
