"""Permanent regression suite for SPIF-REPLAY-EMPTY-SIGNER-001.

Converted from the loop probe test_loop_empty_signer_probe.py
(cycle 2026-11-15-1722; preserved under the loop goal's
hidden_files/evidence/2026-11-15-1722/spif/). Probe legs are verbatim.

Invariant: ReplayGuard's replay identity must be injective over attestation
states -- a document with NO attested signer and a document whose attested
signer is the empty string are different provenance claims and must not
share a (signer, nonce) replay key. (Cousin of SPIF-REPLAY-SIGNER-COLLISION-001:
tuple keys are injective over signer strings, but the "" sentinel for
signerless documents conflates the two states.)

Fix: the signerless member keys under a None sentinel in
ReplayGuard.check, so an attested "" signer keeps its own ("", nonce)
key. First-use acceptance of both states is pinned by the control legs
below; only the key collision is removed.
"""
from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from spif import SPIFDocument, Node, Distribution, Provenance
from spif.crypto import sign_document
from spif.reader import SPIFReader
from spif.replay import ReplayGuard, SPIFReplayError
from spif.types import Signature


def _doc(nonce, signer="ABSENT", multisig=None):
    doc = SPIFDocument(
        payload=[Node(id="r", type="text", value="hi",
                      confidence=Distribution(mean=0.9, var=0.05))],
        provenance=Provenance(source_model="test", timestamp_ms=0, nonce=nonce),
    )
    if signer != "ABSENT":
        doc.signature = Signature(algorithm="ed25519", signer=signer, signature=b"\x00" * 64)
    if multisig is not None:
        doc.signatures = [Signature(algorithm="ed25519", signer=s, signature=b"\x00" * 64)
                          for s in multisig]
    return doc


def test_control_unsigned_replay_rejected():
    g = ReplayGuard()
    g.check(_doc("n-ctl-u"))
    with pytest.raises(SPIFReplayError):
        g.check(_doc("n-ctl-u"))


def test_control_empty_signer_replay_rejected():
    g = ReplayGuard()
    g.check(_doc("n-ctl-e", signer=""))
    with pytest.raises(SPIFReplayError):
        g.check(_doc("n-ctl-e", signer=""))


def test_collision_unsigned_then_empty_signer():
    g = ReplayGuard()
    g.check(_doc("n-col-a"))                    # signerless consumes ("", n)
    try:
        g.check(_doc("n-col-a", signer=""))     # distinct attestation state
    except SPIFReplayError:
        raise AssertionError(
            "COLLISION A: empty-signer doc rejected as replay of a signerless doc — "
            "distinct attestation states share the ('', nonce) replay key")


def test_collision_empty_signer_then_unsigned():
    g = ReplayGuard()
    g.check(_doc("n-col-b", signer=""))
    try:
        g.check(_doc("n-col-b"))
    except SPIFReplayError:
        raise AssertionError(
            "COLLISION B: signerless doc rejected as replay of an empty-signer doc — "
            "distinct attestation states share the ('', nonce) replay key")


def test_wire_empty_signer_envelope_does_not_verify():
    key = Ed25519PrivateKey.generate()
    doc = SPIFDocument(
        payload=[Node(id="r", type="text", value="hi",
                      confidence=Distribution(mean=0.9, var=0.05))],
        provenance=Provenance(source_model="test", timestamp_ms=0, nonce="n-wire"),
    )
    data = sign_document(doc, key, signer_id="")
    parsed = SPIFReader(require_signature=False).decode(data)
    assert parsed.signature is not None and parsed.signature.signer == ""
    try:
        verified = SPIFReader().verify_signature(data)
    except Exception:
        verified = False  # raising on an unverifiable signer is fail-closed
    assert verified is False, "empty-signer envelope verified under require-signature self-check"
