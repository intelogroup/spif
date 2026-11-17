"""Permanent regression suite for SPIF-REPLAY-TYPE-001.

Converted from the loop probe test_loop_nonce_type_probe.py
(cycle 2026-11-15-2022; preserved under the loop goal's
hidden_files/evidence/2026-11-15-2022/spif/). Probe legs are verbatim.

Invariant: malformed (wrong-typed) nonce/signer must fail closed with SPIFReplayError,
never be accepted as a distinct fresh key and never crash with a bare TypeError.
Logical nonce 'n1' in bytes/int spelling must not bypass a seen str nonce.

Fix: ReplayGuard.check requires the nonce and every attested signer
to be str, raising SPIFReplayError otherwise.
"""
from __future__ import annotations
import pytest
from spif import SPIFDocument, Node, Distribution, Provenance
from spif.replay import ReplayGuard, SPIFReplayError
from spif.types import Signature

def _doc(nonce="n1", signer="alice"):
    doc = SPIFDocument(payload=[Node(id="r", type="text", value="hi", confidence=Distribution(mean=0.9, var=0.05))],
                       provenance=Provenance(source_model="test", timestamp_ms=0, nonce=nonce))
    if signer is not None:
        doc.signature = Signature(algorithm="ed25519", signer=signer, signature=b"\x00"*64)
    return doc

def test_control_same_str_nonce_rejected():
    g = ReplayGuard(); g.check(_doc(nonce="n1"))
    with pytest.raises(SPIFReplayError):
        g.check(_doc(nonce="n1"))

def test_bytes_nonce_not_distinct_from_str():
    g = ReplayGuard(); g.check(_doc(nonce="n1"))
    with pytest.raises(SPIFReplayError):
        g.check(_doc(nonce=b"n1"))

def test_int_nonce_fails_closed():
    g = ReplayGuard(); g.check(_doc(nonce="123"))
    with pytest.raises(SPIFReplayError):
        g.check(_doc(nonce=123))

def test_unhashable_nonce_fails_closed_not_typeerror():
    g = ReplayGuard()
    with pytest.raises(SPIFReplayError):
        g.check(_doc(nonce=["n1"]))

def test_bytes_signer_not_distinct_from_str():
    g = ReplayGuard(); g.check(_doc(nonce="n9", signer="alice"))
    with pytest.raises(SPIFReplayError):
        g.check(_doc(nonce="n9", signer=b"alice"))

def test_int_signer_fails_closed():
    g = ReplayGuard()
    with pytest.raises(SPIFReplayError):
        g.check(_doc(nonce="n10", signer=123))
