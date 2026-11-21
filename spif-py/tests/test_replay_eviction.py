"""Permanent regression suite for SPIF-REPLAY-EVICTION-001.

Invariant: ReplayGuard's FIFO cap silently weakens replay protection —
once the seen set turns over, an evicted (signer, nonce) pair reads as
fresh and a replayed document is accepted, with no signal to the
consumer. Jim's ruling (2026-11-21): keep the FIFO eviction, but make
every eviction observable.

Fix: ReplayGuard counts evictions on the public read-only `evictions`
property, incremented once per evicted pair in check(). The eviction
behavior itself is unchanged; the counter is the contract.
"""
from spif import SPIFDocument, Node, Distribution, Provenance
from spif.replay import ReplayGuard, SPIFReplayError
from spif.types import Signature


def _doc(nonce, signer=None, multisig=None):
    doc = SPIFDocument(payload=[Node(id="r", type="text", value="hi", confidence=Distribution(mean=0.9, var=0.05))], provenance=Provenance(source_model="test", timestamp_ms=0, nonce=nonce))
    if signer is not None:
        doc.signature = Signature(algorithm="ed25519", signer=signer, signature=b"\x00" * 64)
    if multisig is not None:
        doc.signatures = [
            Signature(algorithm="ed25519", signer=s, signature=b"\x00" * 64) for s in multisig
        ]
    return doc


def test_evictions_starts_at_zero():
    assert ReplayGuard().evictions == 0
    assert ReplayGuard(max_entries=3).evictions == 0


def test_no_eviction_at_or_below_cap():
    g = ReplayGuard(max_entries=3)
    for i in range(3):
        g.check(_doc(f"n{i}", signer="alice"))
    assert len(g._seen) == 3
    assert g.evictions == 0


def test_one_increment_per_eviction_over_cap():
    g = ReplayGuard(max_entries=3)
    for i in range(5):
        g.check(_doc(f"n{i}", signer="alice"))
    assert len(g._seen) == 3
    assert g.evictions == 2


def test_evicted_nonce_reads_as_fresh_and_counter_shows_it():
    g = ReplayGuard(max_entries=2)
    g.check(_doc("n1", signer="alice"))
    g.check(_doc("n2", signer="alice"))
    g.check(_doc("n3", signer="alice"))  # evicts (alice, n1)
    assert g.evictions == 1
    # The pinned weakening, now observable: the replay is accepted...
    g.check(_doc("n1", signer="alice"))
    # ...and accepting it evicted the next-oldest pair in turn.
    assert g.evictions == 2
    # A pair still inside the window is still rejected as a replay.
    try:
        g.check(_doc("n3", signer="alice"))
    except SPIFReplayError:
        pass
    else:
        raise AssertionError("in-window replay was not rejected")


def test_multisig_pairs_evict_and_count_individually():
    g = ReplayGuard(max_entries=2)
    g.check(_doc("n1", multisig=["alice", "bob"]))  # consumes 2 pairs, at cap
    assert g.evictions == 0
    g.check(_doc("n2", signer="alice"))  # one more pair -> one eviction
    assert len(g._seen) == 2
    assert g.evictions == 1


def test_evictions_counter_is_read_only():
    g = ReplayGuard(max_entries=1)
    try:
        g.evictions = 0
    except AttributeError:
        return
    raise AssertionError("evictions must be a read-only property")
