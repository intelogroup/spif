"""Permanent regression suite for SPIF-REPLAY-CAPACITY-001.

Converted from the loop probe test_loop_replay_capacity_probe.py
(cycle 2026-11-16-0522; preserved under the loop goal's
hidden_files/evidence/2026-11-16-0522/spif/). Probe legs are verbatim.

Invariant: ReplayGuard must not silently disable replay protection or crash
with a bare exception on a misconfigured capacity. A non-positive or
wrong-typed max_entries (from env/JSON config) must fail closed at
construction with ValueError/SPIFReplayError, never accept a replay as fresh
and never escape as bare TypeError.

Fix: ReplayGuard.__init__ validates max_entries (positive int, not
bool) and raises ValueError otherwise.
"""
from spif import SPIFDocument, Node, Distribution, Provenance
from spif.replay import ReplayGuard, SPIFReplayError
from spif.types import Signature

def _doc(nonce, signer):
    doc = SPIFDocument(payload=[Node(id="r", type="text", value="hi", confidence=Distribution(mean=0.9, var=0.05))], provenance=Provenance(source_model="test", timestamp_ms=0, nonce=nonce))
    doc.signature = Signature(algorithm="ed25519", signer=signer, signature=b"\x00"*64)
    return doc

def _assert_guard_fails_closed(bad):
    try:
        g = ReplayGuard(max_entries=bad)
    except (ValueError, SPIFReplayError):
        return
    except Exception as e:
        raise AssertionError(f"bare {type(e).__name__} at construction for max_entries={bad!r}: {e}")
    # Constructed: a replay must still be rejected with SPIFReplayError
    try:
        g.check(_doc("n1", "alice"))
        g.check(_doc("n1", "alice"))
    except SPIFReplayError:
        return
    except Exception as e:
        raise AssertionError(f"bare {type(e).__name__} on check for max_entries={bad!r}: {e}")
    raise AssertionError(f"REPLAY ACCEPTED: max_entries={bad!r} silently disabled replay protection")

def test_control_positive_capacity_replay_rejected():
    g = ReplayGuard(max_entries=3)
    g.check(_doc("n-target", "alice"))
    try:
        g.check(_doc("n-target", "alice"))
    except SPIFReplayError:
        return
    raise AssertionError("control failed")

def test_control_default_replay_rejected():
    g = ReplayGuard()
    g.check(_doc("n-target", "alice"))
    try:
        g.check(_doc("n-target", "alice"))
    except SPIFReplayError:
        return
    raise AssertionError("control failed")

def test_zero_capacity_fails_closed():
    _assert_guard_fails_closed(0)

def test_negative_one_capacity_fails_closed():
    _assert_guard_fails_closed(-1)

def test_string_capacity_fails_closed():
    _assert_guard_fails_closed("3")

def test_none_capacity_fails_closed():
    _assert_guard_fails_closed(None)

def test_false_capacity_fails_closed():
    _assert_guard_fails_closed(False)
