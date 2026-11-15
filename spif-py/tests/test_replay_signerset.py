"""Permanent regression suite for SPIF-REPLAY-SIGNERSET-INCOMPLETE-001.

Converted from the loop probe test_loop_replay_crossbranch_probe.py
(cycle 2026-11-10-0522; preserved under the loop goal's
hidden_files/evidence/2026-11-10-0522/spif/).

The card's root cause: ReplayGuard's replay identity must encode the
FULL attested signer set -- ([doc.signature] if present) +
doc.signatures, the attested-set definition trust.py uses -- and must
encode it injectively, so no signer is dropped and no two distinct
sets collide. The control and signer-collision legs below are the
probe's, verbatim.

The probe's third leg originally expected the overlapping set
{alice, carol} to be ACCEPTED after {alice, bob} consumed the same
nonce (full-set-identity semantics). That expectation is SUPERSEDED:
Jim's decision (2026-11-15) is that per-signer nonce consumption
stands as SPIF's replay semantics -- a nonce is spent per signer, in
any set composition (PR #112, SPIF-REPLAY-SUBSET-001). Alice reusing
a one-time nonce with different company is still alice reusing it.
The leg is therefore inverted here: it asserts the overlapping set is
REJECTED, because alice's (signer, nonce) pair was already consumed.
"""
from spif import SPIFDocument, Node, Distribution, Provenance
from spif.replay import ReplayGuard, SPIFReplayError
from spif.types import Signature


def _doc(nonce, single=None, multisig=None):
    doc = SPIFDocument(
        payload=[Node(id="r", type="text", value="hi",
                      confidence=Distribution(mean=0.9, var=0.05))],
        provenance=Provenance(source_model="test", timestamp_ms=0, nonce=nonce),
    )
    if single is not None:
        doc.signature = Signature(algorithm="ed25519", signer=single, signature=b"\x00" * 64)
    if multisig is not None:
        doc.signatures = [Signature(algorithm="ed25519", signer=s, signature=b"\x00" * 64)
                          for s in multisig]
    return doc


def test_control_same_full_set_replay_raises():
    g = ReplayGuard()
    g.check(_doc("n-ctl", single="alice", multisig=["bob"]))
    try:
        g.check(_doc("n-ctl", single="alice", multisig=["bob"]))
    except SPIFReplayError:
        return
    raise AssertionError("control failed: identical full signer set replay was not flagged")


def test_crossbranch_single_plusname_vs_multisig_pair():
    g = ReplayGuard()
    g.check(_doc("n1", single="alice+bob"))        # ONE single-signature signer, id contains '+'
    g.check(_doc("n1", multisig=["alice", "bob"]))  # TWO multisig signers, same nonce


def test_both_fields_overlapping_multisig_sets_same_single_rejected():
    # Inverted from the preserved probe's leg B (see module docstring):
    # under per-signer nonce consumption (Jim's decision, 2026-11-15),
    # alice's nonce is already spent by the first presentation, so the
    # overlapping set {alice, carol} is a replay even though carol is new.
    g = ReplayGuard()
    g.check(_doc("n2", single="alice", multisig=["bob"]))    # attested set {alice, bob}
    try:
        g.check(_doc("n2", single="alice", multisig=["carol"]))  # attested set {alice, carol}
    except SPIFReplayError:
        return
    raise AssertionError("overlapping set accepted: alice's (signer, nonce) pair was already consumed")
