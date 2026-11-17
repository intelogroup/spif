"""Replay protection — nonce tracking for verifiers (v1.1+).

SPIF signing itself is stateless (same input -> same signature), so replay
rejection is a verifier-side concern: track (signer, nonce) pairs already
seen and reject repeats. This is the same pattern as JWT `jti` blacklisting.
"""
from __future__ import annotations

from collections import OrderedDict

from .types import SPIFDocument


class SPIFReplayError(Exception):
    """Raised when a document's (signer, nonce) pair has already been seen."""


class ReplayGuard:
    # ponytail: in-memory, per-process only, FIFO-capped at max_entries.
    # Swap for a shared store (Redis/DB) with a real TTL if verification
    # happens across multiple processes/replicas or needs time-based expiry.
    def __init__(self, max_entries: int = 100_000):
        # Capacity typically comes from deployer config (env/JSON), where
        # a stray 0, "3" or null must not silently disable replay
        # protection or crash later with a bare TypeError/KeyError
        # (SPIF-REPLAY-CAPACITY-001): validate at construction.
        if (
            isinstance(max_entries, bool)
            or not isinstance(max_entries, int)
            or max_entries < 1
        ):
            raise ValueError(
                f"max_entries must be a positive int, got {max_entries!r}"
            )
        self._max_entries = max_entries
        self._seen: OrderedDict[tuple[str | None, str], None] = OrderedDict()

    def check(self, doc: SPIFDocument) -> None:
        """Raise SPIFReplayError if this document's signer+nonce was already seen."""
        if doc.provenance is None or not doc.provenance.nonce:
            raise SPIFReplayError("Document has no provenance.nonce — cannot check for replay")
        # The replay identity is PER SIGNER: every attested signer
        # (single signature and/or multisig entries) consumes the nonce
        # individually, and a presentation is a replay if ANY member
        # signer's (signer, nonce) pair was already seen. Keying by the
        # full signer SET instead let a genuine multisig envelope be
        # replayed by shedding a co-signer — the stripped variant keyed
        # differently even though the remaining signer had already
        # consumed the nonce (SPIF-REPLAY-SUBSET-001). Tuple keys are
        # injective by construction, so the old joined-string escaping
        # (SPIF-REPLAY-SIGNER-COLLISION-001) is unnecessary: a signer
        # named "a+b" is its own key and never collides with the pair
        # ("a", ...), ("b", ...). Disjoint signer sets sharing a nonce
        # still both pass — their member pairs differ. A document with
        # no attested signer keys under a None sentinel, NOT "": an
        # attested empty-string signer is a distinct provenance claim
        # and must not share the signerless key — keying both under ""
        # let either state burn the other's nonce
        # (SPIF-REPLAY-EMPTY-SIGNER-001). Signerless replay behavior is
        # otherwise unchanged: first use passes, a repeat raises.
        # Nonce and signer ids must be str: a wrong-typed spelling
        # (b"n1", 123) is a distinct Python dict key from its string
        # form and would be accepted as fresh, and an unhashable nonce
        # crashed with a bare TypeError (SPIF-REPLAY-TYPE-001) — so
        # malformed shapes fail closed here instead.
        nonce = doc.provenance.nonce
        if not isinstance(nonce, str):
            raise SPIFReplayError(
                f"provenance.nonce must be a string, got "
                f"{type(nonce).__name__} — cannot check for replay"
            )
        signers: list[str] = []
        if doc.signature:
            signers.append(doc.signature.signer)
        signers.extend(s.signer for s in doc.signatures)
        for signer in signers:
            if not isinstance(signer, str):
                raise SPIFReplayError(
                    f"signer id must be a string, got "
                    f"{type(signer).__name__} — cannot check for replay"
                )
        members: list[str | None] = sorted(set(signers)) or [None]
        for signer in members:
            if (signer, nonce) in self._seen:
                raise SPIFReplayError(
                    f"Replay detected: nonce {nonce!r} from signer {signer!r} already used"
                )
        for signer in members:
            self._seen[(signer, nonce)] = None
        while len(self._seen) > self._max_entries:
            self._seen.popitem(last=False)
