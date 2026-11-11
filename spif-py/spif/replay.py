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
        self._max_entries = max_entries
        self._seen: OrderedDict[tuple[str, str], None] = OrderedDict()

    def check(self, doc: SPIFDocument) -> None:
        """Raise SPIFReplayError if this document's signer+nonce was already seen."""
        if doc.provenance is None or not doc.provenance.nonce:
            raise SPIFReplayError("Document has no provenance.nonce — cannot check for replay")
        # The replay identity is the FULL attested signer set (single
        # signature and/or multisig entries), encoded injectively:
        # each signer id escapes the separator by doubling it, then the
        # sorted ids join on the single separator. The old plain
        # "+".join was ambiguous — one signer named "a+b" collided with
        # the two-signer set ["a", "b"], and signer ids are base64
        # public keys where "+" is a real alphabet character
        # (SPIF-REPLAY-SIGNER-COLLISION-001). Escaping keeps a lone
        # separator-free signer id as its own key, as before.
        signers: list[str] = []
        if doc.signature:
            signers.append(doc.signature.signer)
        signers.extend(s.signer for s in doc.signatures)
        signer = "+".join(
            s.replace("+", "++") for s in sorted(signers))
        key = (signer, doc.provenance.nonce)
        if key in self._seen:
            raise SPIFReplayError(
                f"Replay detected: nonce {doc.provenance.nonce!r} from signer {signer!r} already used"
            )
        self._seen[key] = None
        if len(self._seen) > self._max_entries:
            self._seen.popitem(last=False)
