"""Replay protection — nonce tracking for verifiers (v1.1+).

SPIF signing itself is stateless (same input -> same signature), so replay
rejection is a verifier-side concern: track (signer, nonce) pairs already
seen and reject repeats. This is the same pattern as JWT `jti` blacklisting.
"""
from __future__ import annotations

from .types import SPIFDocument


class SPIFReplayError(Exception):
    """Raised when a document's (signer, nonce) pair has already been seen."""


class ReplayGuard:
    # ponytail: in-memory set, per-process only. Swap for a shared store
    # (Redis/DB) if verification happens across multiple processes/replicas.
    def __init__(self):
        self._seen: set[tuple[str, str]] = set()

    def check(self, doc: SPIFDocument) -> None:
        """Raise SPIFReplayError if this document's signer+nonce was already seen."""
        if doc.provenance is None or not doc.provenance.nonce:
            raise SPIFReplayError("Document has no provenance.nonce — cannot check for replay")
        signer = doc.signature.signer if doc.signature else ""
        key = (signer, doc.provenance.nonce)
        if key in self._seen:
            raise SPIFReplayError(
                f"Replay detected: nonce {doc.provenance.nonce!r} from signer {signer!r} already used"
            )
        self._seen.add(key)
