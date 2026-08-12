"""
C2PA manifest → SPIF importer.

Converts a C2PA manifest store (the JSON string returned by
``c2pa-python``'s ``Reader.json()`` / ``c2pa-node``'s equivalent, or an
already-parsed dict of the same shape) into a SPIFDocument. This is an
*import* adapter, not an export one: it turns a
foreign provenance artifact into a SPIF node so it can travel inside a SPIF
DAG, be multi-signed alongside SPIF's own signatures, and be queried the
same way as any other SPIF-native content.

This module does not parse JUMBF/CBOR or verify COSE signatures itself —
that is exactly what ``c2pa-python`` already does correctly. Feed it that
library's manifest JSON, not raw asset bytes.

Confidence
──────────
C2PA provenance is binary (the manifest validated or it didn't) — there is
no distribution to estimate. Every imported node gets Distribution.certain(),
same as any other point-mass claim. A manifest whose own ``validation_state``
(set by ``c2pa-python``'s Reader after checking trust anchors) is
``"Invalid"`` is refused outright — a point-mass claim built on a manifest
c2pa-python itself flagged as invalid would be a false "certain". Readers on
older c2pa-python without this field, or a bare manifest with no
validation info, are still imported as-is per this adapter's documented
contract: it trusts what it's given, and validation is the caller's job.

Signature handling
───────────────────
C2PA manifests are signed with COSE (typically ES256/ES384), not raw
ed25519 — SPIF's Signature type assumes raw 64-byte ed25519 signatures.
Rather than lossily coerce one into the other, the C2PA signer identity is
recorded as metadata (Provenance.model_card) and validation stays the
C2PA library's job. Call c2pa-python's own verification before importing;
this adapter trusts the manifest dict it's given.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from ..format import NODE_FACT
from ..types import Distribution, Node, Provenance, SPIFDocument

_CERTAIN = Distribution.certain(semantics="output_stability")


def _parse_store(manifest_store: dict[str, Any] | str) -> dict[str, Any]:
    """Normalise a c2pa-python manifest store to a dict.

    Accepts either a dict or the raw JSON string ``Reader.json()`` actually
    returns.
    """
    if isinstance(manifest_store, str):
        manifest_store = json.loads(manifest_store)
    if not isinstance(manifest_store, dict):
        raise ValueError(
            f"C2PA manifest store must be a dict or JSON string, got {type(manifest_store).__name__}"
        )
    return manifest_store


def _active_manifest(manifest_store: dict[str, Any]) -> dict[str, Any]:
    """Pick the active manifest out of a parsed c2pa-python manifest store."""
    active_label = manifest_store.get("active_manifest")
    manifests = manifest_store.get("manifests", {})
    if active_label and active_label in manifests:
        return manifests[active_label]
    if manifests:
        return next(iter(manifests.values()))
    # Some readers return a single manifest dict directly, not a store.
    if "claim_generator" in manifest_store or "assertions" in manifest_store:
        return manifest_store
    raise ValueError("no manifest found in C2PA manifest store")


def _manifest_hash(manifest: dict[str, Any]) -> str:
    canonical = json.dumps(manifest, sort_keys=True, ensure_ascii=False, default=str)
    return hashlib.sha256(canonical.encode()).hexdigest()


def import_c2pa_manifest(
    manifest_store: dict[str, Any] | str,
    *,
    context_ref: str = "",
    timestamp_ms: int | None = None,
) -> SPIFDocument:
    """
    Build a SPIFDocument from a C2PA manifest store.

    Parameters
    ----------
    manifest_store :
        The JSON string returned by ``c2pa.Reader(...).json()``, or an
        already-parsed dict of the same shape (a single manifest dict is
        also accepted).
    context_ref :
        Hash of a prior SPIF document this import continues, if any.
    timestamp_ms :
        Override the timestamp instead of reading it from the manifest's
        c2pa.actions / signature_info.

    Returns
    -------
    SPIFDocument with one NODE_FACT node holding the manifest's assertions
    and a Provenance describing the C2PA claim generator.
    """
    store = _parse_store(manifest_store)
    manifest = _active_manifest(store)

    validation_state = store.get("validation_state") or manifest.get("validation_state")
    if validation_state == "Invalid":
        raise ValueError(
            "C2PA manifest failed its own validation (validation_state='Invalid'); refusing to import"
        )

    claim_generator = manifest.get("claim_generator", "unknown")
    signature_info = manifest.get("signature_info") or {}
    signer = signature_info.get("issuer") or signature_info.get("cert_serial_number") or ""

    ts_ms = timestamp_ms
    if ts_ms is None:
        raw_time = signature_info.get("time")
        ts_ms = _parse_iso_ms(raw_time) if raw_time else 0

    provenance = Provenance(
        source_model=claim_generator,
        model_version=claim_generator,
        timestamp_ms=ts_ms,
        input_hash=_manifest_hash(manifest),
        context_ref=context_ref,
        model_card=f"c2pa:{signer}" if signer else "",
    )

    fact_node = Node(
        id="c2pa_manifest",
        type=NODE_FACT,
        value={
            "title": manifest.get("title", ""),
            "format": manifest.get("format", ""),
            "assertions": manifest.get("assertions", []),
            "ingredients": manifest.get("ingredients", []),
            "validation_state": validation_state or "unknown",
        },
        confidence=_CERTAIN,
    )

    return SPIFDocument(
        payload=[fact_node],
        provenance=provenance,
        trace=[],
        trace_method="post-hoc",
    )


def _parse_iso_ms(raw_time: str) -> int:
    """Best-effort ISO-8601 -> epoch ms. Returns 0 if unparseable."""
    from datetime import datetime

    try:
        return int(datetime.fromisoformat(raw_time.replace("Z", "+00:00")).timestamp() * 1000)
    except (ValueError, AttributeError):
        return 0
