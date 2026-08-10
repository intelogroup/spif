"""Reference envelope for a deployer-side Article 50 integration.

This module does not implement an EU AI Act marker, a user interface, or
C2PA.  It defines the handoff contract a deployer can use to keep those
surfaces together with SPIF provenance.  The deployer remains responsible for
choosing a legally and technically appropriate marker, label, and C2PA
implementation for the content and use case.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class DeployerOutput:
    """Content plus the disclosure and provenance surfaces an integrator owns."""

    content: str
    visible_label: str
    machine_readable_mark: str
    spif_bytes: bytes
    c2pa_manifest: bytes | None = None

    def to_transport(self) -> dict[str, Any]:
        """Return a JSON-safe envelope for a response transport."""
        result: dict[str, Any] = {
            "content": self.content,
            "visible_label": self.visible_label,
            "machine_readable_mark": self.machine_readable_mark,
            "spif_b64": base64.b64encode(self.spif_bytes).decode("ascii"),
        }
        if self.c2pa_manifest is not None:
            result["c2pa_manifest_b64"] = base64.b64encode(self.c2pa_manifest).decode(
                "ascii"
            )
        return result

    @classmethod
    def from_transport(cls, value: dict[str, Any]) -> "DeployerOutput":
        """Restore an envelope after JSON or equivalent transport."""
        manifest = value.get("c2pa_manifest_b64")
        return cls(
            content=_required_text(value, "content"),
            visible_label=_required_text(value, "visible_label"),
            machine_readable_mark=_required_text(value, "machine_readable_mark"),
            spif_bytes=_decode_required(value, "spif_b64"),
            c2pa_manifest=None if manifest is None else base64.b64decode(manifest),
        )


def build_deployer_output(
    *,
    content: str,
    visible_label: str,
    machine_readable_mark: str,
    spif_bytes: bytes,
    c2pa_manifest: bytes | None = None,
) -> DeployerOutput:
    """Build an explicit, non-compliance-claiming deployer envelope.

    ``visible_label`` and ``machine_readable_mark`` are supplied by the
    deployer.  SPIF does not decide whether either value meets Article 50 for
    a particular system, medium, or audience.
    """
    _require_text(content, "content")
    _require_text(visible_label, "visible_label")
    _require_text(machine_readable_mark, "machine_readable_mark")
    if not isinstance(spif_bytes, bytes) or not spif_bytes:
        raise ValueError("spif_bytes must be non-empty bytes")
    if c2pa_manifest is not None and (
        not isinstance(c2pa_manifest, bytes) or not c2pa_manifest
    ):
        raise ValueError("c2pa_manifest must be non-empty bytes when provided")
    return DeployerOutput(
        content=content,
        visible_label=visible_label,
        machine_readable_mark=machine_readable_mark,
        spif_bytes=spif_bytes,
        c2pa_manifest=c2pa_manifest,
    )


def _require_text(value: object, name: str) -> None:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{name} must be non-empty text")


def _required_text(value: dict[str, Any], name: str) -> str:
    item = value.get(name)
    _require_text(item, name)
    return item


def _decode_required(value: dict[str, Any], name: str) -> bytes:
    encoded = value.get(name)
    if not isinstance(encoded, str) or not encoded:
        raise ValueError(f"{name} must be non-empty base64 text")
    try:
        decoded = base64.b64decode(encoded, validate=True)
    except ValueError as exc:
        raise ValueError(f"{name} must be valid base64 text") from exc
    if not decoded:
        raise ValueError(f"{name} must decode to non-empty bytes")
    return decoded
