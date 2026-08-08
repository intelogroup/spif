"""Shared helpers used identically by every vendor adapter."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from ..types import Provenance


def input_hash(messages: list[dict[str, Any]]) -> str:
    """Stable SHA-256 of the messages list (canonical JSON)."""
    canonical = json.dumps(messages, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(canonical.encode()).hexdigest()


def build_provenance(
    model: str,
    messages: list[dict[str, Any]],
    temperature: float,
    timestamp_ms: int,
    context_ref: str,
) -> Provenance:
    return Provenance(
        source_model=model,
        model_version=model,
        temperature=temperature,
        input_hash=input_hash(messages),
        context_ref=context_ref,
        timestamp_ms=timestamp_ms,
    )
