"""
SIF → OpenTelemetry GenAI semantic conventions exporter.

Maps a SPIFDocument to an OTel span dict matching the GenAI semantic conventions:
https://opentelemetry.io/docs/specs/semconv/gen-ai/gen-ai-spans/

This is a LOSSY export. The following SIF features have no OTel equivalent:
  - Distribution.shape (gaussian/bimodal/beta) → dropped (only mean exported)
  - Distribution.semantics → dropped
  - TraceStep DAG dependencies → flattened to list of events
  - CHUNK_SIGNATURE (ed25519) → dropped
  - CHUNK_CHECKSUM → dropped
  - CHUNK_ALTS (weighted alternatives) → dropped
  - CHUNK_DELTA → dropped
  - CHUNK_SEMANTIC (embeddings) → dropped

What is preserved:
  - gen_ai.system (from provenance.source_model)
  - gen_ai.request.model (from provenance.source_model)
  - gen_ai.usage.input_tokens (not in SIF — not applicable)
  - span start_time (from provenance.timestamp_ms)
  - Output text (from payload nodes, as span events)
  - Temperature (from provenance.temperature)
  - Confidence mean (as custom attribute, non-standard)
"""
from __future__ import annotations
import time as _time

from ..types import SPIFDocument
from ..format import NODE_TOOL_CALL, NODE_TOOL_RESULT


def to_otel_span(doc: SPIFDocument, span_id: str | None = None) -> dict:
    """
    Convert a SPIFDocument to an OTel GenAI span dict.

    Returns a dict that matches the OTel GenAI trace export format.
    Lossy: see module docstring for what is dropped.
    """
    prov = doc.provenance
    model = prov.source_model if prov else "unknown"
    timestamp_ms = prov.timestamp_ms if prov else int(_time.time() * 1000)
    temperature = prov.temperature if prov else 1.0

    # OTel time is nanoseconds since Unix epoch
    start_time_unix_nano = timestamp_ms * 1_000_000

    # Build span attributes (OTel GenAI semantic conventions)
    attributes: dict[str, object] = {
        "gen_ai.system": _infer_system(model),
        "gen_ai.request.model": model,
        "gen_ai.request.temperature": temperature,
        "gen_ai.operation.name": "chat",  # SIF doesn't distinguish, default to chat
    }

    # Confidence: non-standard extension (OTel has no confidence field)
    if doc.payload:
        means = [n.confidence.mean for n in doc.payload if n.confidence]
        if means:
            attributes["sif.payload.confidence_mean_avg"] = sum(means) / len(means)
            attributes["sif.payload.n_nodes"] = len(doc.payload)

    # Surface all call_ids as a queryable span attribute for correlation
    call_ids = [
        n.value.get("call_id", "")
        for n in doc.payload
        if n.type in (NODE_TOOL_CALL, NODE_TOOL_RESULT)
        and isinstance(n.value, dict)
        and n.value.get("call_id")
    ]
    if call_ids:
        attributes["gen_ai.tool.call_ids"] = call_ids

    if doc.trace:
        attributes["sif.trace.method"] = doc.trace_method
        attributes["sif.trace.n_steps"] = len(doc.trace)

    # Build span events (one per payload node)
    # Tool call/result nodes get distinct event names per OTel GenAI conventions.
    # Plain content nodes use gen_ai.content.completion (unchanged behaviour).
    events = []
    for node in doc.payload:
        val = node.value if isinstance(node.value, dict) else {}
        if node.type == NODE_TOOL_CALL:
            events.append({
                "name": "gen_ai.tool.call",
                "time_unix_nano": start_time_unix_nano,
                "attributes": {
                    "gen_ai.tool.name":           val.get("name", ""),
                    "gen_ai.tool.call_id":         val.get("call_id", ""),
                    "sif.node.id":                 node.id,
                    "sif.node.confidence_mean":    node.confidence.mean if node.confidence else None,
                },
            })
        elif node.type == NODE_TOOL_RESULT:
            events.append({
                "name": "gen_ai.tool.result",
                "time_unix_nano": start_time_unix_nano,
                "attributes": {
                    "gen_ai.tool.call_id":         val.get("call_id", ""),
                    "gen_ai.tool.is_error":        bool(val.get("is_error", False)),
                    "sif.node.id":                 node.id,
                    "sif.node.type":               node.type,
                    "sif.node.confidence_mean":    node.confidence.mean if node.confidence else None,
                },
            })
        else:
            events.append({
                "name": "gen_ai.content.completion",
                "time_unix_nano": start_time_unix_nano,
                "attributes": {
                    "gen_ai.completion":           str(node.value),
                    "sif.node.id":                 node.id,
                    "sif.node.type":               node.type,
                    "sif.node.confidence_mean":    node.confidence.mean if node.confidence else None,
                },
            })

    # Trace steps → span events (flattened, DAG structure dropped)
    for step in doc.trace:
        events.append({
            "name": "sif.trace.step",  # non-standard
            "time_unix_nano": start_time_unix_nano,
            "attributes": {
                "sif.step.id": step.id,
                "sif.step.type": step.type,
                "sif.step.content": str(step.content)[:256],  # truncate long thoughts
                "sif.step.confidence_mean": step.confidence.mean if step.confidence else None,
                # deps dropped: OTel has no DAG concept
            },
        })

    span = {
        "name": f"gen_ai.{attributes['gen_ai.operation.name']}",
        "span_id": span_id or _make_span_id(),
        "start_time_unix_nano": start_time_unix_nano,
        "end_time_unix_nano": start_time_unix_nano + 1_000_000_000,  # +1s default
        "attributes": attributes,
        "events": events,
        "status": {
            "code": "ERROR" if any(
                n.type == NODE_TOOL_RESULT
                and isinstance(n.value, dict)
                and n.value.get("is_error")
                for n in doc.payload
            ) else "OK"
        },
        # NOT exported: signature, checksum, embeddings, alternatives, delta
        "_sif_export_losses": [
            "Distribution.shape (gaussian/bimodal → float only)",
            "Distribution.semantics (factual_accuracy/epistemic → dropped)",
            "TraceStep.deps (DAG edges → flattened to event list)",
            "CHUNK_SIGNATURE (ed25519 → not in OTel spec)",
            "CHUNK_CHECKSUM (SHA-256 → not in OTel spec)",
            "CHUNK_ALTS (alternatives → dropped)",
            "CHUNK_SEMANTIC (embeddings → dropped)",
            "CHUNK_DELTA (version chain → dropped)",
        ],
    }

    return span


def _infer_system(model: str) -> str:
    """Map model name to OTel gen_ai.system value."""
    m = model.lower()
    if "claude" in m or "anthropic" in m:
        return "anthropic"
    if "gpt" in m or "openai" in m:
        return "openai"
    if "gemini" in m or "google" in m:
        return "google_ai_studio"
    if "llama" in m or "meta" in m:
        return "meta"
    return "custom"


def _make_span_id() -> str:
    import os
    return os.urandom(8).hex()
