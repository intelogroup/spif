"""
SPIFRenderer — human-readable output for SPIF documents.

NOT FOR MODEL CONSUMPTION — visual representation only.
Confidence bars (████░) are lossy; do not parse them programmatically.
For model-readable output: from spfx.exporters.lossless_json import to_lossless_json
"""

from __future__ import annotations
from .format import TRACE_POSTHOC, TRACE_LIVE, TRACE_VERIFIED
from .types import SPIFDocument, Distribution, NodeRef, Node, TraceStep


_TRACE_METHOD_LABEL = {
    TRACE_POSTHOC:  "post-hoc  (model narrated after output — not a recording)",
    TRACE_LIVE:     "live      (generated simultaneously with output)",
    TRACE_VERIFIED: "verified  (derived from model internals)",
}


def _conf_bar(d: Distribution, width: int = 12) -> str:
    filled = round(d.mean * width)
    bar = "█" * filled + "░" * (width - filled)
    pct = f"{d.mean * 100:.0f}%"
    sem = f"  [{d.semantics}]" if d.semantics else ""
    return f"[{bar}] {pct}{sem}"


def _render_value(v) -> str:
    if isinstance(v, Distribution):
        return f"~{v.mean:.3f} ± {v.var:.3f} ({v.shape}, {v.semantics})"
    if isinstance(v, NodeRef):
        return f"→ {v.node_id}"
    if isinstance(v, bytes):
        return f"<binary {len(v)} bytes>"
    return str(v)


def _render_node(n: Node, indent: int = 0) -> str:
    pad = "  " * indent
    lines = [
        f"{pad}[{n.type.upper()}] id={n.id}",
        f"{pad}  value:      {_render_value(n.value)}",
        f"{pad}  confidence: {_conf_bar(n.confidence)}",
    ]
    if n.refs:
        ref_ids = ", ".join(r.node_id for r in n.refs)
        lines.append(f"{pad}  refs:       {ref_ids}")
    return "\n".join(lines)


def _render_step(s: TraceStep, indent: int = 0) -> str:
    pad = "  " * indent
    lines = [
        f"{pad}[{s.type.upper()}] id={s.id}",
        f"{pad}  content:    {_render_value(s.content)}",
        f"{pad}  confidence: {_conf_bar(s.confidence)}",
    ]
    if s.deps:
        lines.append(f"{pad}  depends on: {', '.join(s.deps)}")
    if s.alternatives:
        alts = " | ".join(_render_value(a) for a in s.alternatives[:3])
        lines.append(f"{pad}  considered: {alts}")
    return "\n".join(lines)


class SPIFRenderer:
    def render(self, doc: SPIFDocument) -> str:
        sections: list[str] = []

        sections.append("═" * 60)
        sections.append("  SPIF DOCUMENT  v0.2")
        sections.append("═" * 60)

        # Signature status (most important for audit use case — show first)
        if doc.signature:
            sections.append(
                f"\nSIGNATURE\n"
                f"  algorithm: {doc.signature.algorithm}\n"
                f"  signer:    {doc.signature.signer}\n"
                f"  status:    present (run `spfx verify` to cryptographically validate)"
            )
        else:
            sections.append("\nSIGNATURE  unsigned")

        if doc.provenance:
            p = doc.provenance
            from datetime import datetime, timezone
            ts = datetime.fromtimestamp(p.timestamp_ms / 1000, tz=timezone.utc)
            sections.append(
                f"\nPROVENANCE\n"
                f"  model:       {p.source_model}"
                + (f" ({p.model_version})" if p.model_version else "") + "\n"
                f"  created:     {ts.strftime('%Y-%m-%d %H:%M:%S UTC')}\n"
                f"  temperature: {p.temperature}\n"
                + (f"  input_hash:  {p.input_hash[:16]}..." if p.input_hash else "")
            )

        if doc.semantic:
            s = doc.semantic
            model_label = f"  model:         {s.embedding_model}" if s.embedding_model else \
                          "  model:         unspecified (v0.1 doc — cross-impl comparison unreliable)"
            sections.append(
                f"\nSEMANTIC LAYER\n"
                f"{model_label}\n"
                f"  embedding dim: {s.dim}\n"
                f"  preview:       [{', '.join(f'{x:.4f}' for x in s.embedding[:4])}"
                f"{'...' if s.dim > 4 else ''}]"
            )

        sections.append(f"\nPAYLOAD  ({len(doc.payload)} node{'s' if len(doc.payload) != 1 else ''})")
        sections.append("─" * 60)
        for n in doc.payload:
            sections.append(_render_node(n))

        if doc.trace:
            method_label = _TRACE_METHOD_LABEL.get(doc.trace_method, doc.trace_method)
            sections.append(
                f"\nREASONING TRACE  ({len(doc.trace)} step{'s' if len(doc.trace) != 1 else ''})\n"
                f"  method: {method_label}"
            )
            sections.append("─" * 60)
            # Build indent map from validated DAG
            depth: dict[str, int] = {}
            for st in doc.trace:
                depth[st.id] = 0 if not st.deps else \
                    max(depth.get(d, 0) for d in st.deps) + 1
            for st in doc.trace:
                sections.append(_render_step(st, indent=depth.get(st.id, 0)))

        if doc.alternatives:
            norm = doc.alternatives[0].normalized if doc.alternatives else True
            weight_label = "probability" if norm else "score (unnormalized)"
            sections.append(
                f"\nALTERNATIVES  ({len(doc.alternatives)} variant{'s' if len(doc.alternatives) != 1 else ''}, "
                f"weight={weight_label})"
            )
            sections.append("─" * 60)
            for i, alt in enumerate(doc.alternatives):
                sections.append(f"  variant {i+1}  weight={alt.weight:.3f}")
                for n in alt.nodes:
                    sections.append(_render_node(n, indent=2))

        if doc.delta:
            sections.append(f"\nDELTA FROM  {doc.delta.base_hash[:16]}...")

        sections.append("\n" + "═" * 60)
        return "\n".join(sections)
