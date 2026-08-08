"""
A3 — Expressiveness comparison: what SIF expresses that JSON cannot enforce.

Outputs a structured comparison showing where JSON requires conventions
that a parser cannot enforce without schema knowledge.
"""

from __future__ import annotations
import json

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from spif import (
    SPIFDocument, Node, NodeRef, TraceStep, Distribution,
    SPIFWriter, SPIFReader,
)


# ---------------------------------------------------------------------------
# The same document in SIF and JSON — side by side
# ---------------------------------------------------------------------------

def sif_document() -> SPIFDocument:
    return SPIFDocument(
        payload=[
            Node(
                id="claim",
                type="fact",
                value="Remote work reduces urban office occupancy.",
                confidence=Distribution(mean=0.62, var=0.09, shape="bimodal", p5=0.3, p95=0.88),
            ),
            Node(
                id="evidence",
                type="fact",
                value="JLL 2024: average office occupancy at 54% in major US cities.",
                confidence=Distribution(mean=0.91, var=0.02, shape="gaussian"),
                refs=[NodeRef("claim")],
            ),
        ],
        trace=[
            TraceStep(
                id="s1", type="evidence",
                content="User asked about remote work impact on offices",
                confidence=Distribution(mean=1.0, var=0.0, shape="point"),
            ),
            TraceStep(
                id="s2", type="inference",
                content="Occupancy data supports negative impact claim",
                confidence=Distribution(mean=0.62, var=0.09, shape="bimodal"),
                deps=["s1"],
                alternatives=["Impact is neutral", "Impact is positive long-term"],
            ),
        ]
    )


def json_equivalent(doc: SPIFDocument) -> dict:
    """
    Best-effort JSON. Shows what gets lost:
    - Distribution becomes 3 fields with no type marker — parser can't distinguish
      a distribution from any other dict with 'mean'/'var' keys
    - NodeRef becomes a plain string — parser can't tell it's a reference, not a value
    - DAG deps exist but there's no spec — tooling must know the convention
    - No checksum — integrity is optional convention
    - No magic bytes — format identity is by file extension only
    """
    def serialize_dist(d: Distribution) -> dict:
        # Convention, not type: must be documented separately
        out = {"conf_mean": d.mean, "conf_var": d.var, "conf_shape": d.shape}
        if d.p5 is not None:
            out["conf_p5"] = d.p5
        if d.p95 is not None:
            out["conf_p95"] = d.p95
        return out

    def serialize_node(n: Node) -> dict:
        d = {"id": n.id, "type": n.type, "value": n.value}
        d.update(serialize_dist(n.confidence))
        # NodeRef stored as plain string — parser sees "claim", not NodeRef("claim")
        d["refs"] = [r.node_id for r in n.refs]
        return d

    def serialize_step(s: TraceStep) -> dict:
        d = {"id": s.id, "type": s.type, "content": s.content}
        d.update(serialize_dist(s.confidence))
        d["deps"] = s.deps
        d["alternatives"] = s.alternatives
        return d

    return {
        # No magic bytes. No version. No checksum.
        "payload": [serialize_node(n) for n in doc.payload],
        "trace": [serialize_step(s) for s in doc.trace],
    }


# ---------------------------------------------------------------------------
# Loss analysis
# ---------------------------------------------------------------------------

LOSSES = [
    {
        "feature": "Distribution as typed value",
        "sif": 'CBOR tag(1000): {"mean": 0.62, "var": 0.09, "shape": "bimodal"}',
        "json": '{"conf_mean": 0.62, "conf_var": 0.09, "conf_shape": "bimodal"}',
        "lost": (
            "Parser sees a dict, not a Distribution. "
            "A dict with 'mean' and 'var' is indistinguishable from any other dict. "
            "Field naming is a convention — 'confidence', 'conf_mean', 'prob' all seen in the wild. "
            "Bimodal vs Gaussian requires schema knowledge to interpret."
        ),
    },
    {
        "feature": "NodeRef (typed graph edge)",
        "sif": 'CBOR tag(1001): "claim"   → parser sees NodeRef, not str',
        "json": '"refs": ["claim"]         → parser sees list of strings',
        "lost": (
            "Parser cannot distinguish a reference string from a value string. "
            "Requires schema to know that 'refs' contains IDs. "
            "Dangling references (pointing to non-existent nodes) silently accepted."
        ),
    },
    {
        "feature": "Checksum integrity",
        "sif": "SHA-256 of all bytes, as terminal chunk — enforced by spec",
        "json": "No equivalent — must add 'checksum' field as convention, or use external .sig file",
        "lost": (
            "Integrity is optional in JSON. "
            "Tampered or truncated files parse silently. "
            "No way to detect partial writes or storage corruption."
        ),
    },
    {
        "feature": "Magic bytes + versioning",
        "sif": r'\x89SIF\r\n\x1a\n + 1-byte version — reader rejects wrong format instantly',
        "json": "File extension only — no format identity in the bytes",
        "lost": (
            "A JSON file renamed to .sif would parse without error. "
            "Version field must be a convention in the JSON body. "
            "No canonical way to signal format incompatibility."
        ),
    },
    {
        "feature": "Typed chunk structure",
        "sif": "PROVENANCE chunk, TRACE chunk, PAYLOAD chunk — each typed and skippable",
        "json": "Flat top-level dict with 'payload', 'trace', 'provenance' keys",
        "lost": (
            "In JSON, adding a new layer requires all parsers to update. "
            "Unknown keys silently ignored (or crash strict parsers). "
            "SIF: unknown chunk type → skip by length. Forward compatible by design."
        ),
    },
]


def run():
    doc = sif_document()
    writer = SPIFWriter()
    sif_data = writer.encode(doc)
    json_data = json_equivalent(doc)
    json_str = json.dumps(json_data, indent=2)

    print("=" * 70)
    print("EXPRESSIVENESS COMPARISON: SIF vs JSON")
    print("=" * 70)
    print(f"\nSIF encoded size:  {len(sif_data):,} bytes")
    print(f"JSON encoded size: {len(json_str.encode()):,} bytes\n")

    print("WHAT JSON LOSES (per feature):")
    print("-" * 70)
    for loss in LOSSES:
        print(f"\n[{loss['feature']}]")
        print(f"  SIF:  {loss['sif']}")
        print(f"  JSON: {loss['json']}")
        print(f"  Lost: {loss['lost']}")

    print("\n" + "=" * 70)
    print("KEY FINDING:")
    print(
        "  JSON can store the same data but cannot enforce types at the format level.\n"
        "  A generic JSON parser reading a SIF-equivalent JSON doc does not know:\n"
        "    - which fields are Distributions vs plain dicts\n"
        "    - which strings are NodeRefs vs values\n"
        "    - whether the document is complete or corrupted\n"
        "    - which version of the schema to apply\n"
        "\n"
        "  SIF encodes all of this in the binary structure, not the application schema.\n"
        "  A generic SIF parser knows all of the above without any external schema."
    )
    print("=" * 70)

    # Also demonstrate: a parser that reads SIF gets typed objects automatically
    print("\nDEMO: SIF reader automatically resolves types")
    restored = SPIFReader().decode(sif_data)
    n = restored.payload[0]
    print(f"  payload[0].confidence type: {type(n.confidence).__name__}")
    print(f"  payload[0].confidence.shape: {n.confidence.shape}")
    print(f"  payload[1].refs[0] type: {type(restored.payload[1].refs[0]).__name__}")
    print(f"  payload[1].refs[0].node_id: {restored.payload[1].refs[0].node_id}")
    print("\n  JSON parser would return: dict, dict, str, str — no type information.")


if __name__ == "__main__":
    run()
