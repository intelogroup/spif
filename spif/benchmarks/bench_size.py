"""
A2 — Size benchmark: SIF vs JSON vs CBOR vs MessagePack vs Protobuf.

Generates synthetic documents at 4 complexity levels and measures
encoded byte size for each format. Outputs a markdown table.

Protobuf column requires: pip install protobuf
"""

from __future__ import annotations
import json

import cbor2
import msgpack

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from proto_compat import to_proto_raw, HAVE_PROTOBUF
except Exception:
    HAVE_PROTOBUF = False
    def to_proto_raw(doc):
        return None

from spif import SPIFDocument, Node, TraceStep, Distribution, Provenance, SPIFWriter


# ---------------------------------------------------------------------------
# Document factories at 4 complexity levels
# ---------------------------------------------------------------------------

def _dist(mean: float, var: float = 0.01) -> Distribution:
    return Distribution(mean=mean, var=var, shape="gaussian")


def doc_minimal() -> SPIFDocument:
    """Level 1: single fact node, no optional layers."""
    return SPIFDocument(payload=[
        Node(id="n1", type="fact", value="Paris is the capital of France.",
             confidence=_dist(0.99))
    ])


def doc_medium() -> SPIFDocument:
    """Level 2: 5 nodes with refs, provenance."""
    import time as t
    nodes = [
        Node(id=f"n{i}", type="fact",
             value=f"This is fact number {i} with some representative content.",
             confidence=_dist(0.7 + i * 0.05))
        for i in range(5)
    ]
    return SPIFDocument(
        payload=nodes,
        provenance=Provenance(
            source_model="claude-sonnet-4-6",
            model_version="4.6",
            temperature=0.7,
            input_hash="a" * 64,
            timestamp_ms=int(t.time() * 1000),
        )
    )


def doc_with_trace() -> SPIFDocument:
    """Level 3: full reasoning trace (8 steps)."""
    import time as t
    steps = [
        TraceStep(
            id=f"s{i}",
            type=["evidence", "hypothesis", "inference", "conclusion"][i % 4],
            content=f"Reasoning step {i}: this is the content of this particular inference step.",
            confidence=_dist(0.6 + i * 0.04),
            deps=[f"s{i-1}"] if i > 0 else [],
            alternatives=[f"Alternative {i}a", f"Alternative {i}b"],
        )
        for i in range(8)
    ]
    return SPIFDocument(
        payload=[Node(id="conclusion", type="fact",
                      value="Final conclusion from multi-step reasoning.",
                      confidence=_dist(0.91))],
        trace=steps,
        provenance=Provenance(
            source_model="claude-sonnet-4-6",
            timestamp_ms=int(t.time() * 1000),
        )
    )


def doc_full() -> SPIFDocument:
    """Level 4: all layers — 10 nodes, 10 trace steps, semantic embedding, alternatives."""
    import time as t
    nodes = [
        Node(id=f"n{i}", type="fact",
             value=f"Content node {i}: a representative sentence of medium length.",
             confidence=_dist(0.5 + i * 0.04))
        for i in range(10)
    ]
    steps = [
        TraceStep(
            id=f"s{i}",
            type=["evidence", "hypothesis", "inference", "conclusion"][i % 4],
            content=f"Step {i} reasoning content.",
            confidence=_dist(0.6 + i * 0.03),
            deps=[f"s{i-1}"] if i > 0 else [],
        )
        for i in range(10)
    ]
    from spif import SemanticLayer, Alternative
    return SPIFDocument(
        payload=nodes,
        trace=steps,
        provenance=Provenance(
            source_model="claude-sonnet-4-6",
            timestamp_ms=int(t.time() * 1000),
            temperature=0.7,
            input_hash="b" * 64,
        ),
        semantic=SemanticLayer(
            embedding=[float(i) / 100 for i in range(128)],
        ),
        alternatives=[
            Alternative(weight=1.0, nodes=[
                Node(id="alt1", type="fact", value="Alternative conclusion A.")
            ]),
        ]
    )


# ---------------------------------------------------------------------------
# JSON equivalent (for comparison — lossy, no typed distributions)
# ---------------------------------------------------------------------------

def to_json_dict(doc: SPIFDocument) -> dict:
    """Best-effort JSON encoding using naming conventions."""
    def node_to_dict(n: Node) -> dict:
        return {
            "id": n.id, "type": n.type, "value": n.value,
            # Convention: store distribution as separate fields
            "confidence_mean": n.confidence.mean,
            "confidence_var": n.confidence.var,
            "confidence_shape": n.confidence.shape,
            "refs": [r.node_id for r in n.refs],
        }

    def step_to_dict(s: TraceStep) -> dict:
        return {
            "id": s.id, "type": s.type, "content": s.content,
            "confidence_mean": s.confidence.mean,
            "confidence_var": s.confidence.var,
            "deps": s.deps,
            "alternatives": s.alternatives,
        }

    d: dict = {"payload": [node_to_dict(n) for n in doc.payload]}
    if doc.trace:
        d["trace"] = [step_to_dict(s) for s in doc.trace]
    if doc.provenance:
        p = doc.provenance
        d["provenance"] = {
            "source_model": p.source_model,
            "temperature": p.temperature,
            "input_hash": p.input_hash,
            "timestamp_ms": p.timestamp_ms,
        }
    if doc.semantic:
        d["embedding"] = doc.semantic.embedding
    if doc.alternatives:
        d["alternatives"] = [
            {"weight": a.weight, "nodes": [node_to_dict(n) for n in a.nodes]}
            for a in doc.alternatives
        ]
    return d


def to_cbor_raw(doc: SPIFDocument) -> bytes:
    """Raw CBOR without SIF framing — baseline for overhead measurement."""
    return cbor2.dumps(to_json_dict(doc))


def to_msgpack_raw(doc: SPIFDocument) -> bytes:
    return msgpack.packb(to_json_dict(doc), use_bin_type=True)


# ---------------------------------------------------------------------------
# Benchmark runner
# ---------------------------------------------------------------------------

LEVELS = [
    ("minimal (1 node)",          doc_minimal),
    ("medium (5 nodes+prov)",     doc_medium),
    ("trace (1 node+8 steps)",    doc_with_trace),
    ("full (10+10+embed+alts)",   doc_full),
]

REPS = 1000  # for size — just measure one doc per level


def run():
    writer = SPIFWriter()

    proto_col = HAVE_PROTOBUF
    if proto_col:
        header = f"{'Document':<30} {'SIF':>8} {'JSON':>8} {'CBOR':>8} {'MsgPack':>9} {'Proto':>8} {'SIF/JSON':>10} {'SIF/CBOR':>10} {'SIF/Proto':>10}"
    else:
        header = f"{'Document':<30} {'SIF':>8} {'JSON':>8} {'CBOR':>8} {'MsgPack':>9} {'SIF/JSON':>10} {'SIF/CBOR':>10}"
    print("## Size Benchmark (bytes per document)\n")
    print(header)
    print("-" * len(header))

    for label, factory in LEVELS:
        doc = factory()
        sif_bytes  = writer.encode(doc)
        json_bytes = json.dumps(to_json_dict(doc)).encode()
        cbor_bytes = to_cbor_raw(doc)
        mp_bytes   = to_msgpack_raw(doc)
        pb_bytes   = to_proto_raw(doc)

        ratio_json  = len(sif_bytes) / len(json_bytes)
        ratio_cbor  = len(sif_bytes) / len(cbor_bytes)

        if proto_col and pb_bytes:
            ratio_proto = len(sif_bytes) / len(pb_bytes)
            print(
                f"{label:<30} {len(sif_bytes):>8} {len(json_bytes):>8} "
                f"{len(cbor_bytes):>8} {len(mp_bytes):>9} {len(pb_bytes):>8} "
                f"{ratio_json:>9.2f}x {ratio_cbor:>9.2f}x {ratio_proto:>9.2f}x"
            )
        else:
            print(
                f"{label:<30} {len(sif_bytes):>8} {len(json_bytes):>8} "
                f"{len(cbor_bytes):>8} {len(mp_bytes):>9} "
                f"{ratio_json:>9.2f}x {ratio_cbor:>9.2f}x"
            )

    print()
    print("Notes:")
    print("  SIF/JSON < 1.0x means SIF is smaller than JSON")
    print("  SIF/CBOR > 1.0x shows the overhead of SIF chunk framing + typed tags")
    print("  SIF/Proto > 1.0x: Protobuf wins on raw size; SPIF adds integrity + schema-free decode")
    print("  JSON encoding is lossy: Distribution is stored as 3 separate fields,")
    print("  NodeRef is a plain string — no type enforcement in parser.")
    if not proto_col:
        print("  Protobuf column omitted: pip install protobuf to include")


if __name__ == "__main__":
    run()
