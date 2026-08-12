"""Roadmap item: benchmark DAG cycle-detection to confirm O(N) behavior (DoS resistance).

A quadratic (or worse) cycle-detection algorithm would let an attacker submit a
large-but-acyclic trace/payload graph and burn CPU disproportionate to N. This
asserts wall-clock growth stays roughly linear across increasing N, not O(N^2).
"""

import time

from spif import SPIFDocument, Node, NodeRef, TraceStep, SPIFWriter, SPIFReader


def _linear_trace_doc(n: int) -> bytes:
    steps = [TraceStep(id="s0", type="evidence", content="root")]
    for i in range(1, n):
        steps.append(TraceStep(id=f"s{i}", type="inference", content="x", deps=[f"s{i-1}"]))
    doc = SPIFDocument(payload=[Node(id="n1", type="fact", value="v")], trace=steps)
    return SPIFWriter().encode(doc)


def _wide_noderef_doc(n: int) -> bytes:
    nodes = [Node(id="root", type="fact", value="v")]
    for i in range(1, n):
        nodes.append(Node(id=f"n{i}", type="fact", value="v", refs=[NodeRef(node_id="root")]))
    doc = SPIFDocument(payload=nodes)
    return SPIFWriter().encode(doc)


def _time_decode(data: bytes, reps: int = 5) -> float:
    reader = SPIFReader()
    start = time.perf_counter()
    for _ in range(reps):
        reader.decode(data)
    return (time.perf_counter() - start) / reps


def test_dag_cycle_detection_scales_linearly_trace():
    small = _time_decode(_linear_trace_doc(500))
    large = _time_decode(_linear_trace_doc(4000))
    # 8x the nodes; allow generous slack over ideal 8x but reject quadratic-ish 64x blowup.
    ratio = large / small if small > 0 else 0
    assert ratio < 20, f"trace DAG validation looks super-linear: {ratio:.1f}x time for 8x nodes"


def test_dag_cycle_detection_scales_linearly_noderefs():
    small = _time_decode(_wide_noderef_doc(500))
    large = _time_decode(_wide_noderef_doc(4000))
    ratio = large / small if small > 0 else 0
    assert ratio < 20, f"noderef DAG validation looks super-linear: {ratio:.1f}x time for 8x nodes"


def test_large_acyclic_trace_decodes_without_error():
    data = _linear_trace_doc(5000)
    restored = SPIFReader().decode(data)
    assert len(restored.trace) == 5000
