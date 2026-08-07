"""Roadmap item: measure tamper-detection latency for integrity validation.

Ensures corrupted/tampered documents are rejected fast (no expensive retry
loops, no scanning) and that detection latency stays roughly flat regardless
of document size — a slow tamper check on large docs would itself be a DoS
surface.
"""

import time

from spfx import SPIFDocument, Node, TraceStep, SPIFWriter, SPIFReader, SPIFChecksumError
from spfx.format import MAGIC


def _doc(n_nodes: int) -> SPIFDocument:
    nodes = [Node(id=f"n{i}", type="fact", value="x" * 32) for i in range(n_nodes)]
    trace = [TraceStep(id="s0", type="evidence", content="root")]
    return SPIFDocument(payload=nodes, trace=trace)


def _tamper(data: bytes) -> bytes:
    mutated = bytearray(data)
    # Flip a byte inside the PAYLOAD chunk body, past the preamble/header.
    idx = len(MAGIC) + 2 + 40
    mutated[idx] ^= 0xFF
    return bytes(mutated)


def _time_tamper_detection(data: bytes, reps: int = 20) -> float:
    tampered = _tamper(data)
    reader = SPIFReader()
    start = time.perf_counter()
    for _ in range(reps):
        try:
            reader.decode(tampered)
        except SPIFChecksumError:
            pass
    return (time.perf_counter() - start) / reps


def test_tampered_document_rejected_via_checksum():
    data = SPIFWriter().encode(_doc(5))
    tampered = _tamper(data)
    try:
        SPIFReader().decode(tampered)
        assert False, "expected SPIFChecksumError"
    except SPIFChecksumError:
        pass


def test_tamper_detection_latency_stays_bounded_small_doc():
    data = SPIFWriter().encode(_doc(5))
    latency = _time_tamper_detection(data)
    # Detection must short-circuit at checksum stage, well under 5ms even on slow CI.
    assert latency < 0.005, f"tamper detection too slow for small doc: {latency*1000:.3f}ms"


def test_tamper_detection_latency_scales_with_size_not_blowup():
    small = _time_tamper_detection(_write_of(50))
    large = _time_tamper_detection(_write_of(2000))
    ratio = large / small if small > 0 else 0
    # 40x the nodes; checksum is O(N) over bytes so some growth is expected,
    # but detection must not blow up superlinearly (e.g. from a naive retry/scan).
    assert ratio < 80, f"tamper detection latency grew {ratio:.1f}x for 40x doc size"


def _write_of(n_nodes: int) -> bytes:
    return SPIFWriter().encode(_doc(n_nodes))
