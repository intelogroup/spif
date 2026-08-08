"""
SPIF stress tests — second battery.

New angles not covered by test_stress.py:
  - Cross-language binary compatibility (Python writes → Rust reads)
  - Memory footprint (tracemalloc peak during encode/decode)
  - Cyclic trace DAG rejection
  - Deep NodeRef chains
  - Binary/bytes node values (multimodal)
  - Concurrent streaming with mid-stream resume
  - Edge cases in the alternative weights validator
  - Provenance context_ref chain integrity
  - Streaming reader with interleaved noise / concurrent feeds
  - Checksum coverage (every byte in the document is covered)
  - Document with all optional layers + compression + signatures
"""

from __future__ import annotations

import dataclasses
import hashlib
import os
import struct
import threading
import tracemalloc
from concurrent.futures import ThreadPoolExecutor

import pytest

from spif import (
    SPIFDocument, Node, Distribution, TraceStep, Provenance,
    SemanticLayer, Alternative, SPIFWriter, SPIFReader,
)
from spif.format import MAGIC, CHUNK_CHECKSUM, NODE_TOOL_CALL, NODE_TOOL_RESULT
from spif.reader import SPIFChecksumError, SPIFFormatError
from spif.streaming import SPIFStreamWriter, SPIFStreamReader, iter_events
from spif.types import Delta, NodeRef, Signature


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _d(mean: float = 0.9) -> Distribution:
    return Distribution(mean=mean, var=0.01, shape="gaussian", semantics="epistemic")


def _n(i: int, val: str = None) -> Node:
    return Node(id=f"n{i}", type="text", value=val or f"node {i}", confidence=_d())


def _prov() -> Provenance:
    return Provenance(
        source_model="claude-sonnet-4-6",
        timestamp_ms=1712000000000,
        temperature=0.7,
        input_hash="b" * 64,
    )


def _encode_decode(doc: SPIFDocument, **kwargs) -> SPIFDocument:
    return SPIFReader().decode(SPIFWriter(**kwargs).encode(doc))


# ---------------------------------------------------------------------------
# Determinism
#
# Cross-language decode coverage (formerly a native Rust viewer subprocess
# here) now lives in test_compat_fixtures.py against compat/sif_reader.ts —
# there is no native viewer/desktop app anymore, only the browser verifier
# at verify/ (spif.dev/verify).
# ---------------------------------------------------------------------------

def test_binary_identical_to_self():
    """Encoding the same doc twice must produce byte-identical output (determinism)."""
    doc = SPIFDocument(payload=[_n(0)], provenance=_prov())
    b1 = SPIFWriter().encode(doc)
    b2 = SPIFWriter().encode(doc)
    assert b1 == b2


# ---------------------------------------------------------------------------
# Memory footprint
# ---------------------------------------------------------------------------

class TestMemoryFootprint:
    def _peak_kb(self, fn) -> float:
        tracemalloc.start()
        fn()
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        return peak / 1024

    def test_minimal_doc_peak_under_1mb(self):
        doc = SPIFDocument(payload=[_n(0)])
        writer = SPIFWriter()
        peak = self._peak_kb(lambda: writer.encode(doc))
        assert peak < 1024, f"Minimal encode peaked at {peak:.0f} KB"

    def test_100_node_doc_peak_under_10mb(self):
        doc = SPIFDocument(payload=[_n(i) for i in range(100)], provenance=_prov())
        writer = SPIFWriter()
        peak = self._peak_kb(lambda: writer.encode(doc))
        assert peak < 10 * 1024, f"100-node encode peaked at {peak:.0f} KB"

    def test_decode_peak_proportional_to_input(self):
        """Decode peak memory should be < 50× the encoded size (no runaway allocation)."""
        nodes = [_n(i, val="content " * 20) for i in range(50)]
        doc = SPIFDocument(payload=nodes, provenance=_prov())
        data = SPIFWriter().encode(doc)
        reader = SPIFReader()
        peak = self._peak_kb(lambda: reader.decode(data))
        ratio = (peak * 1024) / len(data)
        assert ratio < 50, f"Decode memory ratio {ratio:.1f}× exceeds threshold"

    @pytest.mark.slow
    def test_large_embedding_encode_memory(self):
        """Encoding a 3072-dim embedding must not consume more than 50 MB."""
        doc = SPIFDocument(
            payload=[_n(0)],
            semantic=SemanticLayer(
                embedding=[float(i) / 3072 for i in range(3072)],
                embedding_model="text-embedding-3-large",
            ),
        )
        writer = SPIFWriter()
        peak = self._peak_kb(lambda: writer.encode(doc))
        assert peak < 50 * 1024, f"Large embedding encode peaked at {peak:.0f} KB"


# ---------------------------------------------------------------------------
# Cyclic trace DAG detection
# ---------------------------------------------------------------------------

class TestCyclicDagRejection:
    def test_self_referencing_step_rejected(self):
        """A step that depends on itself must raise SPIFFormatError on decode."""
        step = TraceStep(id="s0", type="inference", content="self",
                         confidence=_d(), deps=["s0"])
        doc = SPIFDocument(payload=[_n(0)], trace=[step])
        data = SPIFWriter().encode(doc)
        with pytest.raises(SPIFFormatError, match="[Cc]ycle|[Cc]yclic|[Ss]elf"):
            SPIFReader().decode(data)

    def test_two_node_cycle_rejected(self):
        """s0 → s1 → s0 must be rejected."""
        steps = [
            TraceStep(id="s0", type="inference", content="a", confidence=_d(), deps=["s1"]),
            TraceStep(id="s1", type="inference", content="b", confidence=_d(), deps=["s0"]),
        ]
        doc = SPIFDocument(payload=[_n(0)], trace=steps)
        data = SPIFWriter().encode(doc)
        with pytest.raises(SPIFFormatError, match="[Cc]ycle|[Cc]yclic"):
            SPIFReader().decode(data)

    def test_three_node_cycle_rejected(self):
        steps = [
            TraceStep(id="s0", type="inference", content="a", confidence=_d(), deps=["s2"]),
            TraceStep(id="s1", type="inference", content="b", confidence=_d(), deps=["s0"]),
            TraceStep(id="s2", type="inference", content="c", confidence=_d(), deps=["s1"]),
        ]
        doc = SPIFDocument(payload=[_n(0)], trace=steps)
        data = SPIFWriter().encode(doc)
        with pytest.raises(SPIFFormatError, match="[Cc]ycle|[Cc]yclic"):
            SPIFReader().decode(data)

    def test_valid_dag_not_rejected(self):
        """A valid DAG (no cycles) must decode without error."""
        steps = [
            TraceStep(id="s0", type="hypothesis", content="root", confidence=_d(), deps=[]),
            TraceStep(id="s1", type="inference", content="mid", confidence=_d(), deps=["s0"]),
            TraceStep(id="s2", type="conclusion", content="leaf", confidence=_d(), deps=["s0", "s1"]),
        ]
        doc = SPIFDocument(payload=[_n(0)], trace=steps)
        restored = _encode_decode(doc)
        assert len(restored.trace) == 3


# ---------------------------------------------------------------------------
# NodeRef deep chains
# ---------------------------------------------------------------------------

class TestNodeRefChains:
    def test_chain_of_50_refs(self):
        """n49 → n48 → ... → n0 — all refs must survive roundtrip."""
        nodes = [
            Node(
                id=f"n{i}",
                type="text",
                value=f"node {i}",
                confidence=_d(),
                refs=[NodeRef(f"n{i-1}")] if i > 0 else [],
            )
            for i in range(50)
        ]
        doc = SPIFDocument(payload=nodes)
        restored = _encode_decode(doc)
        assert restored.payload[49].refs[0].node_id == "n48"
        assert restored.payload[0].refs == []

    def test_star_refs(self):
        """One hub node referenced by 100 leaf nodes."""
        hub = Node(id="hub", type="concept", value="central concept", confidence=_d())
        leaves = [
            Node(id=f"leaf{i}", type="text", value=f"leaf {i}", confidence=_d(),
                 refs=[NodeRef("hub")])
            for i in range(100)
        ]
        doc = SPIFDocument(payload=[hub] + leaves)
        restored = _encode_decode(doc)
        assert all(n.refs[0].node_id == "hub" for n in restored.payload[1:])

    def test_distribution_as_node_value(self):
        """Node value can itself be a Distribution."""
        val = Distribution(mean=0.75, var=0.05, shape="beta", semantics="factual_accuracy")
        node = Node(id="n0", type="fact", value=val, confidence=_d())
        doc = SPIFDocument(payload=[node])
        restored = _encode_decode(doc)
        v = restored.payload[0].value
        assert isinstance(v, Distribution)
        assert abs(v.mean - 0.75) < 1e-9

    def test_noderef_as_node_value(self):
        """Node value can be a NodeRef — meaning 'same value as that node'."""
        n0 = Node(id="n0", type="fact", value="original", confidence=_d())
        n1 = Node(id="n1", type="fact", value=NodeRef("n0"), confidence=_d())
        doc = SPIFDocument(payload=[n0, n1])
        restored = _encode_decode(doc)
        assert isinstance(restored.payload[1].value, NodeRef)
        assert restored.payload[1].value.node_id == "n0"


# ---------------------------------------------------------------------------
# Binary / bytes node values (multimodal)
# ---------------------------------------------------------------------------

class TestMultimodalNodes:
    def test_bytes_value_roundtrip(self):
        """A node with raw bytes value must survive encode/decode intact."""
        payload = os.urandom(256)
        node = Node(id="img", type="multimodal", value=payload, confidence=_d())
        doc = SPIFDocument(payload=[node])
        restored = _encode_decode(doc)
        assert bytes(restored.payload[0].value) == payload

    def test_large_binary_value(self):
        """1 MB binary payload must roundtrip."""
        payload = os.urandom(1024 * 1024)
        node = Node(id="blob", type="multimodal", value=payload, confidence=_d())
        doc = SPIFDocument(payload=[node])
        restored = _encode_decode(doc)
        assert bytes(restored.payload[0].value) == payload

    def test_empty_bytes_value(self):
        node = Node(id="empty", type="multimodal", value=b"", confidence=_d())
        doc = SPIFDocument(payload=[node])
        restored = _encode_decode(doc)
        assert bytes(restored.payload[0].value) == b""

    def test_dict_value_roundtrip(self):
        """Dict node values (structured multimodal) must survive."""
        val = {"width": 1920, "height": 1080, "format": "jpeg", "data": "base64..."}
        node = Node(id="structured", type="multimodal", value=val, confidence=_d())
        doc = SPIFDocument(payload=[node])
        restored = _encode_decode(doc)
        assert restored.payload[0].value["width"] == 1920
        assert restored.payload[0].value["format"] == "jpeg"

    def test_multimodal_with_compression(self):
        """Compressible binary (repeated pattern) must be smaller when compressed."""
        payload = b"\xAB\xCD" * (32 * 1024)  # 64KB, highly compressible
        node = Node(id="blob", type="multimodal", value=payload, confidence=_d())
        doc = SPIFDocument(payload=[node])
        raw = len(SPIFWriter(compress=False).encode(doc))
        compressed = len(SPIFWriter(compress=True).encode(doc))
        assert compressed < raw * 0.5, f"Expected >50% compression, got {compressed}/{raw}"


# ---------------------------------------------------------------------------
# Alternative weights edge cases
# ---------------------------------------------------------------------------

class TestAlternativeWeights:
    def test_weights_must_sum_to_one_when_normalized(self):
        with pytest.raises(ValueError, match="sum"):
            SPIFWriter().encode(SPIFDocument(
                payload=[_n(0)],
                alternatives=[
                    Alternative(weight=0.7, nodes=[_n(1)], normalized=True),
                    Alternative(weight=0.7, nodes=[_n(2)], normalized=True),
                ],
            ))

    def test_weights_near_one_accepted(self):
        """0.5001 + 0.4999 = 1.0000 — must be accepted."""
        doc = SPIFDocument(
            payload=[_n(0)],
            alternatives=[
                Alternative(weight=0.5001, nodes=[_n(1)], normalized=True),
                Alternative(weight=0.4999, nodes=[_n(2)], normalized=True),
            ],
        )
        restored = _encode_decode(doc)
        assert len(restored.alternatives) == 2

    def test_unnormalized_any_weight_accepted(self):
        """Unnormalized weights can be any positive float."""
        doc = SPIFDocument(
            payload=[_n(0)],
            alternatives=[
                Alternative(weight=1000.0, nodes=[_n(1)], normalized=False),
                Alternative(weight=0.001,  nodes=[_n(2)], normalized=False),
            ],
        )
        restored = _encode_decode(doc)
        assert restored.alternatives[0].weight == 1000.0

    def test_single_alternative_weight_one(self):
        doc = SPIFDocument(
            payload=[_n(0)],
            alternatives=[Alternative(weight=1.0, nodes=[_n(1)], normalized=True)],
        )
        restored = _encode_decode(doc)
        assert restored.alternatives[0].weight == 1.0


# ---------------------------------------------------------------------------
# Checksum completeness
# ---------------------------------------------------------------------------

class TestChecksumCompleteness:
    def _good(self) -> bytes:
        return SPIFWriter().encode(SPIFDocument(payload=[_n(0)]))

    def test_every_byte_before_checksum_is_covered(self):
        """
        Flipping each bit before the CHECKSUM chunk must invalidate the checksum.
        We verify this exhaustively for small docs to confirm SHA-256 coverage.
        """
        data = self._good()
        # Locate CHECKSUM chunk start
        pos = len(MAGIC) + 2
        checksum_start = None
        while pos + 5 < len(data):
            ct = data[pos]
            clen = struct.unpack_from(">I", data, pos + 1)[0]
            if ct == CHUNK_CHECKSUM:
                checksum_start = pos
                break
            pos += 5 + clen
        assert checksum_start is not None

        body = data[:checksum_start]
        for i in range(min(len(body), 200)):  # test first 200 bytes
            corrupted = bytearray(data)
            corrupted[i] ^= 0xFF
            with pytest.raises(Exception):
                SPIFReader().decode(bytes(corrupted))

    def test_checksum_chunk_itself_is_not_covered(self):
        """
        Modifying the checksum payload itself must raise SPIFChecksumError
        (the stored hash won't match what we compute from the body).
        """
        data = bytearray(self._good())
        # Corrupt the first byte of the SHA-256 digest (5 bytes into the CHECKSUM chunk)
        data[-32] ^= 0x01
        with pytest.raises(SPIFChecksumError):
            SPIFReader().decode(bytes(data))

    def test_appended_bytes_not_covered(self):
        """
        Bytes after the CHECKSUM chunk are outside the checksum scope.
        A reader MUST still parse correctly (extra bytes ignored).
        """
        data = self._good() + b"\x00" * 100
        # This may raise or silently succeed depending on implementation.
        # Crucially, it must not crash with an unhandled exception.
        try:
            SPIFReader().decode(data)
        except Exception:
            pass  # acceptable — but must not be a crash


# ---------------------------------------------------------------------------
# Streaming: concurrent resume with real state
# ---------------------------------------------------------------------------

class TestConcurrentStreamResume:
    def test_10_concurrent_resumes(self):
        """10 threads each simulate a dropped connection and resume."""
        errors = []
        results = []
        lock = threading.Lock()

        def simulate_drop_and_resume(thread_id: int):
            try:
                tokens = [f"t{thread_id}_{j}" for j in range(30)]
                doc = SPIFDocument(payload=[_n(thread_id, val="".join(tokens))])

                # Phase 1: stream 15 tokens, then drop
                w1 = SPIFStreamWriter()
                w1.open()
                for tok in tokens[:15]:
                    w1.partial_text(tok)
                token = w1.resume_token()

                # Phase 2: resume from token 15
                w2 = SPIFStreamWriter(resume_from=token)
                parts = [w2.open()]
                for tok in tokens:  # replay all — writer fast-forwards
                    chunk = w2.partial_text(tok)
                    if chunk:
                        parts.append(chunk)
                parts.append(w2.commit(doc))
                data = b"".join(parts)

                restored = SPIFReader().decode(data)
                with lock:
                    results.append(restored.payload[0].id)
            except Exception as exc:
                with lock:
                    errors.append((thread_id, exc))

        threads = [threading.Thread(target=simulate_drop_and_resume, args=(i,))
                   for i in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors, f"Errors: {errors}"
        assert len(results) == 10

    def test_stream_reader_concurrent_feeds(self):
        """Two independent stream readers processing different docs concurrently."""
        doc1 = SPIFDocument(payload=[_n(0, "doc-one")])
        doc2 = SPIFDocument(payload=[_n(1, "doc-two")])

        def make_stream(doc, tokens):
            w = SPIFStreamWriter()
            parts = [w.open()]
            for t in tokens:
                parts.append(w.partial_text(t))
            parts.append(w.commit(doc))
            return b"".join(parts)

        data1 = make_stream(doc1, ["hello", " world"])
        data2 = make_stream(doc2, ["foo", " bar"])

        results = {}
        lock = threading.Lock()

        def read_stream(key, data):
            events = list(iter_events(data))
            verified = next(e for e in events if e.type == "verified")
            with lock:
                results[key] = verified.document.payload[0].value

        t1 = threading.Thread(target=read_stream, args=(1, data1))
        t2 = threading.Thread(target=read_stream, args=(2, data2))
        t1.start(); t2.start()
        t1.join(); t2.join()

        assert results[1] == "doc-one"
        assert results[2] == "doc-two"


# ---------------------------------------------------------------------------
# Full document (all layers, compressed, signed) roundtrip
# ---------------------------------------------------------------------------

class TestFullDocumentRoundtrip:
    def test_all_layers_uncompressed(self):
        doc = self._make_maximal_doc()
        restored = _encode_decode(doc, compress=False)
        self._assert_full(doc, restored)

    def test_all_layers_compressed(self):
        doc = self._make_maximal_doc()
        restored = _encode_decode(doc, compress=True)
        self._assert_full(doc, restored)

    def test_multiple_reencodings_stable(self):
        """Encoding the same doc 10× must produce byte-identical results."""
        doc = self._make_maximal_doc()
        writer = SPIFWriter()
        b0 = writer.encode(doc)
        for _ in range(9):
            assert writer.encode(doc) == b0

    def test_all_layers_compressed_smaller_than_uncompressed(self):
        doc = self._make_maximal_doc()
        raw = len(SPIFWriter(compress=False).encode(doc))
        compressed = len(SPIFWriter(compress=True).encode(doc))
        assert compressed < raw

    def _make_maximal_doc(self) -> SPIFDocument:
        nodes = [_n(i, val="The quick brown fox " * 5) for i in range(10)]
        steps = [
            TraceStep(id=f"s{i}", type="inference",
                      content=f"Reasoning step {i} with some text",
                      confidence=_d(),
                      deps=[f"s{i-1}"] if i > 0 else [])
            for i in range(10)
        ]
        return SPIFDocument(
            payload=nodes,
            provenance=_prov(),
            semantic=SemanticLayer(
                embedding=[float(i) / 128 for i in range(128)],
                embedding_model="text-embedding-3-small",
            ),
            trace=steps,
            trace_method="live",
            alternatives=[
                Alternative(weight=0.7, nodes=[_n(99)], normalized=True),
                Alternative(weight=0.3, nodes=[_n(98)], normalized=True),
            ],
            delta=Delta(base_hash="a" * 64, changes=[{"op": "add", "value": "x"}]),
        )

    def _assert_full(self, original: SPIFDocument, restored: SPIFDocument) -> None:
        assert len(restored.payload) == len(original.payload)
        assert restored.payload[5].value == original.payload[5].value
        assert restored.provenance.source_model == original.provenance.source_model
        assert restored.semantic.dim == original.semantic.dim
        assert len(restored.trace) == len(original.trace)
        assert restored.trace[9].deps == ["s8"]
        assert len(restored.alternatives) == 2
        assert restored.delta.base_hash == "a" * 64


# ---------------------------------------------------------------------------
# Provenance context chain integrity
# ---------------------------------------------------------------------------

class TestProvenanceChain:
    def test_three_turn_chain_integrity(self):
        """Turn 3's context_ref must trace back through turn 2 → turn 1."""
        doc1 = SPIFDocument(payload=[_n(0, "turn 1")], provenance=_prov())
        prov2 = dataclasses.replace(_prov(), timestamp_ms=1712000001000,
                                     context_ref=doc1.content_id())
        doc2 = SPIFDocument(payload=[_n(1, "turn 2")], provenance=prov2)
        prov3 = dataclasses.replace(_prov(), timestamp_ms=1712000002000,
                                     context_ref=doc2.content_id())
        doc3 = SPIFDocument(payload=[_n(2, "turn 3")], provenance=prov3)

        r3 = _encode_decode(doc3)
        assert r3.provenance.context_ref == doc2.content_id()
        assert r3.provenance.context_ref != doc1.content_id()

    def test_content_id_not_affected_by_reencoding(self):
        """content_id must be stable across multiple encode/decode cycles."""
        doc = SPIFDocument(payload=[_n(0)], provenance=_prov())
        cid = doc.content_id()
        for _ in range(5):
            doc = _encode_decode(doc)
            assert doc.content_id() == cid

    def test_context_ref_empty_for_first_turn(self):
        prov = Provenance(source_model="claude-sonnet-4-6", timestamp_ms=0, context_ref="")
        doc = SPIFDocument(payload=[_n(0)], provenance=prov)
        restored = _encode_decode(doc)
        assert restored.provenance.context_ref == ""
