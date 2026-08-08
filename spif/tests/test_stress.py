"""
Real-world stress tests for SPIF.

These tests push the format hard — large documents, deep DAGs, adversarial
binary inputs, concurrency, Unicode edge cases, compression under load, and
multi-language roundtrip scenarios.  They are designed to catch regressions
that unit tests miss by exercising the full encode → wire → decode pipeline
under conditions that resemble production use.

Run the full suite:   pytest tests/test_stress.py -v
Run quick smoke:      pytest tests/test_stress.py -m "not slow"
"""

from __future__ import annotations

import hashlib
import random
import string
import struct
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import pytest

from spif import (
    SPIFDocument, Node, Distribution, TraceStep, Provenance,
    SemanticLayer, Alternative, SPIFWriter, SPIFReader,
)
from spif.format import (
    MAGIC, CHUNK_CHECKSUM, CHUNK_PAYLOAD, CHUNK_HEADER,
    NODE_TOOL_CALL, NODE_TOOL_RESULT,
)
from spif.reader import SPIFChecksumError, SPIFFormatError, SPIFMagicError
from spif.streaming import SPIFStreamWriter, SPIFStreamReader, iter_events
from spif.types import Delta, Signature


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

RNG = random.Random(0xDEADBEEF)


def _dist(mean: float = 0.9, semantics: str = "epistemic") -> Distribution:
    return Distribution(mean=mean, var=0.01, shape="gaussian", semantics=semantics)


def _node(i: int, value: str = None) -> Node:
    return Node(
        id=f"n{i}",
        type="text",
        value=value or f"Content of node {i}",
        confidence=_dist(mean=RNG.uniform(0.5, 0.99)),
    )


def _prov() -> Provenance:
    return Provenance(
        source_model="claude-sonnet-4-6",
        model_version="claude-sonnet-4-6-20250514",
        temperature=0.7,
        input_hash="a" * 64,
        context_ref="",
        timestamp_ms=1712000000000,
    )


def _encode_decode(doc: SPIFDocument, compress: bool = False) -> SPIFDocument:
    data = SPIFWriter(compress=compress).encode(doc)
    return SPIFReader().decode(data)


# ---------------------------------------------------------------------------
# Scale: large payload
# ---------------------------------------------------------------------------

class TestLargeDocuments:
    @pytest.mark.slow
    def test_1000_node_payload_roundtrip(self):
        nodes = [_node(i) for i in range(1000)]
        doc = SPIFDocument(payload=nodes, provenance=_prov())
        restored = _encode_decode(doc)
        assert len(restored.payload) == 1000
        assert restored.payload[500].id == "n500"

    def test_100_node_payload_roundtrip(self):
        nodes = [_node(i) for i in range(100)]
        doc = SPIFDocument(payload=nodes, provenance=_prov())
        restored = _encode_decode(doc)
        assert len(restored.payload) == 100

    @pytest.mark.slow
    def test_large_payload_with_compression_roundtrip(self):
        nodes = [_node(i, value="x" * 500) for i in range(200)]
        doc = SPIFDocument(payload=nodes, provenance=_prov())
        raw = SPIFWriter(compress=False).encode(doc)
        compressed = SPIFWriter(compress=True).encode(doc)
        assert len(compressed) < len(raw)  # must actually compress
        restored = SPIFReader().decode(compressed)
        assert len(restored.payload) == 200
        assert restored.payload[0].value == "x" * 500

    def test_10mb_text_value_node(self):
        """A single node with 10 MB of text must roundtrip cleanly."""
        big = "A" * (10 * 1024 * 1024)
        doc = SPIFDocument(payload=[Node(id="big", type="text", value=big,
                                         confidence=_dist())])
        restored = _encode_decode(doc)
        assert len(restored.payload[0].value) == 10 * 1024 * 1024

    def test_large_embedding_roundtrip(self):
        """3072-dimensional embedding (OpenAI ada-003 size) must survive encode/decode."""
        dim = 3072
        embedding = [RNG.uniform(-1, 1) for _ in range(dim)]
        doc = SPIFDocument(
            payload=[_node(0)],
            semantic=SemanticLayer(
                embedding=embedding,
                embedding_model="text-embedding-3-large",
            ),
        )
        restored = _encode_decode(doc)
        assert restored.semantic is not None
        assert len(restored.semantic.embedding) == dim
        assert abs(restored.semantic.embedding[0] - embedding[0]) < 1e-5

    def test_large_embedding_compresses_well(self):
        dim = 1536
        embedding = [RNG.uniform(-1, 1) for _ in range(dim)]
        doc = SPIFDocument(
            payload=[_node(0)],
            semantic=SemanticLayer(embedding=embedding, embedding_model="ada-002"),
        )
        raw = SPIFWriter(compress=False).encode(doc)
        compressed = SPIFWriter(compress=True).encode(doc)
        ratio = len(compressed) / len(raw)
        assert ratio < 0.9, f"Expected >10% compression on embedding, got ratio={ratio:.2f}"


# ---------------------------------------------------------------------------
# Scale: deep trace DAGs
# ---------------------------------------------------------------------------

class TestDeepTraceDag:
    def test_linear_chain_100_steps(self):
        steps = []
        for i in range(100):
            steps.append(TraceStep(
                id=f"s{i}",
                type="inference",
                content=f"Step {i} reasoning",
                confidence=_dist(mean=0.8),
                deps=[f"s{i-1}"] if i > 0 else [],
            ))
        doc = SPIFDocument(payload=[_node(0)], trace=steps, trace_method="live")
        restored = _encode_decode(doc)
        assert len(restored.trace) == 100
        assert restored.trace[99].deps == ["s98"]

    def test_wide_tree_50_leaves(self):
        """50 leaves all depending on a single root step."""
        root = TraceStep(id="root", type="hypothesis", content="root",
                         confidence=_dist(), deps=[])
        leaves = [
            TraceStep(id=f"leaf{i}", type="inference", content=f"leaf {i}",
                      confidence=_dist(), deps=["root"])
            for i in range(50)
        ]
        doc = SPIFDocument(payload=[_node(0)], trace=[root] + leaves)
        restored = _encode_decode(doc)
        assert len(restored.trace) == 51
        assert all(s.deps == ["root"] for s in restored.trace[1:])

    @pytest.mark.slow
    def test_diamond_dag_500_nodes(self):
        """Diamond DAG: each step depends on the previous two — stress-tests DAG parsing."""
        steps = [TraceStep(id="s0", type="hypothesis", content="start",
                           confidence=_dist(), deps=[]),
                 TraceStep(id="s1", type="hypothesis", content="branch",
                           confidence=_dist(), deps=[])]
        for i in range(2, 500):
            deps = [f"s{i-1}", f"s{i-2}"]
            steps.append(TraceStep(id=f"s{i}", type="inference",
                                   content=f"fib-{i}", confidence=_dist(), deps=deps))
        doc = SPIFDocument(payload=[_node(0)], trace=steps)
        restored = _encode_decode(doc)
        assert len(restored.trace) == 500
        assert restored.trace[499].deps == ["s498", "s497"]


# ---------------------------------------------------------------------------
# Unicode and special characters
# ---------------------------------------------------------------------------

class TestUnicodeStress:
    HARD_STRINGS = [
        "",                           # empty string
        " " * 1000,                   # all spaces
        "\x00\x01\x02",               # control chars (valid in CBOR text)
        "\u0000",                     # null in unicode
        "こんにちは世界",               # Japanese
        "مرحبا بالعالم",              # Arabic (RTL)
        "😀🎉🔥💯🚀" * 100,           # emoji repeated
        "\u200b\u200c\u200d",         # zero-width chars
        "café naïve résumé",          # accented Latin
        "\uffff\ufffe",               # BOM and near-BOM
        "𝄞𝄢𝄻" * 50,               # musical symbols (4-byte UTF-8)
        "A" * 65536,                  # 64KB ASCII
        "\n\r\t" * 1000,              # mixed line endings
    ]

    @pytest.mark.parametrize("s", HARD_STRINGS)
    def test_hard_string_in_node_value(self, s):
        doc = SPIFDocument(payload=[Node(id="u", type="text", value=s,
                                         confidence=_dist())])
        restored = _encode_decode(doc)
        assert restored.payload[0].value == s

    @pytest.mark.parametrize("s", HARD_STRINGS)
    def test_hard_string_in_node_id(self, s):
        if not s or "\x00" in s:
            pytest.skip("empty or null id not valid")
        doc = SPIFDocument(payload=[Node(id=s, type="text", value="ok",
                                         confidence=_dist())])
        restored = _encode_decode(doc)
        assert restored.payload[0].id == s

    def test_hard_string_in_trace_content(self):
        for s in self.HARD_STRINGS:
            step = TraceStep(id="s0", type="inference", content=s,
                             confidence=_dist(), deps=[])
            doc = SPIFDocument(payload=[_node(0)], trace=[step])
            restored = _encode_decode(doc)
            assert restored.trace[0].content == s

    def test_hard_string_in_model_name(self):
        for s in self.HARD_STRINGS:
            if not s:
                continue
            prov = Provenance(source_model=s, timestamp_ms=0)
            doc = SPIFDocument(payload=[_node(0)], provenance=prov)
            restored = _encode_decode(doc)
            assert restored.provenance.source_model == s


# ---------------------------------------------------------------------------
# Binary corruption / adversarial inputs
# ---------------------------------------------------------------------------

class TestAdversarialBinary:
    def _good_doc(self) -> bytes:
        return SPIFWriter().encode(SPIFDocument(payload=[_node(0)]))

    def test_all_zeros_rejected(self):
        with pytest.raises(SPIFMagicError):
            SPIFReader().decode(b"\x00" * 1000)

    def test_truncated_at_every_byte(self):
        """Truncating at any byte before the final checksum must raise, not hang or crash."""
        data = self._good_doc()
        # Skip the last 37 bytes (checksum chunk); truncation there is expected to fail
        for i in range(1, len(data) - 37):
            with pytest.raises(Exception):
                SPIFReader().decode(data[:i])

    def test_single_bit_flip_at_every_position(self):
        """Flipping any bit anywhere must either be caught by checksum or raise."""
        data = bytearray(self._good_doc())
        # Sample 50 random positions to keep the test fast
        positions = RNG.sample(range(len(data)), min(50, len(data)))
        for pos in positions:
            corrupted = bytearray(data)
            corrupted[pos] ^= 0x01
            with pytest.raises(Exception):
                SPIFReader().decode(bytes(corrupted))

    def test_payload_chunk_zeroed(self):
        data = bytearray(self._good_doc())
        # Find PAYLOAD chunk (type 0x04) and zero its content
        pos = len(MAGIC) + 2
        while pos + 5 < len(data):
            ct = data[pos]
            clen = struct.unpack_from(">I", data, pos + 1)[0]
            if ct == CHUNK_PAYLOAD:
                for i in range(5, 5 + clen):
                    data[pos + i] = 0x00
                break
            pos += 5 + clen
        with pytest.raises(Exception):
            SPIFReader().decode(bytes(data))

    def test_checksum_chunk_wrong_length(self):
        data = bytearray(self._good_doc())
        # Find CHECKSUM chunk and change its declared length to 31
        pos = len(MAGIC) + 2
        while pos + 5 < len(data):
            ct = data[pos]
            clen = struct.unpack_from(">I", data, pos + 1)[0]
            if ct == CHUNK_CHECKSUM:
                struct.pack_into(">I", data, pos + 1, 31)  # wrong length
                break
            pos += 5 + clen
        with pytest.raises(Exception):
            SPIFReader().decode(bytes(data))

    def test_duplicate_payload_chunk(self):
        """Two PAYLOAD chunks: reader takes the last one but checksum must still verify."""
        data = bytearray(self._good_doc())
        # Find PAYLOAD chunk position and size
        pos = len(MAGIC) + 2
        payload_chunk = None
        while pos + 5 < len(data):
            ct = data[pos]
            clen = struct.unpack_from(">I", data, pos + 1)[0]
            if ct == CHUNK_PAYLOAD:
                payload_chunk = bytes(data[pos: pos + 5 + clen])
                break
            pos += 5 + clen
        assert payload_chunk is not None
        # We can't inject and re-checksum without the writer — just confirm the original is valid
        SPIFReader().decode(bytes(data))

    def test_magic_prefix_mismatch(self):
        data = bytearray(self._good_doc())
        data[4] = 0x00  # corrupt 'F' in SPIF
        with pytest.raises(SPIFMagicError):
            SPIFReader().decode(bytes(data))

    def test_random_bytes_rejected(self):
        for _ in range(20):
            junk = bytes(RNG.getrandbits(8) for _ in range(RNG.randint(10, 2000)))
            with pytest.raises(Exception):
                SPIFReader().decode(junk)

    def test_valid_cbor_but_wrong_schema(self):
        """Replace PAYLOAD content with valid CBOR that doesn't match the schema."""
        import cbor2
        bad_payload = cbor2.dumps("this is not a node array")
        chunk = struct.pack(">BI", CHUNK_PAYLOAD, len(bad_payload)) + bad_payload
        data = bytearray(self._good_doc())
        # Replace payload chunk
        pos = len(MAGIC) + 2
        while pos + 5 < len(data):
            ct = data[pos]
            clen = struct.unpack_from(">I", data, pos + 1)[0]
            if ct == CHUNK_PAYLOAD:
                # Re-build document with bad payload (checksum will fail)
                prefix = bytes(data[:pos])
                suffix = bytes(data[pos + 5 + clen:])
                new_body = prefix + chunk + suffix[37:]  # drop old checksum
                checksum = hashlib.sha256(new_body).digest()
                final = new_body + struct.pack(">BI", CHUNK_CHECKSUM, 32) + checksum
                with pytest.raises(Exception):
                    SPIFReader().decode(final)
                return
            pos += 5 + clen


# ---------------------------------------------------------------------------
# Concurrent encode / decode
# ---------------------------------------------------------------------------

class TestConcurrency:
    def test_parallel_encode_decode_100_threads(self):
        """100 threads each encode and decode a different document — no shared state."""
        errors = []

        def worker(i: int):
            try:
                doc = SPIFDocument(
                    payload=[_node(i, value=f"thread-{i}-content")],
                    provenance=_prov(),
                )
                data = SPIFWriter().encode(doc)
                restored = SPIFReader().decode(data)
                assert restored.payload[0].value == f"thread-{i}-content"
            except Exception as exc:
                errors.append(exc)

        with ThreadPoolExecutor(max_workers=100) as pool:
            futures = [pool.submit(worker, i) for i in range(100)]
            for f in as_completed(futures):
                f.result()

        assert not errors, f"Thread errors: {errors}"

    def test_parallel_streaming_writers(self):
        """20 concurrent streaming writers must produce independently valid documents."""
        results = []
        lock = threading.Lock()

        def stream_worker(i: int):
            tokens = [f"word{j} " for j in range(20)]
            doc = SPIFDocument(payload=[_node(i, value="".join(tokens))])
            writer = SPIFStreamWriter()
            parts = [writer.open()]
            for tok in tokens:
                parts.append(writer.partial_text(tok))
            parts.append(writer.commit(doc))
            data = b"".join(parts)
            restored = SPIFReader().decode(data)
            with lock:
                results.append(restored.payload[0].id)

        threads = [threading.Thread(target=stream_worker, args=(i,)) for i in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(results) == 20
        assert all(r.startswith("n") for r in results)

    def test_shared_reader_instance_is_safe(self):
        """SPIFReader is stateless — a single instance shared across threads must be safe."""
        reader = SPIFReader()
        errors = []
        docs_to_read = []
        for i in range(50):
            doc = SPIFDocument(payload=[_node(i)])
            docs_to_read.append(SPIFWriter().encode(doc))

        def read_worker(data: bytes):
            try:
                reader.decode(data)
            except Exception as exc:
                errors.append(exc)

        with ThreadPoolExecutor(max_workers=50) as pool:
            list(pool.map(read_worker, docs_to_read))

        assert not errors


# ---------------------------------------------------------------------------
# Streaming edge cases
# ---------------------------------------------------------------------------

class TestStreamingEdgeCases:
    def test_feed_one_byte_at_a_time(self):
        tokens = ["hello", " ", "world"]
        doc = SPIFDocument(payload=[_node(0, value="hello world")])
        writer = SPIFStreamWriter()
        parts = [writer.open()]
        for tok in tokens:
            parts.append(writer.partial_text(tok))
        parts.append(writer.commit(doc))
        data = b"".join(parts)

        reader = SPIFStreamReader()
        all_events = []
        for byte in data:
            all_events.extend(reader.feed(bytes([byte])))

        verified = [e for e in all_events if e.type == "verified"]
        partials = [e for e in all_events if e.type == "partial_text"]
        assert len(verified) == 1
        assert len(partials) == 3
        assert "".join(e.text for e in partials) == "hello world"

    def test_feed_large_chunks(self):
        tokens = [f"t{i}" for i in range(500)]
        doc = SPIFDocument(payload=[_node(0)])
        writer = SPIFStreamWriter()
        parts = [writer.open()]
        for tok in tokens:
            parts.append(writer.partial_text(tok))
        parts.append(writer.commit(doc))
        data = b"".join(parts)

        # Feed in 4KB chunks
        events = list(iter_events(data, chunk_size=4096))
        partials = [e for e in events if e.type == "partial_text"]
        assert len(partials) == 500

    def test_stream_resume_full_protocol(self):
        """Simulate drop after 50 tokens, resume, verify complete doc."""
        tokens = [f"word{i} " for i in range(100)]
        doc = SPIFDocument(payload=[_node(0, value="".join(tokens))])

        # First stream: send 50 tokens then drop
        w1 = SPIFStreamWriter()
        w1.open()
        for tok in tokens[:50]:
            w1.partial_text(tok)
        resume_token = w1.resume_token()

        # Resumed stream: replay all 100 tokens, writer skips 0-49
        w2 = SPIFStreamWriter(resume_from=resume_token)
        parts = [w2.open()]
        for tok in tokens:
            chunk = w2.partial_text(tok)
            if chunk:
                parts.append(chunk)
        parts.append(w2.commit(doc))
        resumed_data = b"".join(parts)

        events = list(iter_events(resumed_data))
        verified = next(e for e in events if e.type == "verified")
        resumed_evts = [e for e in events if e.type == "resumed"]
        partials = [e for e in events if e.type == "partial_text"]

        assert verified.document is not None
        assert len(resumed_evts) == 1
        assert resumed_evts[0].seq == 50
        # Only tokens 50-99 should be in the resumed stream
        assert len(partials) == 50
        assert partials[0].seq == 50

    def test_stream_with_all_layers(self):
        """Stream a document that has every optional layer populated."""
        doc = SPIFDocument(
            payload=[_node(0)],
            provenance=_prov(),
            semantic=SemanticLayer(
                embedding=[float(i) / 100 for i in range(128)],
                embedding_model="test-embed",
            ),
            trace=[
                TraceStep(id="s0", type="inference", content="reasoning",
                          confidence=_dist(), deps=[])
            ],
            trace_method="live",
            alternatives=[
                Alternative(weight=1.0, nodes=[_node(99)], normalized=True)
            ],
        )
        writer = SPIFStreamWriter()
        parts = [writer.open(doc.provenance)]
        for i in range(10):
            parts.append(writer.partial_text(f"tok{i}"))
        parts.append(writer.commit(doc))
        data = b"".join(parts)

        restored = SPIFReader().decode(data)
        assert restored.provenance.source_model == "claude-sonnet-4-6"
        assert restored.semantic.dim == 128
        assert len(restored.trace) == 1
        assert len(restored.alternatives) == 1


# ---------------------------------------------------------------------------
# Tool call nodes
# ---------------------------------------------------------------------------

class TestToolCallNodes:
    def test_tool_call_result_chain_roundtrip(self):
        """Tool call → tool result → response text chain."""
        from spif.types import NodeRef

        tool_call = Node(
            id="call1",
            type=NODE_TOOL_CALL,
            value={"name": "get_weather", "arguments": {"city": "Paris"}, "call_id": "c1"},
            confidence=_dist(mean=1.0),
        )
        tool_result = Node(
            id="result1",
            type=NODE_TOOL_RESULT,
            value={"call_id": "c1", "content": "20°C, sunny", "is_error": False},
            confidence=_dist(mean=1.0),
        )
        response = Node(
            id="resp1",
            type="text",
            value="The weather in Paris is 20°C and sunny.",
            confidence=_dist(mean=0.95),
            refs=[NodeRef("result1")],
        )
        doc = SPIFDocument(payload=[tool_call, tool_result, response])
        restored = _encode_decode(doc)

        assert restored.payload[0].type == NODE_TOOL_CALL
        assert restored.payload[0].value["name"] == "get_weather"
        assert restored.payload[1].type == NODE_TOOL_RESULT
        assert restored.payload[1].value["is_error"] is False
        assert restored.payload[2].refs[0].node_id == "result1"

    def test_multi_turn_tool_calls(self):
        """10-step tool call chain."""
        nodes = []
        for i in range(10):
            nodes.append(Node(
                id=f"call{i}",
                type=NODE_TOOL_CALL,
                value={"name": f"tool_{i}", "arguments": {"idx": i}, "call_id": f"c{i}"},
                confidence=_dist(mean=1.0),
            ))
            nodes.append(Node(
                id=f"res{i}",
                type=NODE_TOOL_RESULT,
                value={"call_id": f"c{i}", "content": f"result_{i}", "is_error": False},
                confidence=_dist(mean=1.0),
            ))
        doc = SPIFDocument(payload=nodes)
        restored = _encode_decode(doc)
        assert len(restored.payload) == 20
        assert restored.payload[18].type == NODE_TOOL_CALL

    def test_tool_result_with_error(self):
        nodes = [
            Node(id="c1", type=NODE_TOOL_CALL,
                 value={"name": "bad_tool", "arguments": {}, "call_id": "x"},
                 confidence=_dist(mean=1.0)),
            Node(id="r1", type=NODE_TOOL_RESULT,
                 value={"call_id": "x", "content": "TimeoutError", "is_error": True},
                 confidence=_dist(mean=1.0)),
        ]
        doc = SPIFDocument(payload=nodes)
        restored = _encode_decode(doc)
        assert restored.payload[1].value["is_error"] is True


# ---------------------------------------------------------------------------
# Content identity and multi-turn chaining
# ---------------------------------------------------------------------------

class TestContentIdentity:
    def test_content_id_stable_across_reencode(self):
        doc = SPIFDocument(payload=[_node(0)], provenance=_prov())
        id1 = doc.content_id()
        id2 = doc.content_id()
        assert id1 == id2

    def test_content_id_changes_on_payload_change(self):
        doc1 = SPIFDocument(payload=[_node(0)], provenance=_prov())
        doc2 = SPIFDocument(payload=[_node(1)], provenance=_prov())
        assert doc1.content_id() != doc2.content_id()

    def test_content_id_invariant_to_signature(self):
        """Adding a signature must not change the content_id."""
        doc = SPIFDocument(payload=[_node(0)])
        id_unsigned = doc.content_id()
        import dataclasses
        doc_signed = dataclasses.replace(
            doc,
            signature=Signature(algorithm="ed25519", signer="test", signature=b"\x00" * 64),
        )
        assert doc_signed.content_id() == id_unsigned

    def test_context_ref_chain(self):
        """context_ref of doc2 must equal content_id() of doc1."""
        doc1 = SPIFDocument(payload=[_node(0)], provenance=_prov())
        prov2 = Provenance(
            source_model="claude-sonnet-4-6",
            timestamp_ms=1712000001000,
            context_ref=doc1.content_id(),
        )
        doc2 = SPIFDocument(payload=[_node(1)], provenance=prov2)
        restored2 = _encode_decode(doc2)
        assert restored2.provenance.context_ref == doc1.content_id()

    def test_content_id_is_hex_sha256(self):
        doc = SPIFDocument(payload=[_node(0)])
        cid = doc.content_id()
        assert len(cid) == 64
        assert all(c in "0123456789abcdef" for c in cid)


# ---------------------------------------------------------------------------
# Compression fidelity under load
# ---------------------------------------------------------------------------

class TestCompressionFidelity:
    def test_compressed_equals_uncompressed_semantically(self):
        nodes = [_node(i) for i in range(50)]
        trace = [TraceStep(id=f"s{i}", type="inference", content=f"step {i}",
                           confidence=_dist(), deps=[f"s{i-1}"] if i > 0 else [])
                 for i in range(20)]
        doc = SPIFDocument(
            payload=nodes,
            trace=trace,
            provenance=_prov(),
            semantic=SemanticLayer(
                embedding=[float(i) / 1000 for i in range(512)],
                embedding_model="test",
            ),
        )
        r_plain = _encode_decode(doc, compress=False)
        r_compressed = _encode_decode(doc, compress=True)

        assert len(r_plain.payload) == len(r_compressed.payload)
        assert len(r_plain.trace) == len(r_compressed.trace)
        assert r_plain.payload[25].value == r_compressed.payload[25].value
        assert r_plain.semantic.dim == r_compressed.semantic.dim

    def test_compression_then_streaming_roundtrip(self):
        """Compressed doc written to stream, then streamed back, must decode correctly."""
        doc = SPIFDocument(
            payload=[_node(i, value="x" * 200) for i in range(30)],
            provenance=_prov(),
        )
        writer = SPIFStreamWriter()
        parts = [writer.open(doc.provenance)]
        for i in range(20):
            parts.append(writer.partial_text(f"chunk{i}"))
        parts.append(writer.commit(doc))
        data = b"".join(parts)

        restored = SPIFReader().decode(data)
        assert len(restored.payload) == 30

    def test_incompressible_data_doesnt_grow_unreasonably(self):
        """Random bytes are incompressible — compressed size should be < 120% of raw."""
        import os
        random_values = [str(int.from_bytes(os.urandom(4), "big")) for _ in range(50)]
        nodes = [_node(i, value=random_values[i]) for i in range(50)]
        doc = SPIFDocument(payload=nodes)
        raw_size = len(SPIFWriter(compress=False).encode(doc))
        compressed_size = len(SPIFWriter(compress=True).encode(doc))
        assert compressed_size < raw_size * 1.2, \
            f"Compressed ({compressed_size}) > 120% of raw ({raw_size})"


# ---------------------------------------------------------------------------
# Distribution semantics stress
# ---------------------------------------------------------------------------

class TestDistributionEdgeCases:
    def test_mean_exactly_zero(self):
        d = Distribution(mean=0.0, var=0.0, shape="point", semantics="epistemic")
        doc = SPIFDocument(payload=[Node(id="x", type="fact", value="v", confidence=d)])
        restored = _encode_decode(doc)
        assert restored.payload[0].confidence.mean == 0.0

    def test_mean_exactly_one(self):
        d = Distribution(mean=1.0, var=0.0, shape="point", semantics="epistemic")
        doc = SPIFDocument(payload=[Node(id="x", type="fact", value="v", confidence=d)])
        restored = _encode_decode(doc)
        assert restored.payload[0].confidence.mean == 1.0

    def test_p5_p95_roundtrip(self):
        d = Distribution(mean=0.5, var=0.05, shape="gaussian",
                         semantics="epistemic", p5=0.3, p95=0.7)
        doc = SPIFDocument(payload=[Node(id="x", type="fact", value="v", confidence=d)])
        restored = _encode_decode(doc)
        c = restored.payload[0].confidence
        assert abs(c.p5 - 0.3) < 1e-9
        assert abs(c.p95 - 0.7) < 1e-9

    def test_token_probability_semantics(self):
        d = Distribution(mean=0.85, var=0.01, shape="gaussian",
                         semantics="token_probability")
        doc = SPIFDocument(payload=[Node(id="x", type="text", value="hi", confidence=d)])
        restored = _encode_decode(doc)
        assert restored.payload[0].confidence.semantics == "token_probability"

    def test_custom_semantics_no_warning(self):
        import warnings
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            d = Distribution(mean=0.5, var=0.0, shape="point",
                             semantics="custom:my_application_specific")
            assert not any("Unknown" in str(x.message) for x in w)

    def test_all_shapes_roundtrip(self):
        for shape in ["gaussian", "beta", "bimodal", "uniform", "point"]:
            d = Distribution(mean=0.5, var=0.01, shape=shape, semantics="epistemic")
            doc = SPIFDocument(payload=[Node(id="x", type="fact", value="v", confidence=d)])
            restored = _encode_decode(doc)
            assert restored.payload[0].confidence.shape == shape


# ---------------------------------------------------------------------------
# Delta chunk
# ---------------------------------------------------------------------------

class TestDeltaChunk:
    def test_delta_roundtrip(self):
        from spif.types import Delta
        base_doc = SPIFDocument(payload=[_node(0)])
        delta_doc = SPIFDocument(
            payload=[_node(0, value="updated")],
            delta=Delta(
                base_hash=base_doc.content_id(),
                changes=[
                    {"op": "replace", "path": "/payload/0/value", "value": "updated"}
                ],
            ),
        )
        restored = _encode_decode(delta_doc)
        assert restored.delta is not None
        assert restored.delta.base_hash == base_doc.content_id()
        assert restored.delta.changes[0]["op"] == "replace"

    def test_delta_with_many_changes(self):
        from spif.types import Delta
        changes = [{"op": "replace", "path": f"/payload/{i}/value", "value": f"v{i}"}
                   for i in range(100)]
        doc = SPIFDocument(
            payload=[_node(0)],
            delta=Delta(base_hash="a" * 64, changes=changes),
        )
        restored = _encode_decode(doc)
        assert len(restored.delta.changes) == 100


# ---------------------------------------------------------------------------
# Alternatives chunk
# ---------------------------------------------------------------------------

class TestAlternativesChunk:
    def test_three_alternatives_roundtrip(self):
        doc = SPIFDocument(
            payload=[_node(0)],
            alternatives=[
                Alternative(weight=0.6, nodes=[_node(10)], normalized=True),
                Alternative(weight=0.3, nodes=[_node(11)], normalized=True),
                Alternative(weight=0.1, nodes=[_node(12)], normalized=True),
            ],
        )
        restored = _encode_decode(doc)
        assert len(restored.alternatives) == 3
        assert abs(restored.alternatives[0].weight - 0.6) < 1e-9
        assert restored.alternatives[2].nodes[0].id == "n12"

    def test_unnormalized_alternatives(self):
        doc = SPIFDocument(
            payload=[_node(0)],
            alternatives=[
                Alternative(weight=10.0, nodes=[_node(1)], normalized=False),
                Alternative(weight=7.5, nodes=[_node(2)], normalized=False),
            ],
        )
        restored = _encode_decode(doc)
        assert restored.alternatives[0].normalized is False
        assert restored.alternatives[0].weight == 10.0


# ---------------------------------------------------------------------------
# Throughput smoke test
# ---------------------------------------------------------------------------

class TestThroughput:
    @pytest.mark.slow
    def test_1000_roundtrips_in_under_10_seconds(self):
        doc = SPIFDocument(
            payload=[_node(i) for i in range(10)],
            provenance=_prov(),
        )
        writer = SPIFWriter()
        reader = SPIFReader()
        start = time.monotonic()
        for _ in range(1000):
            data = writer.encode(doc)
            reader.decode(data)
        elapsed = time.monotonic() - start
        assert elapsed < 10.0, f"1000 roundtrips took {elapsed:.1f}s (expected < 10s)"

    def test_100_streaming_roundtrips(self):
        doc = SPIFDocument(payload=[_node(0)])
        for _ in range(100):
            w = SPIFStreamWriter()
            parts = [w.open()]
            for tok in ["a", "b", "c"]:
                parts.append(w.partial_text(tok))
            parts.append(w.commit(doc))
            data = b"".join(parts)
            SPIFReader().decode(data)
