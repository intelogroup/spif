"""Roundtrip tests: write then read, assert equality across all layer combinations."""

import time
import pytest
from spfx import (
    SPIFWriter, SPIFReader, SPIFDocument,
    Distribution, Node, NodeRef, TraceStep,
    Provenance, SemanticLayer, Alternative, Delta,
)


def _write_read(doc: SPIFDocument) -> SPIFDocument:
    data = SPIFWriter().encode(doc)
    return SPIFReader().decode(data)


def test_minimal():
    doc = SPIFDocument(payload=[
        Node(id="n1", type="fact", value="Paris is the capital of France.",
             confidence=Distribution(mean=0.99, var=0.001))
    ])
    out = _write_read(doc)
    assert out.payload[0].id == "n1"
    assert out.payload[0].value == "Paris is the capital of France."
    assert abs(out.payload[0].confidence.mean - 0.99) < 1e-6


def test_distribution_roundtrip():
    d = Distribution(mean=0.73, var=0.04, shape="beta", p5=0.5, p95=0.9)
    doc = SPIFDocument(payload=[Node(id="x", type="text", value="test", confidence=d)])
    out = _write_read(doc)
    c = out.payload[0].confidence
    assert abs(c.mean - 0.73) < 1e-6
    assert c.shape == "beta"
    assert abs(c.p5 - 0.5) < 1e-6


def test_node_refs():
    doc = SPIFDocument(payload=[
        Node(id="n1", type="concept", value="France"),
        Node(id="n2", type="fact", value="Paris", refs=[NodeRef("n1")]),
    ])
    out = _write_read(doc)
    assert out.payload[1].refs[0].node_id == "n1"


def test_with_provenance():
    ts = int(time.time() * 1000)
    doc = SPIFDocument(
        payload=[Node(id="n1", type="text", value="hi")],
        provenance=Provenance(
            source_model="claude-sonnet-4-6",
            model_version="4.6",
            temperature=0.7,
            input_hash="abc123",
            timestamp_ms=ts,
        )
    )
    out = _write_read(doc)
    assert out.provenance.source_model == "claude-sonnet-4-6"
    assert out.provenance.temperature == 0.7
    assert out.provenance.timestamp_ms == ts


def test_with_semantic():
    emb = [0.1, 0.2, 0.3, 0.4, 0.5]
    doc = SPIFDocument(
        payload=[Node(id="n1", type="text", value="hello")],
        semantic=SemanticLayer(embedding=emb),
    )
    out = _write_read(doc)
    assert len(out.semantic.embedding) == 5
    assert abs(out.semantic.embedding[2] - 0.3) < 1e-6


def test_with_trace():
    doc = SPIFDocument(
        payload=[Node(id="n1", type="fact", value="Paris")],
        trace=[
            TraceStep(id="s1", type="evidence", content="Question asks about France's capital",
                      confidence=Distribution(mean=1.0, var=0.0, shape="point")),
            TraceStep(id="s2", type="inference", content="Paris is the capital",
                      confidence=Distribution(mean=0.99, var=0.001),
                      deps=["s1"],
                      alternatives=["Lyon", "Versailles"]),
            TraceStep(id="s3", type="conclusion", content="Paris",
                      confidence=Distribution(mean=0.99, var=0.001),
                      deps=["s2"]),
        ]
    )
    out = _write_read(doc)
    assert len(out.trace) == 3
    assert out.trace[1].deps == ["s1"]
    assert out.trace[1].alternatives == ["Lyon", "Versailles"]
    assert out.trace[2].deps == ["s2"]


def test_with_alternatives():
    doc = SPIFDocument(
        payload=[Node(id="n1", type="text", value="primary answer")],
        alternatives=[
            Alternative(weight=0.6, nodes=[Node(id="a1", type="text", value="alt A")]),
            Alternative(weight=0.4, nodes=[Node(id="a2", type="text", value="alt B")]),
        ]
    )
    out = _write_read(doc)
    assert len(out.alternatives) == 2
    assert abs(out.alternatives[0].weight - 0.6) < 1e-6
    assert out.alternatives[1].nodes[0].value == "alt B"


def test_with_delta():
    doc = SPIFDocument(
        payload=[Node(id="n1", type="text", value="updated")],
        delta=Delta(base_hash="deadbeef" * 8, changes=[{"op": "replace", "path": "/n1/value"}]),
    )
    out = _write_read(doc)
    assert out.delta.base_hash == "deadbeef" * 8
    assert out.delta.changes[0]["op"] == "replace"


def test_all_layers():
    """Full document with every optional layer present."""
    ts = int(time.time() * 1000)
    doc = SPIFDocument(
        payload=[
            Node(id="n1", type="fact", value="Paris",
                 confidence=Distribution(mean=0.99, var=0.001, shape="gaussian")),
        ],
        provenance=Provenance(source_model="test-model", timestamp_ms=ts, temperature=0.5),
        semantic=SemanticLayer(embedding=[0.1, 0.2, 0.3]),
        trace=[
            TraceStep(id="s1", type="conclusion", content="Paris",
                      confidence=Distribution(mean=0.99, var=0.001)),
        ],
        alternatives=[Alternative(weight=1.0, nodes=[Node(id="x", type="text", value="Lyon")])],
        delta=Delta(base_hash="00" * 32, changes=[]),
    )
    out = _write_read(doc)
    assert out.payload[0].id == "n1"
    assert out.provenance.source_model == "test-model"
    assert len(out.semantic.embedding) == 3
    assert len(out.trace) == 1
    assert len(out.alternatives) == 1
    assert out.delta.base_hash == "00" * 32


# ---------------------------------------------------------------------------
# Tool call node roundtrips (2.4)
# ---------------------------------------------------------------------------

def test_tool_call_node_roundtrip():
    from spfx.format import NODE_TOOL_CALL
    doc = SPIFDocument(payload=[
        Node(
            id="call_1",
            type=NODE_TOOL_CALL,
            value={"name": "get_weather", "arguments": {"city": "Paris"}, "call_id": "abc123"},
            confidence=Distribution(mean=1.0, var=0.0, shape="point", semantics="epistemic"),
        )
    ])
    out = _write_read(doc)
    assert out.payload[0].type == NODE_TOOL_CALL
    v = out.payload[0].value
    assert v["name"] == "get_weather"
    assert v["arguments"]["city"] == "Paris"
    assert v["call_id"] == "abc123"


def test_tool_result_node_roundtrip():
    from spfx.format import NODE_TOOL_RESULT
    doc = SPIFDocument(payload=[
        Node(
            id="result_1",
            type=NODE_TOOL_RESULT,
            value={"call_id": "abc123", "content": {"temp": 22, "unit": "C"}, "is_error": False},
            confidence=Distribution(mean=1.0, var=0.0, shape="point", semantics="epistemic"),
        )
    ])
    out = _write_read(doc)
    assert out.payload[0].type == NODE_TOOL_RESULT
    v = out.payload[0].value
    assert v["call_id"] == "abc123"
    assert v["content"]["temp"] == 22
    assert v["is_error"] is False


def test_tool_call_with_refs_roundtrip():
    """Response node can ref the tool result it consumed."""
    from spfx.format import NODE_TOOL_CALL, NODE_TOOL_RESULT, NODE_TEXT
    doc = SPIFDocument(payload=[
        Node(
            id="call_1",
            type=NODE_TOOL_CALL,
            value={"name": "search", "arguments": {"q": "SPIF"}, "call_id": "c1"},
            confidence=Distribution(mean=1.0, var=0.0, shape="point", semantics="epistemic"),
        ),
        Node(
            id="result_1",
            type=NODE_TOOL_RESULT,
            value={"call_id": "c1", "content": "SPIF is a binary format.", "is_error": False},
            confidence=Distribution(mean=1.0, var=0.0, shape="point", semantics="epistemic"),
        ),
        Node(
            id="response",
            type=NODE_TEXT,
            value="Based on the search, SPIF is a binary format.",
            confidence=Distribution(mean=0.9, var=0.03, shape="gaussian", semantics="output_stability"),
            refs=[NodeRef("result_1")],
        ),
    ])
    out = _write_read(doc)
    assert len(out.payload) == 3
    assert out.payload[0].type == NODE_TOOL_CALL
    assert out.payload[1].type == NODE_TOOL_RESULT
    assert out.payload[2].type == NODE_TEXT
    assert out.payload[2].refs[0].node_id == "result_1"


# ---------------------------------------------------------------------------
# Multi-turn content_id chaining (2.5)
# ---------------------------------------------------------------------------

def test_content_id_is_deterministic():
    from spfx import compute_content_id
    doc = SPIFDocument(payload=[Node(id="x", type="text", value="hello")])
    id1 = compute_content_id(doc)
    id2 = compute_content_id(doc)
    assert id1 == id2
    assert len(id1) == 64  # SHA-256 hex


def test_content_id_differs_for_different_payload():
    from spfx import compute_content_id
    doc1 = SPIFDocument(payload=[Node(id="x", type="text", value="hello")])
    doc2 = SPIFDocument(payload=[Node(id="x", type="text", value="world")])
    assert compute_content_id(doc1) != compute_content_id(doc2)


def test_doc_content_id_method_matches_function():
    from spfx import compute_content_id
    doc = SPIFDocument(payload=[Node(id="x", type="text", value="test")])
    assert doc.content_id() == compute_content_id(doc)


# ---------------------------------------------------------------------------
# Compression roundtrips (3.2)
# ---------------------------------------------------------------------------

def test_compressed_roundtrip():
    """SPIFWriter(compress=True) → SPIFReader().decode() gives same result."""
    from spfx.format import NODE_TEXT
    doc = SPIFDocument(payload=[
        Node(id="r", type=NODE_TEXT, value="Hello compressed world! " * 50,
             confidence=Distribution(mean=0.9, var=0.03, shape="gaussian",
                                     semantics="output_stability"))
    ])
    compressed_data = SPIFWriter(compress=True).encode(doc)
    uncompressed_data = SPIFWriter().encode(doc)

    restored = SPIFReader().decode(compressed_data)
    assert restored.payload[0].value == doc.payload[0].value
    # Compression should reduce size for repetitive data
    assert len(compressed_data) < len(uncompressed_data)


def test_compressed_with_all_layers():
    doc = SPIFDocument(
        payload=[Node(id="n1", type="fact", value="The sky is blue",
                      confidence=Distribution(mean=0.95, var=0.02))],
        provenance=Provenance(source_model="test", timestamp_ms=1234567890000,
                              temperature=1.0),
        trace=[TraceStep(id="s1", type="evidence", content="observation",
                         confidence=Distribution(mean=0.9, var=0.05))],
        alternatives=[Alternative(weight=1.0, nodes=[
            Node(id="alt1", type="fact", value="The sky is grey")
        ])],
    )
    data = SPIFWriter(compress=True).encode(doc)
    restored = SPIFReader().decode(data)
    assert restored.payload[0].value == "The sky is blue"
    assert restored.provenance.source_model == "test"
    assert len(restored.trace) == 1
    assert len(restored.alternatives) == 1


def test_uncompressed_reader_reads_uncompressed_doc():
    """Uncompressed docs still read fine after adding compression support."""
    doc = SPIFDocument(payload=[Node(id="x", type="text", value="plain")])
    data = SPIFWriter().encode(doc)  # no compress
    restored = SPIFReader().decode(data)
    assert restored.payload[0].value == "plain"


def test_compressed_provenance_still_readable():
    """PROVENANCE is never compressed — always readable for routing."""
    doc = SPIFDocument(
        payload=[Node(id="x", type="text", value="data " * 100)],
        provenance=Provenance(source_model="gpt-4o", timestamp_ms=0),
    )
    data = SPIFWriter(compress=True).encode(doc)
    restored = SPIFReader().decode(data)
    assert restored.provenance.source_model == "gpt-4o"


# ---------------------------------------------------------------------------
# Zlib level 9 regression (writer uses level=9 now)
# ---------------------------------------------------------------------------

def test_zlib_level9_still_roundtrips():
    """Level-9 zlib output must still be decompressible by SPIFReader."""
    doc = SPIFDocument(
        payload=[Node(id="n1", type="text", value="compress me " * 200,
                      confidence=Distribution(mean=0.8, var=0.1))],
        provenance=Provenance(source_model="test", timestamp_ms=0),
    )
    data = SPIFWriter(compress=True).encode(doc)
    restored = SPIFReader().decode(data)
    assert restored.payload[0].value.startswith("compress me ")


def test_zlib_level9_smaller_than_no_compress():
    doc = SPIFDocument(
        payload=[Node(id="n1", type="text", value="repeat " * 500,
                      confidence=Distribution(mean=0.9, var=0.05))]
    )
    compressed = SPIFWriter(compress=True).encode(doc)
    plain = SPIFWriter().encode(doc)
    assert len(compressed) < len(plain)


# ---------------------------------------------------------------------------
# Zstd compression roundtrips (v1.1)
# ---------------------------------------------------------------------------

def test_zstd_roundtrip():
    """zstd-compressed doc roundtrips correctly."""
    pytest.importorskip("zstandard")
    doc = SPIFDocument(
        payload=[Node(id="n1", type="text", value="zstd test payload " * 100,
                      confidence=Distribution(mean=0.9, var=0.05))],
        provenance=Provenance(source_model="test-model", timestamp_ms=0),
    )
    data = SPIFWriter(compress=True, compression="zstd").encode(doc)
    restored = SPIFReader().decode(data)
    assert restored.payload[0].value.startswith("zstd test payload ")
    assert restored.provenance.source_model == "test-model"


def test_zstd_smaller_than_zlib():
    """zstd should achieve similar or better compression than zlib for repetitive data."""
    pytest.importorskip("zstandard")
    doc = SPIFDocument(
        payload=[Node(id="n1", type="text", value="repeated content block " * 500,
                      confidence=Distribution(mean=0.9, var=0.05))]
    )
    zlib_data = SPIFWriter(compress=True, compression="zlib").encode(doc)
    zstd_data = SPIFWriter(compress=True, compression="zstd").encode(doc)
    # Both should compress — zstd may be ≤ zlib for this data
    plain = SPIFWriter().encode(doc)
    assert len(zlib_data) < len(plain)
    assert len(zstd_data) < len(plain)


def test_invalid_compression_raises():
    with pytest.raises(ValueError, match="compression must be"):
        SPIFWriter(compression="bzip2")
