"""DAG validation: cycle detection and dangling dependency detection."""

import pytest
from spfx import SPIFDocument, Node, TraceStep, SPIFWriter, SPIFReader, SPIFFormatError


def _write(doc):
    return SPIFWriter().encode(doc)


def _payload():
    return [Node(id="n1", type="fact", value="test")]


def test_valid_linear_chain_passes():
    doc = SPIFDocument(
        payload=_payload(),
        trace=[
            TraceStep(id="s1", type="evidence", content="a"),
            TraceStep(id="s2", type="inference", content="b", deps=["s1"]),
            TraceStep(id="s3", type="conclusion", content="c", deps=["s2"]),
        ]
    )
    restored = SPIFReader().decode(_write(doc))
    assert len(restored.trace) == 3


def test_valid_dag_multiple_roots_passes():
    doc = SPIFDocument(
        payload=_payload(),
        trace=[
            TraceStep(id="s1", type="evidence", content="a"),
            TraceStep(id="s2", type="evidence", content="b"),
            TraceStep(id="s3", type="conclusion", content="c", deps=["s1", "s2"]),
        ]
    )
    restored = SPIFReader().decode(_write(doc))
    assert len(restored.trace) == 3


def test_direct_self_cycle_detected():
    doc = SPIFDocument(
        payload=_payload(),
        trace=[TraceStep(id="s1", type="evidence", content="a", deps=["s1"])]
    )
    with pytest.raises(SPIFFormatError, match="Cycle"):
        SPIFReader().decode(_write(doc))


def test_two_node_cycle_detected():
    doc = SPIFDocument(
        payload=_payload(),
        trace=[
            TraceStep(id="s1", type="evidence", content="a", deps=["s2"]),
            TraceStep(id="s2", type="conclusion", content="b", deps=["s1"]),
        ]
    )
    with pytest.raises(SPIFFormatError, match="Cycle"):
        SPIFReader().decode(_write(doc))


def test_three_node_cycle_detected():
    doc = SPIFDocument(
        payload=_payload(),
        trace=[
            TraceStep(id="s1", type="evidence", content="a", deps=["s3"]),
            TraceStep(id="s2", type="inference", content="b", deps=["s1"]),
            TraceStep(id="s3", type="conclusion", content="c", deps=["s2"]),
        ]
    )
    with pytest.raises(SPIFFormatError, match="Cycle"):
        SPIFReader().decode(_write(doc))


def test_dangling_dep_detected():
    doc = SPIFDocument(
        payload=_payload(),
        trace=[
            TraceStep(id="s1", type="evidence", content="a"),
            TraceStep(id="s2", type="conclusion", content="b", deps=["s_nonexistent"]),
        ]
    )
    with pytest.raises(SPIFFormatError, match="unknown dep"):
        SPIFReader().decode(_write(doc))


def test_empty_trace_passes():
    doc = SPIFDocument(payload=_payload())
    restored = SPIFReader().decode(_write(doc))
    assert restored.trace == []


# ---------------------------------------------------------------------------
# Node.refs DAG validation (payload graph)
# ---------------------------------------------------------------------------

def test_node_refs_valid_linear_chain_passes():
    """A → B is a valid acyclic ref chain."""
    from spfx.types import NodeRef
    doc = SPIFDocument(payload=[
        Node(id="a", type="fact", value="A"),
        Node(id="b", type="fact", value="B", refs=[NodeRef("a")]),
    ])
    restored = SPIFReader().decode(_write(doc))
    assert len(restored.payload) == 2


def test_node_refs_two_node_cycle_detected():
    """A → B → A must be rejected."""
    from spfx.types import NodeRef
    doc = SPIFDocument(payload=[
        Node(id="a", type="fact", value="A", refs=[NodeRef("b")]),
        Node(id="b", type="fact", value="B", refs=[NodeRef("a")]),
    ])
    with pytest.raises(SPIFFormatError, match="Cycle"):
        SPIFReader().decode(_write(doc))


def test_node_refs_three_node_cycle_detected():
    """A → B → C → A must be rejected."""
    from spfx.types import NodeRef
    doc = SPIFDocument(payload=[
        Node(id="a", type="fact", value="A", refs=[NodeRef("c")]),
        Node(id="b", type="fact", value="B", refs=[NodeRef("a")]),
        Node(id="c", type="fact", value="C", refs=[NodeRef("b")]),
    ])
    with pytest.raises(SPIFFormatError, match="Cycle"):
        SPIFReader().decode(_write(doc))


def test_node_refs_dangling_ref_detected():
    """A ref to a non-existent node ID must be rejected."""
    from spfx.types import NodeRef
    doc = SPIFDocument(payload=[
        Node(id="a", type="fact", value="A", refs=[NodeRef("ghost")]),
    ])
    with pytest.raises(SPIFFormatError, match="unknown node_id"):
        SPIFReader().decode(_write(doc))


def test_node_refs_duplicate_id_detected():
    """Two nodes with the same id must be rejected."""
    doc = SPIFDocument(payload=[
        Node(id="dup", type="fact", value="First"),
        Node(id="dup", type="fact", value="Second"),
    ])
    with pytest.raises(SPIFFormatError, match="Duplicate Node id"):
        SPIFReader().decode(_write(doc))
