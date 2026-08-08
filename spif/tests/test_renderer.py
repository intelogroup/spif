from spif import (
    SPIFDocument, Node, Distribution, TraceStep, Provenance, SemanticLayer,
    SPIFRenderer,
)
import time


def _doc_with_trace():
    return SPIFDocument(
        payload=[Node(id="n1", type="fact", value="Paris",
                      confidence=Distribution(mean=0.99, var=0.001))],
        trace=[
            TraceStep(id="s1", type="evidence", content="France capital question",
                      confidence=Distribution(mean=1.0, var=0.0, shape="point")),
            TraceStep(id="s2", type="conclusion", content="Paris",
                      confidence=Distribution(mean=0.99, var=0.001),
                      deps=["s1"], alternatives=["Lyon"]),
        ]
    )


def test_render_contains_payload_header():
    doc = SPIFDocument(payload=[Node(id="n1", type="text", value="hello")])
    out = SPIFRenderer().render(doc)
    assert "PAYLOAD" in out


def test_render_shows_node_id():
    doc = SPIFDocument(payload=[Node(id="my_node", type="fact", value="test")])
    out = SPIFRenderer().render(doc)
    assert "my_node" in out


def test_render_shows_confidence_bar():
    doc = SPIFDocument(payload=[
        Node(id="n1", type="text", value="x",
             confidence=Distribution(mean=0.5, var=0.1))
    ])
    out = SPIFRenderer().render(doc)
    assert "█" in out
    assert "50%" in out


def test_render_shows_trace():
    doc = _doc_with_trace()
    out = SPIFRenderer().render(doc)
    assert "REASONING TRACE" in out
    assert "EVIDENCE" in out
    assert "CONCLUSION" in out


def test_render_shows_alternatives_in_trace():
    doc = _doc_with_trace()
    out = SPIFRenderer().render(doc)
    assert "Lyon" in out


def test_render_shows_provenance():
    doc = SPIFDocument(
        payload=[Node(id="n1", type="text", value="x")],
        provenance=Provenance(source_model="my-model", timestamp_ms=int(time.time() * 1000),
                              temperature=0.7)
    )
    out = SPIFRenderer().render(doc)
    assert "PROVENANCE" in out
    assert "my-model" in out
    assert "0.7" in out


def test_render_shows_semantic():
    doc = SPIFDocument(
        payload=[Node(id="n1", type="text", value="x")],
        semantic=SemanticLayer(embedding=[0.1, 0.2, 0.3, 0.4, 0.5, 0.6])
    )
    out = SPIFRenderer().render(doc)
    assert "SEMANTIC" in out
    assert "dim: 6" in out
