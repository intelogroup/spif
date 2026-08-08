"""Tests for attempt/task_id Provenance fields and document_status property."""

from __future__ import annotations

from spif import SPIFDocument, Node, Distribution, Provenance, SPIFWriter, SPIFReader
from spif.format import NODE_TOOL_RESULT, NODE_TEXT


def _write_read(doc: SPIFDocument) -> SPIFDocument:
    return SPIFReader().decode(SPIFWriter().encode(doc))


def _doc_with_provenance(**kwargs) -> SPIFDocument:
    return SPIFDocument(
        payload=[Node(id="n1", type="text", value="hi",
                      confidence=Distribution(mean=0.9, var=0.05))],
        provenance=Provenance(source_model="test-model", timestamp_ms=0, **kwargs),
    )


class TestProvenanceNewFields:
    def test_attempt_roundtrip(self):
        doc = _doc_with_provenance(attempt=3)
        out = _write_read(doc)
        assert out.provenance.attempt == 3

    def test_task_id_roundtrip(self):
        doc = _doc_with_provenance(task_id="task-xyz-789")
        out = _write_read(doc)
        assert out.provenance.task_id == "task-xyz-789"

    def test_attempt_and_task_id_together(self):
        doc = _doc_with_provenance(attempt=1, task_id="task-99")
        out = _write_read(doc)
        assert out.provenance.attempt == 1
        assert out.provenance.task_id == "task-99"

    def test_old_doc_defaults_to_zero(self):
        """Documents written before these fields were added must parse with attempt=0."""
        doc = _doc_with_provenance()
        out = _write_read(doc)
        assert out.provenance.attempt == 0
        assert out.provenance.task_id == ""

    def test_attempt_included_in_content_id(self):
        """Retry attempts must produce distinct content IDs."""
        from spif import compute_content_id
        doc1 = _doc_with_provenance(task_id="t1", attempt=0)
        doc2 = _doc_with_provenance(task_id="t1", attempt=1)
        assert compute_content_id(doc1) != compute_content_id(doc2)

    def test_task_id_included_in_content_id(self):
        from spif import compute_content_id
        doc1 = _doc_with_provenance(task_id="task-a")
        doc2 = _doc_with_provenance(task_id="task-b")
        assert compute_content_id(doc1) != compute_content_id(doc2)

    def test_risk_tier_and_model_card_roundtrip(self):
        doc = _doc_with_provenance(risk_tier="high", model_card="https://modelregistry.example.com/cards/1")
        out = _write_read(doc)
        assert out.provenance.risk_tier == "high"
        assert out.provenance.model_card == "https://modelregistry.example.com/cards/1"

    def test_risk_tier_and_model_card_defaults(self):
        doc = _doc_with_provenance()
        out = _write_read(doc)
        assert out.provenance.risk_tier == ""
        assert out.provenance.model_card == ""

    def test_risk_tier_included_in_content_id(self):
        from spif import compute_content_id
        doc1 = _doc_with_provenance(risk_tier="minimal")
        doc2 = _doc_with_provenance(risk_tier="high")
        assert compute_content_id(doc1) != compute_content_id(doc2)

    def test_model_card_included_in_content_id(self):
        from spif import compute_content_id
        doc1 = _doc_with_provenance(model_card="http://ref/1")
        doc2 = _doc_with_provenance(model_card="http://ref/2")
        assert compute_content_id(doc1) != compute_content_id(doc2)



class TestDocumentStatus:
    def _tool_result_node(self, *, is_error: bool) -> Node:
        return Node(
            id="tr1",
            type=NODE_TOOL_RESULT,
            value={"call_id": "c1", "content": "result", "is_error": is_error},
            confidence=Distribution(mean=0.9, var=0.05),
        )

    def test_ok_when_no_tool_results(self):
        doc = SPIFDocument(payload=[
            Node(id="n1", type=NODE_TEXT, value="hi",
                 confidence=Distribution(mean=0.9, var=0.05))
        ])
        assert doc.document_status == "ok"

    def test_ok_when_tool_result_not_error(self):
        doc = SPIFDocument(payload=[self._tool_result_node(is_error=False)])
        assert doc.document_status == "ok"

    def test_failed_when_tool_result_is_error(self):
        doc = SPIFDocument(payload=[self._tool_result_node(is_error=True)])
        assert doc.document_status == "failed"

    def test_failed_on_any_error_node(self):
        """One error in multiple results → failed."""
        doc = SPIFDocument(payload=[
            self._tool_result_node(is_error=False),
            self._tool_result_node(is_error=True),
        ])
        assert doc.document_status == "failed"

    def test_ok_when_all_results_success(self):
        doc = SPIFDocument(payload=[
            self._tool_result_node(is_error=False),
            self._tool_result_node(is_error=False),
        ])
        assert doc.document_status == "ok"
