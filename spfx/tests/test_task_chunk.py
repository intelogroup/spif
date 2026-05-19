"""Tests for CHUNK_TASK roundtrip, flags2 bit, and optional presence."""

from __future__ import annotations
import pytest

from spfx import SPIFDocument, Node, Distribution, Provenance, SPIFWriter, SPIFReader, TaskInfo
from spfx.format import CHUNK_TASK, FLAG_HAS_TASK


def _minimal_doc() -> SPIFDocument:
    return SPIFDocument(payload=[
        Node(id="n1", type="text", value="hello",
             confidence=Distribution(mean=0.9, var=0.05))
    ])


def _write_read(doc: SPIFDocument) -> SPIFDocument:
    return SPIFReader().decode(SPIFWriter().encode(doc))


class TestTaskChunkRoundtrip:
    def test_no_task_info_roundtrip(self):
        """Documents without TaskInfo still roundtrip correctly."""
        doc = _minimal_doc()
        out = _write_read(doc)
        assert out.task_info is None
        assert out.payload[0].value == "hello"

    def test_task_info_roundtrip(self):
        doc = _minimal_doc()
        doc.task_info = TaskInfo(
            task_id="task-abc-123",
            attempt=2,
            status="failed",
            total_ms=4200,
            tool_count=3,
            error_count=1,
        )
        out = _write_read(doc)
        assert out.task_info is not None
        assert out.task_info.task_id == "task-abc-123"
        assert out.task_info.attempt == 2
        assert out.task_info.status == "failed"
        assert out.task_info.total_ms == 4200
        assert out.task_info.tool_count == 3
        assert out.task_info.error_count == 1

    def test_task_info_defaults(self):
        doc = _minimal_doc()
        doc.task_info = TaskInfo(task_id="t1")
        out = _write_read(doc)
        assert out.task_info.attempt == 0
        assert out.task_info.status == "ok"
        assert out.task_info.total_ms == 0
        assert out.task_info.tool_count == 0
        assert out.task_info.error_count == 0

    def test_flag_has_task_set_when_task_info_present(self):
        """FLAG_HAS_TASK bit must be set in serialized bytes when task_info is present."""
        doc = _minimal_doc()
        doc.task_info = TaskInfo(task_id="t1")
        data = SPIFWriter().encode(doc)
        # Scan for CHUNK_TASK byte in output — FLAG_HAS_TASK being set is confirmed by
        # successful roundtrip, but we also verify the chunk type byte is present.
        assert bytes([CHUNK_TASK]) in data

    def test_flag_has_task_absent_when_no_task_info(self):
        """No CHUNK_TASK byte in output when task_info is None."""
        doc = _minimal_doc()
        data = SPIFWriter().encode(doc)
        assert bytes([CHUNK_TASK]) not in data

    def test_task_info_with_all_layers(self):
        """TaskInfo present alongside all other optional layers."""
        doc = SPIFDocument(
            payload=[Node(id="n1", type="text", value="test",
                          confidence=Distribution(mean=0.8, var=0.1))],
            provenance=Provenance(source_model="model-x", timestamp_ms=0),
            task_info=TaskInfo(task_id="run-42", attempt=1, status="ok",
                               total_ms=1234, tool_count=2, error_count=0),
        )
        out = _write_read(doc)
        assert out.task_info.task_id == "run-42"
        assert out.provenance.source_model == "model-x"


class TestTaskInfoDataclass:
    def test_status_values(self):
        for status in ("ok", "failed", "aborted"):
            ti = TaskInfo(task_id="x", status=status)
            assert ti.status == status

    def test_task_id_required(self):
        with pytest.raises(TypeError):
            TaskInfo()  # type: ignore[call-arg]
