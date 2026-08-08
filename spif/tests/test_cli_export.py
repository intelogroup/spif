"""Tests for spfx render warning and spfx export command."""

from __future__ import annotations

import json

import pytest
from typer.testing import CliRunner

from spif.cli import app
from spif.exporters.msgpack import from_msgpack
from spif.types import SPIFDocument, Node, Provenance, Distribution, TraceStep
from spif.writer import SPIFWriter

runner = CliRunner()


def _write_spif(tmp_path, doc: SPIFDocument | None = None) -> object:
    if doc is None:
        doc = SPIFDocument(
            payload=[Node(id="n1", type="text", value="hello world")],
            provenance=Provenance(
                source_model="claude-sonnet-4-6",
                temperature=1.0,
                timestamp_ms=1_700_000_000_000,
                input_hash="abc123",
            ),
        )
    path = tmp_path / "test.spfx"
    path.write_bytes(SPIFWriter().encode(doc))
    return path


# ---------------------------------------------------------------------------
# render: stderr warning
# ---------------------------------------------------------------------------

class TestRenderWarning:
    def test_render_emits_warning(self, tmp_path):
        path = _write_spif(tmp_path)
        result = runner.invoke(app, ["render", str(path)], catch_exceptions=False)
        assert result.exit_code == 0
        assert "WARNING" in result.output
        assert "human debugging only" in result.output

    def test_render_warning_mentions_lossless_json(self, tmp_path):
        path = _write_spif(tmp_path)
        result = runner.invoke(app, ["render", str(path)], catch_exceptions=False)
        assert "lossless-json" in result.output

    def test_render_document_still_printed(self, tmp_path):
        path = _write_spif(tmp_path)
        result = runner.invoke(app, ["render", str(path)], catch_exceptions=False)
        assert "SPIF DOCUMENT" in result.output
        assert "PAYLOAD" in result.output


# ---------------------------------------------------------------------------
# export --lossless-json: output
# ---------------------------------------------------------------------------

class TestExportLosslessJson:
    def test_export_produces_valid_json(self, tmp_path):
        path = _write_spif(tmp_path)
        result = runner.invoke(app, ["export", str(path), "--lossless-json"],
                               catch_exceptions=False)
        assert result.exit_code == 0
        data = json.loads(result.stdout)
        assert data["fmt"] == "spfx"
        assert data["v"] == "0.2"

    def test_export_preserves_payload(self, tmp_path):
        path = _write_spif(tmp_path)
        result = runner.invoke(app, ["export", str(path), "--lossless-json"],
                               catch_exceptions=False)
        data = json.loads(result.stdout)
        assert len(data["payload"]) == 1
        assert data["payload"][0]["val"] == "hello world"

    def test_export_preserves_provenance(self, tmp_path):
        path = _write_spif(tmp_path)
        result = runner.invoke(app, ["export", str(path), "--lossless-json"],
                               catch_exceptions=False)
        data = json.loads(result.stdout)
        assert data["prov"]["m"] == "claude-sonnet-4-6"
        assert data["prov"]["tmp"] == 1.0

    def test_export_checksum_present(self, tmp_path):
        path = _write_spif(tmp_path)
        result = runner.invoke(app, ["export", str(path), "--lossless-json"],
                               catch_exceptions=False)
        data = json.loads(result.stdout)
        assert "cksum" in data
        assert data["cksum"].startswith("sha256:")

    def test_export_to_file(self, tmp_path):
        path = _write_spif(tmp_path)
        out = tmp_path / "output.json"
        result = runner.invoke(
            app, ["export", str(path), "--lossless-json", "--output", str(out)],
            catch_exceptions=False,
        )
        assert result.exit_code == 0
        assert out.exists()
        data = json.loads(out.read_text())
        assert data["fmt"] == "spfx"

    def test_export_indent_pretty_prints(self, tmp_path):
        path = _write_spif(tmp_path)
        result = runner.invoke(
            app, ["export", str(path), "--lossless-json", "--indent", "2"],
            catch_exceptions=False,
        )
        assert result.exit_code == 0
        # Indented output has newlines
        assert "\n" in result.stdout

    def test_export_no_format_exits_1(self, tmp_path):
        path = _write_spif(tmp_path)
        result = runner.invoke(app, ["export", str(path)])
        assert result.exit_code == 1

    def test_export_with_trace(self, tmp_path):
        doc = SPIFDocument(
            payload=[Node(id="n1", type="text", value="answer")],
            trace=[
                TraceStep(id="s1", type="hypothesis", content="reasoning",
                          confidence=Distribution(mean=0.9, var=0.02,
                                                  shape="gaussian", semantics="epistemic")),
            ],
        )
        path = _write_spif(tmp_path, doc)
        result = runner.invoke(app, ["export", str(path), "--lossless-json"],
                               catch_exceptions=False)
        assert result.exit_code == 0
        data = json.loads(result.stdout)
        assert "trace" in data
        assert data["trace"][0]["id"] == "s1"

    def test_export_roundtrip_via_from_lossless_json(self, tmp_path):
        path = _write_spif(tmp_path)
        result = runner.invoke(app, ["export", str(path), "--lossless-json"],
                               catch_exceptions=False)
        from spif.exporters.lossless_json import from_lossless_json
        restored = from_lossless_json(result.stdout)
        assert restored.payload[0].value == "hello world"
        assert restored.provenance.source_model == "claude-sonnet-4-6"


class TestExportMsgpack:
    def test_export_msgpack_to_file(self, tmp_path):
        path = _write_spif(tmp_path)
        out = tmp_path / "output.msgpack"
        result = runner.invoke(
            app, ["export", str(path), "--msgpack", "--output", str(out)],
            catch_exceptions=False,
        )
        assert result.exit_code == 0
        assert out.exists()
        restored = from_msgpack(out.read_bytes())
        assert restored.payload[0].value == "hello world"
        assert restored.provenance.source_model == "claude-sonnet-4-6"

    def test_export_multiple_formats_exits_1(self, tmp_path):
        path = _write_spif(tmp_path)
        result = runner.invoke(app, ["export", str(path), "--lossless-json", "--msgpack"])
        assert result.exit_code == 1
