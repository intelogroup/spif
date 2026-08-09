"""
Tests for SPIF MCP server tools (tools/spif_mcp.py).

All tests run offline — no API key required.  The Anthropic client is
replaced with a minimal mock that returns pre-canned responses.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

# Make tools/ importable without installing it as a package
sys.path.insert(0, str(Path(__file__).parent.parent / "tools"))

from spif_mcp import call_claude, wrap_text
from spif.exporters.lossless_json import from_lossless_json


# ---------------------------------------------------------------------------
# Helpers: mock Anthropic responses
# ---------------------------------------------------------------------------

def _anthropic_response(text: str, model: str = "claude-sonnet-4-6") -> SimpleNamespace:
    block = SimpleNamespace(type="text", text=text)
    return SimpleNamespace(model=model, content=[block])


def _anthropic_thinking_response(
    text: str,
    thinking_text: str,
    model: str = "claude-sonnet-4-6",
) -> SimpleNamespace:
    thinking_block = SimpleNamespace(type="thinking", thinking=thinking_text)
    text_block = SimpleNamespace(type="text", text=text)
    return SimpleNamespace(model=model, content=[thinking_block, text_block])


def _make_mock_client(response) -> MagicMock:
    client = MagicMock()
    client.messages.create.return_value = response
    return client


# ---------------------------------------------------------------------------
# wrap_text
# ---------------------------------------------------------------------------

class TestWrapText:
    def test_returns_valid_json(self):
        result = wrap_text("hello world", model="gpt-4o")
        data = json.loads(result)
        assert data["fmt"] == "spif"
        assert data["v"] == "0.2"

    def test_payload_contains_text(self):
        result = wrap_text("Paris is the capital of France.", model="gpt-4o")
        data = json.loads(result)
        assert data["payload"][0]["val"] == "Paris is the capital of France."
        assert data["payload"][0]["t"] == "text"

    def test_provenance_records_model(self):
        result = wrap_text("hi", model="gpt-4o-mini", temperature=0.7)
        data = json.loads(result)
        assert data["prov"]["m"] == "gpt-4o-mini"
        assert data["prov"]["tmp"] == 0.7

    def test_provenance_has_timestamp(self):
        result = wrap_text("hi", model="gpt-4o")
        data = json.loads(result)
        assert data["prov"]["ts"] > 0

    def test_input_hash_from_prompt(self):
        import hashlib
        prompt = "What is the capital of France?"
        result = wrap_text("Paris.", model="gpt-4o", prompt=prompt)
        data = json.loads(result)
        messages = [{"role": "user", "content": prompt}]
        expected = hashlib.sha256(
            json.dumps(messages, sort_keys=True, ensure_ascii=False).encode()
        ).hexdigest()
        assert data["prov"]["ih"] == expected

    def test_no_prompt_no_input_hash(self):
        result = wrap_text("hi", model="gpt-4o")
        data = json.loads(result)
        assert data["prov"]["ih"] == ""

    def test_context_ref_stored(self):
        result = wrap_text("hi", model="gpt-4o", context_ref="abc123")
        data = json.loads(result)
        assert data["prov"]["cr"] == "abc123"

    def test_checksum_present_and_valid(self):
        result = wrap_text("hi", model="gpt-4o")
        # from_lossless_json verifies the checksum — raises if invalid
        doc = from_lossless_json(result)
        assert doc.payload[0].value == "hi"

    def test_conservative_confidence_default(self):
        result = wrap_text("hi", model="gpt-4o")
        data = json.loads(result)
        conf = data["payload"][0]["c"]
        assert conf["m"] == pytest.approx(0.85)
        assert conf["v"] == pytest.approx(0.05)

    def test_roundtrip_via_from_lossless_json(self):
        result = wrap_text("The answer is 42.", model="claude-haiku-4-5-20251001",
                           temperature=0.5, prompt="What is the answer?")
        doc = from_lossless_json(result)
        assert doc.payload[0].value == "The answer is 42."
        assert doc.provenance.source_model == "claude-haiku-4-5-20251001"
        assert doc.provenance.temperature == 0.5


# ---------------------------------------------------------------------------
# call_claude (mocked)
# ---------------------------------------------------------------------------

class TestCallClaude:
    def test_returns_valid_spif_json(self):
        response = _anthropic_response("Paris is the capital of France.")
        client = _make_mock_client(response)

        with patch("anthropic.Anthropic", return_value=client):
            result = call_claude("What is the capital of France?")

        data = json.loads(result)
        assert data["fmt"] == "spif"
        assert "Paris" in data["payload"][0]["val"]

    def test_provenance_records_model(self):
        response = _anthropic_response("hello", model="claude-sonnet-4-6")
        client = _make_mock_client(response)

        with patch("anthropic.Anthropic", return_value=client):
            result = call_claude("hi", model="claude-sonnet-4-6")

        data = json.loads(result)
        assert data["prov"]["m"] == "claude-sonnet-4-6"

    def test_input_hash_matches_prompt(self):
        import hashlib
        prompt = "Why is the sky blue?"
        response = _anthropic_response("Rayleigh scattering.")
        client = _make_mock_client(response)

        with patch("anthropic.Anthropic", return_value=client):
            result = call_claude(prompt)

        data = json.loads(result)
        messages = [{"role": "user", "content": prompt}]
        expected = hashlib.sha256(
            json.dumps(messages, sort_keys=True).encode()
        ).hexdigest()
        assert data["prov"]["ih"] == expected

    def test_thinking_blocks_produce_trace(self):
        response = _anthropic_thinking_response(
            text="42",
            thinking_text="Let me think about this step by step...",
        )
        client = _make_mock_client(response)

        with patch("anthropic.Anthropic", return_value=client):
            result = call_claude("What is 6*7?", thinking=True)

        data = json.loads(result)
        assert "trace" in data
        assert len(data["trace"]) == 1
        assert "think" in data["trace"][0]["cont"].lower()

    def test_no_thinking_no_trace(self):
        response = _anthropic_response("hello")
        client = _make_mock_client(response)

        with patch("anthropic.Anthropic", return_value=client):
            result = call_claude("hi", thinking=False)

        data = json.loads(result)
        assert "trace" not in data or data.get("trace") == []

    def test_context_ref_passed_through(self):
        response = _anthropic_response("yes")
        client = _make_mock_client(response)

        with patch("anthropic.Anthropic", return_value=client):
            result = call_claude("continue", context_ref="deadbeef")

        data = json.loads(result)
        assert data["prov"]["cr"] == "deadbeef"

    def test_checksum_verifies(self):
        response = _anthropic_response("hello")
        client = _make_mock_client(response)

        with patch("anthropic.Anthropic", return_value=client):
            result = call_claude("hi")

        doc = from_lossless_json(result)
        assert doc.payload[0].value == "hello"

    def test_missing_anthropic_raises_runtime_error(self):
        with patch.dict("sys.modules", {"anthropic": None}):
            with pytest.raises((RuntimeError, ImportError)):
                call_claude("hi")
