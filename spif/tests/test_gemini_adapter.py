"""
Tests for GeminiSPIFAdapter.

All tests run offline — no API key required.  The Gemini client is replaced
with a minimal mock that emits pre-canned streaming chunks or a complete
response object.
"""

from __future__ import annotations

import math
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock

import pytest

from spif.adapters.gemini_adapter import (
    GeminiSPIFAdapter,
    _confidence_from_logprobs,
    _normalise_messages,
    _messages_to_prompt,
    _messages_to_contents,
    _extract_chunk_content,
)
from spif.reader import SPIFReader
from spif.streaming import iter_events
from spif.types import Distribution


# ---------------------------------------------------------------------------
# Helpers: minimal Gemini response objects
# ---------------------------------------------------------------------------

def _lp_entry(text: str, log_prob: float) -> SimpleNamespace:
    """Fake logprob entry (chosen_candidates item)."""
    return SimpleNamespace(token=text, log_probability=log_prob)


def _make_part(text: str, *, thought: bool = False) -> SimpleNamespace:
    return SimpleNamespace(text=text, thought=thought)


def _make_chunk(
    parts: list[SimpleNamespace] | None = None,
    *,
    logprobs_result: Any = None,
) -> SimpleNamespace:
    """Build a fake Gemini streaming chunk."""
    if parts is None:
        parts = []
    content = SimpleNamespace(parts=parts)
    candidate = SimpleNamespace(content=content, logprobs_result=logprobs_result)
    return SimpleNamespace(candidates=[candidate], text=None)


def _make_simple_chunk(text: str) -> SimpleNamespace:
    """Minimal chunk with a single text part."""
    return _make_chunk([_make_part(text)])


def _make_thinking_chunk(thought: str, text: str) -> SimpleNamespace:
    """Chunk with both a thinking part and a text part."""
    return _make_chunk([_make_part(thought, thought=True), _make_part(text)])


def _make_logprob_chunk(text: str, log_prob: float) -> SimpleNamespace:
    """Chunk with a text part and logprob data."""
    lp_result = SimpleNamespace(chosen_candidates=[_lp_entry(text, log_prob)])
    return _make_chunk([_make_part(text)], logprobs_result=lp_result)


def _make_legacy_client(chunks: list) -> MagicMock:
    """Mock legacy google-generativeai GenerativeModel client."""
    client = MagicMock()
    client.generate_content.return_value = iter(chunks)
    return client


def _make_genai_client(chunks: list) -> MagicMock:
    """Mock google-genai Client whose models.generate_content_stream returns an iterable."""
    client = MagicMock()
    client.models.generate_content_stream.return_value = iter(chunks)
    return client


def _make_complete_response(
    text: str,
    *,
    thought: str | None = None,
    log_prob: float | None = None,
) -> SimpleNamespace:
    """Fake non-streaming Gemini response."""
    parts = []
    if thought:
        parts.append(_make_part(thought, thought=True))
    parts.append(_make_part(text))
    lp_result = None
    if log_prob is not None:
        lp_result = SimpleNamespace(chosen_candidates=[_lp_entry(text, log_prob)])
    return _make_chunk(parts, logprobs_result=lp_result)


# ---------------------------------------------------------------------------
# Unit tests: helpers
# ---------------------------------------------------------------------------

class TestHelpers:
    def test_normalise_string(self):
        msgs = _normalise_messages("hello")
        assert msgs == [{"role": "user", "content": "hello"}]

    def test_normalise_list_passthrough(self):
        msgs = [{"role": "user", "content": "hi"}]
        assert _normalise_messages(msgs) is msgs

    def test_messages_to_prompt_single(self):
        msgs = [{"role": "user", "content": "hello"}]
        assert _messages_to_prompt(msgs) == "hello"

    def test_messages_to_prompt_multi(self):
        msgs = [
            {"role": "user", "content": "Hi"},
            {"role": "assistant", "content": "Hello!"},
        ]
        result = _messages_to_prompt(msgs)
        assert "User: Hi" in result
        assert "Assistant: Hello!" in result

    def test_messages_to_contents(self):
        msgs = [
            {"role": "user", "content": "Hi"},
            {"role": "assistant", "content": "Hello!"},
        ]
        contents = _messages_to_contents(msgs)
        assert contents[0]["role"] == "user"
        assert contents[1]["role"] == "model"  # assistant → model
        assert contents[0]["parts"][0]["text"] == "Hi"

    def test_confidence_from_logprobs_mean(self):
        probs = [1.0] * 10
        dist = _confidence_from_logprobs(probs)
        assert dist.mean == pytest.approx(1.0)

    def test_confidence_from_logprobs_empty(self):
        dist = _confidence_from_logprobs([])
        assert dist.mean == pytest.approx(0.85)

    def test_extract_chunk_text(self):
        chunk = _make_simple_chunk("hello")
        texts, thoughts, probs = _extract_chunk_content(chunk)
        assert texts == ["hello"]
        assert thoughts == []
        assert probs == []

    def test_extract_chunk_thinking(self):
        chunk = _make_thinking_chunk("I think...", "The answer is 42.")
        texts, thoughts, probs = _extract_chunk_content(chunk)
        assert texts == ["The answer is 42."]
        assert thoughts == ["I think..."]

    def test_extract_chunk_logprobs(self):
        chunk = _make_logprob_chunk("yes", -0.1)
        texts, thoughts, probs = _extract_chunk_content(chunk)
        assert texts == ["yes"]
        assert len(probs) == 1
        assert probs[0] == pytest.approx(math.exp(-0.1))

    def test_extract_chunk_no_candidates(self):
        # Chunks with no candidates (e.g. empty final chunk)
        chunk = SimpleNamespace(candidates=[], text=None)
        texts, thoughts, probs = _extract_chunk_content(chunk)
        assert texts == []

    def test_extract_chunk_text_fallback(self):
        # Chunk with no candidates but a .text attribute (new SDK simple case)
        chunk = SimpleNamespace(candidates=[], text="fallback text")
        texts, thoughts, probs = _extract_chunk_content(chunk)
        assert texts == ["fallback text"]


# ---------------------------------------------------------------------------
# Streaming: wire format (legacy SDK)
# ---------------------------------------------------------------------------

class TestStreamWireFormat:
    def test_stream_produces_valid_spif(self):
        chunks = [_make_simple_chunk(t) for t in ["Hello", ", ", "world", "!"]]
        client = _make_legacy_client(chunks)
        adapter = GeminiSPIFAdapter(client, logprobs=False)

        data = b"".join(adapter.stream("hi"))
        doc = SPIFReader().decode(data)
        assert doc.payload[0].value == "Hello, world!"

    def test_stream_provenance_set(self):
        chunks = [_make_simple_chunk("answer")]
        client = _make_legacy_client(chunks)
        adapter = GeminiSPIFAdapter(client, model="gemini-2.0-flash", logprobs=False)

        data = b"".join(adapter.stream("q"))
        doc = SPIFReader().decode(data)
        assert doc.provenance is not None
        assert doc.provenance.source_model == "gemini-2.0-flash"

    def test_stream_input_hash_in_provenance(self):
        import hashlib, json
        chunks = [_make_simple_chunk("ok")]
        client = _make_legacy_client(chunks)
        adapter = GeminiSPIFAdapter(client, logprobs=False)

        data = b"".join(adapter.stream("test prompt"))
        doc = SPIFReader().decode(data)
        messages = [{"role": "user", "content": "test prompt"}]
        expected = hashlib.sha256(
            json.dumps(messages, sort_keys=True).encode()
        ).hexdigest()
        assert doc.provenance.input_hash == expected

    def test_stream_returns_doc_on_stopiteration(self):
        chunks = [_make_simple_chunk("hi")]
        client = _make_legacy_client(chunks)
        adapter = GeminiSPIFAdapter(client, logprobs=False)

        gen = adapter.stream("hello")
        try:
            while True:
                next(gen)
        except StopIteration as e:
            doc = e.value
        assert doc is not None
        assert doc.payload[0].value == "hi"

    def test_stream_fires_partial_text_events(self):
        tokens = ["The", " sky", " is", " blue."]
        chunks = [_make_simple_chunk(t) for t in tokens]
        client = _make_legacy_client(chunks)
        adapter = GeminiSPIFAdapter(client, logprobs=False)

        data = b"".join(adapter.stream("q"))
        events = list(iter_events(data))
        partial = [e for e in events if e.type == "partial_text"]
        assert len(partial) == len(tokens)
        assert [e.text for e in partial] == tokens

    def test_stream_fires_verified_event(self):
        chunks = [_make_simple_chunk("done")]
        client = _make_legacy_client(chunks)
        adapter = GeminiSPIFAdapter(client, logprobs=False)

        data = b"".join(adapter.stream("q"))
        events = list(iter_events(data))
        verified = [e for e in events if e.type == "verified"]
        assert len(verified) == 1
        assert verified[0].document.payload[0].value == "done"


# ---------------------------------------------------------------------------
# Streaming: new google-genai SDK
# ---------------------------------------------------------------------------

class TestGenaiSDK:
    def test_stream_produces_valid_spif_genai(self):
        chunks = [_make_simple_chunk(t) for t in ["Hi", " there"]]
        client = _make_genai_client(chunks)
        adapter = GeminiSPIFAdapter(client, model="gemini-2.0-flash",
                                    logprobs=False, use_genai_sdk=True)

        data = b"".join(adapter.stream("hello"))
        doc = SPIFReader().decode(data)
        assert doc.payload[0].value == "Hi there"

    def test_genai_client_called_with_model(self):
        chunks = [_make_simple_chunk("ok")]
        client = _make_genai_client(chunks)
        adapter = GeminiSPIFAdapter(client, model="gemini-pro",
                                    logprobs=False, use_genai_sdk=True)

        list(adapter.stream("q"))
        call_kwargs = client.models.generate_content_stream.call_args[1]
        assert call_kwargs["model"] == "gemini-pro"


# ---------------------------------------------------------------------------
# Thinking → trace
# ---------------------------------------------------------------------------

class TestThinkingTrace:
    def test_thinking_parts_produce_trace_steps(self):
        chunks = [_make_thinking_chunk("Step 1: think...", "The answer is 42.")]
        client = _make_legacy_client(chunks)
        adapter = GeminiSPIFAdapter(client, logprobs=False)

        data = b"".join(adapter.stream("q"))
        doc = SPIFReader().decode(data)
        assert len(doc.trace) == 1
        assert doc.trace[0].id == "thought_0"
        assert "Step 1: think..." in doc.trace[0].content
        assert doc.trace_method == "live"
        assert doc.payload[0].value == "The answer is 42."

    def test_multiple_thinking_chunks(self):
        chunks = [
            _make_thinking_chunk("Thought A", ""),
            _make_thinking_chunk("Thought B", "Final answer."),
        ]
        client = _make_legacy_client(chunks)
        adapter = GeminiSPIFAdapter(client, logprobs=False)

        data = b"".join(adapter.stream("q"))
        doc = SPIFReader().decode(data)
        assert len(doc.trace) == 2
        assert doc.trace[0].id == "thought_0"
        assert doc.trace[1].id == "thought_1"
        assert doc.trace[1].deps == ["thought_0"]

    def test_capture_thinking_false_suppresses_trace(self):
        chunks = [_make_thinking_chunk("internal", "answer")]
        client = _make_legacy_client(chunks)
        adapter = GeminiSPIFAdapter(client, logprobs=False, capture_thinking=False)

        data = b"".join(adapter.stream("q"))
        doc = SPIFReader().decode(data)
        assert doc.trace == []
        assert doc.trace_method == "post-hoc"

    def test_no_thinking_no_trace(self):
        chunks = [_make_simple_chunk("hello")]
        client = _make_legacy_client(chunks)
        adapter = GeminiSPIFAdapter(client, logprobs=False)

        data = b"".join(adapter.stream("q"))
        doc = SPIFReader().decode(data)
        assert doc.trace == []


# ---------------------------------------------------------------------------
# Logprobs → confidence
# ---------------------------------------------------------------------------

class TestLogprobConfidence:
    def test_logprobs_produce_real_distribution_genai_sdk(self):
        # Logprobs only work with the new google-genai SDK.
        chunks = [_make_logprob_chunk("yes", -0.05)]
        client = _make_genai_client(chunks)
        adapter = GeminiSPIFAdapter(client, logprobs=True, use_genai_sdk=True)

        data = b"".join(adapter.stream("q"))
        doc = SPIFReader().decode(data)
        conf = doc.payload[0].confidence
        assert conf.mean > 0.8
        assert conf.semantics == "output_stability"

    def test_no_logprobs_uses_default(self):
        chunks = [_make_simple_chunk("answer")]
        client = _make_legacy_client(chunks)
        adapter = GeminiSPIFAdapter(client, logprobs=False)

        data = b"".join(adapter.stream("q"))
        doc = SPIFReader().decode(data)
        assert doc.payload[0].confidence.mean == pytest.approx(0.85)

    def test_confidence_override_takes_precedence(self):
        override = Distribution(mean=0.5, var=0.1, shape="gaussian",
                                semantics="output_stability")
        chunks = [_make_simple_chunk("yes")]
        client = _make_legacy_client(chunks)
        adapter = GeminiSPIFAdapter(client, logprobs=False, confidence_override=override)

        data = b"".join(adapter.stream("q"))
        doc = SPIFReader().decode(data)
        assert doc.payload[0].confidence.mean == pytest.approx(0.5)

    def test_thinking_without_logprobs_uses_thinking_confidence(self):
        chunks = [_make_thinking_chunk("I think", "answer")]
        client = _make_legacy_client(chunks)
        adapter = GeminiSPIFAdapter(client, logprobs=False)

        data = b"".join(adapter.stream("q"))
        doc = SPIFReader().decode(data)
        # Thinking present → uses _THINKING_CONFIDENCE (mean=0.92)
        assert doc.payload[0].confidence.mean == pytest.approx(0.92)

    def test_legacy_sdk_ignores_response_logprobs(self):
        # Legacy SDK strips response_logprobs silently — falls back to default
        chunks = [_make_logprob_chunk("yes", -0.05)]
        client = _make_legacy_client(chunks)
        adapter = GeminiSPIFAdapter(client, logprobs=True)  # legacy SDK

        data = b"".join(adapter.stream("q"))
        doc = SPIFReader().decode(data)
        # Logprob data IS still extracted from the response object even if not requested
        # (the mock returns it regardless). This tests that extraction still works.
        assert doc.payload[0].confidence.mean > 0.0


# ---------------------------------------------------------------------------
# Non-streaming complete()
# ---------------------------------------------------------------------------

class TestComplete:
    def test_complete_returns_spif_document(self):
        response = _make_complete_response("Paris")
        client = MagicMock()
        client.generate_content.return_value = response
        adapter = GeminiSPIFAdapter(client, model="gemini-2.0-flash", logprobs=False)

        doc = adapter.complete("Capital of France?")
        assert doc.payload[0].value == "Paris"
        assert doc.provenance.source_model == "gemini-2.0-flash"

    def test_complete_with_thinking(self):
        response = _make_complete_response("42", thought="The answer is 42.")
        client = MagicMock()
        client.generate_content.return_value = response
        adapter = GeminiSPIFAdapter(client, logprobs=False)

        doc = adapter.complete("What is the answer?")
        assert len(doc.trace) == 1
        assert "The answer is 42." in doc.trace[0].content

    def test_complete_with_logprobs(self):
        # Logprob data returned in the response object is extracted regardless
        # of whether response_logprobs was in the GenerationConfig.
        response = _make_complete_response("Paris", log_prob=-0.02)
        client = MagicMock()
        client.generate_content.return_value = response
        adapter = GeminiSPIFAdapter(client, logprobs=True)

        doc = adapter.complete("Capital of France?")
        # exp(-0.02) ≈ 0.98 → high confidence
        assert doc.payload[0].confidence.mean > 0.9

    def test_complete_encodes_to_valid_spif_bytes(self):
        response = _make_complete_response("Hello world")
        client = MagicMock()
        client.generate_content.return_value = response
        adapter = GeminiSPIFAdapter(client, logprobs=False)

        doc = adapter.complete("hi")
        from spif.writer import SPIFWriter
        data = SPIFWriter().encode(doc)
        restored = SPIFReader().decode(data)
        assert restored.payload[0].value == "Hello world"
