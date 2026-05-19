"""
Tests for OpenAISPIFAdapter.

All tests run offline — no API key required.  The OpenAI client is replaced
with a minimal mock that emits pre-canned streaming chunks or a complete
response object.
"""

from __future__ import annotations

import math
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from spfx.adapters.openai_adapter import (
    OpenAISPIFAdapter,
    _confidence_from_logprobs,
    _normalise_messages,
)
from spfx.reader import SPIFReader
from spfx.streaming import SPIFStreamReader, iter_events
from spfx.types import Distribution


# ---------------------------------------------------------------------------
# Helpers: minimal OpenAI response objects
# ---------------------------------------------------------------------------

def _lp(token: str, logprob: float) -> SimpleNamespace:
    """Fake logprob entry."""
    return SimpleNamespace(token=token, logprob=logprob)


def _chunk(
    content: str | None = None,
    model: str = "gpt-4o",
    logprobs: list | None = None,
    usage: Any = None,
    finish_reason: str | None = None,
) -> SimpleNamespace:
    """Fake streaming chunk."""
    delta = SimpleNamespace(content=content)
    lp = SimpleNamespace(content=logprobs) if logprobs is not None else None
    choice = SimpleNamespace(delta=delta, logprobs=lp, finish_reason=finish_reason)
    return SimpleNamespace(model=model, choices=[choice], usage=usage)


def _usage(completion_tokens: int = 10, reasoning_tokens: int = 0) -> SimpleNamespace:
    details = SimpleNamespace(reasoning_tokens=reasoning_tokens)
    return SimpleNamespace(
        completion_tokens=completion_tokens,
        completion_tokens_details=details,
    )


def _make_stream(tokens: list[str], *, model: str = "gpt-4o",
                 with_logprobs: bool = False,
                 reasoning_tokens: int = 0) -> list[SimpleNamespace]:
    """Build a list of streaming chunks that mimics OpenAI's output."""
    chunks = []
    for tok in tokens:
        lps = [_lp(tok, -0.1)] if with_logprobs else None
        chunks.append(_chunk(content=tok, model=model, logprobs=lps))
    # Final chunk: no content, carries usage
    chunks.append(_chunk(content=None, model=model,
                         usage=_usage(len(tokens), reasoning_tokens),
                         finish_reason="stop"))
    return chunks


def _make_client(chunks: list) -> MagicMock:
    """Mock OpenAI client whose chat.completions.create returns an iterable."""
    client = MagicMock()
    client.chat.completions.create.return_value = iter(chunks)
    return client


def _make_complete_response(
    text: str,
    model: str = "gpt-4o",
    logprobs: list | None = None,
    reasoning_tokens: int = 0,
) -> SimpleNamespace:
    """Fake non-streaming response."""
    lp = SimpleNamespace(content=logprobs) if logprobs is not None else None
    message = SimpleNamespace(content=text)
    choice = SimpleNamespace(message=message, logprobs=lp)
    return SimpleNamespace(
        model=model,
        choices=[choice],
        usage=_usage(reasoning_tokens=reasoning_tokens),
    )


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

    def test_confidence_from_logprobs_mean(self):
        # All tokens with logprob = 0.0 → prob = 1.0
        probs = [1.0] * 10
        dist = _confidence_from_logprobs(probs)
        assert dist.mean == pytest.approx(1.0)
        assert dist.var == pytest.approx(0.0)

    def test_confidence_from_logprobs_mixed(self):
        probs = [math.exp(-0.1), math.exp(-0.5), math.exp(-2.0)]
        dist = _confidence_from_logprobs(probs)
        assert 0.0 < dist.mean < 1.0
        assert dist.var >= 0.0

    def test_confidence_from_logprobs_empty(self):
        dist = _confidence_from_logprobs([])
        assert dist.mean == pytest.approx(0.85)

    def test_confidence_clamped_to_valid_range(self):
        # Even if probs > 1.0 due to floating point, mean is clamped
        dist = _confidence_from_logprobs([1.5, 2.0])
        assert dist.mean <= 1.0
        assert dist.mean >= 0.0


# ---------------------------------------------------------------------------
# Streaming: wire format
# ---------------------------------------------------------------------------

class TestStreamWireFormat:
    def test_stream_produces_valid_spif(self):
        tokens = ["Hello", ", ", "world", "!"]
        client = _make_client(_make_stream(tokens))
        adapter = OpenAISPIFAdapter(client, logprobs=False)

        chunks = list(adapter.stream("hi"))
        data = b"".join(chunks)
        doc = SPIFReader().decode(data)
        assert doc.payload[0].value == "Hello, world!"

    def test_stream_provenance_set(self):
        # Provenance records the *requested* model, not the server-resolved model.
        # The PROVENANCE chunk is written in open() before any chunk arrives,
        # so mid-stream model resolution cannot update it.
        tokens = ["answer"]
        client = _make_client(_make_stream(tokens, model="gpt-4o-mini"))
        adapter = OpenAISPIFAdapter(client, model="gpt-4o", logprobs=False)

        data = b"".join(adapter.stream("q"))
        doc = SPIFReader().decode(data)
        assert doc.provenance is not None
        assert doc.provenance.source_model == "gpt-4o"

    def test_stream_input_hash_in_provenance(self):
        import hashlib, json
        tokens = ["ok"]
        client = _make_client(_make_stream(tokens))
        adapter = OpenAISPIFAdapter(client, logprobs=False)

        data = b"".join(adapter.stream("test prompt"))
        doc = SPIFReader().decode(data)
        messages = [{"role": "user", "content": "test prompt"}]
        expected_hash = hashlib.sha256(
            json.dumps(messages, sort_keys=True).encode()
        ).hexdigest()
        assert doc.provenance.input_hash == expected_hash

    def test_stream_returns_doc_on_stopiteration(self):
        tokens = ["hi"]
        client = _make_client(_make_stream(tokens))
        adapter = OpenAISPIFAdapter(client, logprobs=False)

        gen = adapter.stream("hello")
        try:
            while True:
                next(gen)
        except StopIteration as e:
            doc = e.value
        assert doc is not None
        assert doc.payload[0].value == "hi"

    def test_stream_reader_fires_partial_text_events(self):
        tokens = ["The", " sky", " is", " blue."]
        client = _make_client(_make_stream(tokens))
        adapter = OpenAISPIFAdapter(client, logprobs=False)

        data = b"".join(adapter.stream("q"))
        events = list(iter_events(data))
        partial = [e for e in events if e.type == "partial_text"]
        assert len(partial) == len(tokens)
        assert [e.text for e in partial] == tokens

    def test_stream_reader_fires_verified_event(self):
        tokens = ["done"]
        client = _make_client(_make_stream(tokens))
        adapter = OpenAISPIFAdapter(client, logprobs=False)

        data = b"".join(adapter.stream("q"))
        events = list(iter_events(data))
        verified = [e for e in events if e.type == "verified"]
        assert len(verified) == 1
        assert verified[0].document.payload[0].value == "done"


# ---------------------------------------------------------------------------
# Logprobs → confidence
# ---------------------------------------------------------------------------

class TestLogprobConfidence:
    def test_logprobs_produce_real_distribution(self):
        tokens = ["yes", " definitely"]
        # logprob = -0.05 → high confidence
        chunks = _make_stream(tokens, with_logprobs=True)
        client = _make_client(chunks)
        adapter = OpenAISPIFAdapter(client, logprobs=True)

        data = b"".join(adapter.stream("q"))
        doc = SPIFReader().decode(data)
        conf = doc.payload[0].confidence
        # exp(-0.1) ≈ 0.905
        assert conf.mean > 0.8
        assert conf.semantics == "output_stability"

    def test_no_logprobs_uses_default(self):
        tokens = ["answer"]
        client = _make_client(_make_stream(tokens, with_logprobs=False))
        adapter = OpenAISPIFAdapter(client, logprobs=False)

        data = b"".join(adapter.stream("q"))
        doc = SPIFReader().decode(data)
        assert doc.payload[0].confidence.mean == pytest.approx(0.85)

    def test_confidence_override_ignores_logprobs(self):
        override = Distribution(mean=0.5, var=0.1, shape="gaussian",
                                semantics="output_stability")
        tokens = ["yes"]
        chunks = _make_stream(tokens, with_logprobs=True)
        client = _make_client(chunks)
        adapter = OpenAISPIFAdapter(client, logprobs=True,
                                    confidence_override=override)

        data = b"".join(adapter.stream("q"))
        doc = SPIFReader().decode(data)
        assert doc.payload[0].confidence.mean == pytest.approx(0.5)


# ---------------------------------------------------------------------------
# Reasoning tokens → trace
# ---------------------------------------------------------------------------

class TestReasoningTrace:
    def test_reasoning_tokens_produce_trace_step(self):
        tokens = ["42"]
        chunks = _make_stream(tokens, reasoning_tokens=150)
        client = _make_client(chunks)
        adapter = OpenAISPIFAdapter(client, logprobs=False)

        data = b"".join(adapter.stream("what is 6*7?"))
        doc = SPIFReader().decode(data)
        assert len(doc.trace) == 1
        assert doc.trace[0].id == "reasoning"
        assert "150" in doc.trace[0].content
        assert doc.trace_method == "live"

    def test_no_reasoning_tokens_no_trace(self):
        tokens = ["hello"]
        chunks = _make_stream(tokens, reasoning_tokens=0)
        client = _make_client(chunks)
        adapter = OpenAISPIFAdapter(client, logprobs=False)

        data = b"".join(adapter.stream("hi"))
        doc = SPIFReader().decode(data)
        assert doc.trace == []
        assert doc.trace_method == "post-hoc"

    def test_capture_reasoning_false_suppresses_trace(self):
        tokens = ["ok"]
        chunks = _make_stream(tokens, reasoning_tokens=500)
        client = _make_client(chunks)
        adapter = OpenAISPIFAdapter(client, logprobs=False, capture_reasoning=False)

        data = b"".join(adapter.stream("q"))
        doc = SPIFReader().decode(data)
        assert doc.trace == []


# ---------------------------------------------------------------------------
# Non-streaming complete()
# ---------------------------------------------------------------------------

class TestComplete:
    def test_complete_returns_spif_document(self):
        response = _make_complete_response("Paris")
        client = MagicMock()
        client.chat.completions.create.return_value = response
        adapter = OpenAISPIFAdapter(client, logprobs=False)

        doc = adapter.complete("Capital of France?")
        assert doc.payload[0].value == "Paris"
        assert doc.provenance.source_model == "gpt-4o"

    def test_complete_with_logprobs(self):
        lps = [_lp("Paris", -0.02)]
        response = _make_complete_response("Paris", logprobs=lps)
        client = MagicMock()
        client.chat.completions.create.return_value = response
        adapter = OpenAISPIFAdapter(client, logprobs=True)

        doc = adapter.complete("Capital of France?")
        assert doc.payload[0].confidence.mean > 0.9  # exp(-0.02) ≈ 0.98

    def test_complete_reasoning_tokens_trace(self):
        response = _make_complete_response("The answer is 42.",
                                           reasoning_tokens=200)
        client = MagicMock()
        client.chat.completions.create.return_value = response
        adapter = OpenAISPIFAdapter(client, logprobs=False)

        doc = adapter.complete("What is the answer?")
        assert len(doc.trace) == 1
        assert "200" in doc.trace[0].content

    def test_complete_encodes_to_valid_spif_bytes(self):
        response = _make_complete_response("Hello world")
        client = MagicMock()
        client.chat.completions.create.return_value = response
        adapter = OpenAISPIFAdapter(client, logprobs=False)

        doc = adapter.complete("hi")
        from spfx.writer import SPIFWriter
        data = SPIFWriter().encode(doc)
        restored = SPIFReader().decode(data)
        assert restored.payload[0].value == "Hello world"


# ---------------------------------------------------------------------------
# Reasoning model detection
# ---------------------------------------------------------------------------

class TestReasoningModelDetection:
    @pytest.mark.parametrize("model", [
        "o1", "o1-mini", "o1-preview", "o3", "o3-mini", "o4-mini",
    ])
    def test_reasoning_models_detected(self, model):
        adapter = OpenAISPIFAdapter(MagicMock())
        assert adapter._is_reasoning_model(model)

    @pytest.mark.parametrize("model", [
        "gpt-4o", "gpt-4o-mini", "gpt-4-turbo", "gpt-3.5-turbo",
    ])
    def test_non_reasoning_models(self, model):
        adapter = OpenAISPIFAdapter(MagicMock())
        assert not adapter._is_reasoning_model(model)

    def test_reasoning_model_uses_max_completion_tokens(self):
        client = MagicMock()
        client.chat.completions.create.return_value = iter(
            _make_stream(["ok"], model="o1")
        )
        adapter = OpenAISPIFAdapter(client, model="o1", max_tokens=500,
                                    logprobs=False)
        list(adapter.stream("q"))
        call_kwargs = client.chat.completions.create.call_args[1]
        assert "max_completion_tokens" in call_kwargs
        assert "max_tokens" not in call_kwargs
        assert "temperature" not in call_kwargs

    def test_standard_model_uses_max_tokens(self):
        client = MagicMock()
        client.chat.completions.create.return_value = iter(
            _make_stream(["ok"])
        )
        adapter = OpenAISPIFAdapter(client, logprobs=False)
        list(adapter.stream("q"))
        call_kwargs = client.chat.completions.create.call_args[1]
        assert "max_tokens" in call_kwargs
        assert "temperature" in call_kwargs
