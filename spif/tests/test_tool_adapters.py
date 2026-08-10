"""Tests for tool call support in Anthropic and OpenAI adapters, and claude_to_sif."""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any
import pytest

from spif import SPIFDocument, Node, Distribution, Provenance
from spif.format import NODE_TEXT, NODE_TOOL_CALL, NODE_TOOL_RESULT
from spif.adapters.anthropic_adapter import AnthropicSPIFAdapter, _execute_tools
from spif.adapters.openai_adapter import OpenAISPIFAdapter


# ---------------------------------------------------------------------------
# Minimal Anthropic mock
# ---------------------------------------------------------------------------

@dataclass
class _FakeBlock:
    type: str
    id: str = ""
    name: str = ""
    input: dict = field(default_factory=dict)
    text: str = ""
    tool_use_id: str = ""
    content: Any = ""
    is_error: bool = False


@dataclass
class _FakeMessage:
    model: str
    content: list
    stop_reason: str = "end_turn"


class _FakeAnthropicMessages:
    def __init__(self, response):
        self._response = response
        self.last_kwargs = None

    def create(self, **kwargs):
        self.last_kwargs = kwargs
        return self._response


class _FakeAnthropicClient:
    def __init__(self, response):
        self.messages = _FakeAnthropicMessages(response)


# ---------------------------------------------------------------------------
# Minimal OpenAI mock
# ---------------------------------------------------------------------------

@dataclass
class _FakeFunction:
    name: str
    arguments: str


@dataclass
class _FakeToolCall:
    id: str
    function: _FakeFunction
    type: str = "function"


@dataclass
class _FakeLogprobs:
    content: Any = None


@dataclass
class _FakeChoice:
    message: Any
    finish_reason: str = "stop"
    logprobs: Any = None


@dataclass
class _FakeOAIMessage:
    role: str
    content: str | None
    tool_calls: list | None = None


@dataclass
class _FakeOAIUsage:
    prompt_tokens: int = 10
    completion_tokens: int = 20


@dataclass
class _FakeOAIResponse:
    model: str
    choices: list
    usage: Any = field(default_factory=_FakeOAIUsage)


class _FakeOAICompletions:
    def __init__(self, response):
        self._response = response

    def create(self, **kwargs):
        return self._response


class _FakeOAIChat:
    def __init__(self, response):
        self.completions = _FakeOAICompletions(response)


class _FakeOAIClient:
    def __init__(self, response):
        self.chat = _FakeOAIChat(response)


# ---------------------------------------------------------------------------
# Anthropic adapter — tool call support
# ---------------------------------------------------------------------------

class TestAnthropicAdapterToolCalls:
    def _make_response_with_tool_call(self):
        blocks = [
            _FakeBlock(type="tool_use", id="tc_001", name="get_weather",
                       input={"city": "Paris"}),
            _FakeBlock(type="text", text="Fetching weather..."),
        ]
        return _FakeMessage(model="claude-sonnet-4-6", content=blocks)

    def test_complete_produces_tool_call_node(self):
        resp = self._make_response_with_tool_call()
        adapter = AnthropicSPIFAdapter(_FakeAnthropicClient(resp))
        doc = adapter.complete("What is the weather in Paris?")
        tool_calls = [n for n in doc.payload if n.type == NODE_TOOL_CALL]
        assert len(tool_calls) == 1
        assert tool_calls[0].value["name"] == "get_weather"
        assert tool_calls[0].value["arguments"] == {"city": "Paris"}
        assert tool_calls[0].value["call_id"] == "tc_001"

    def test_claude_5_omits_deprecated_temperature_parameter(self):
        response = _FakeMessage(
            model="claude-opus-5",
            content=[_FakeBlock(type="text", text="ok")],
        )
        client = _FakeAnthropicClient(response)
        adapter = AnthropicSPIFAdapter(client, model="claude-opus-5", temperature=0.2)

        doc = adapter.complete("Reply with exactly: OK")

        assert doc.provenance.source_model == "claude-opus-5"
        assert "temperature" not in client.messages.last_kwargs

    def test_future_claude_model_not_in_hardcoded_allowlist_still_gets_temperature(self):
        """BUG: _temperature_is_deprecated() hardcodes an exact allowlist of
        model prefixes ("claude-opus-5", "claude-sonnet-5", "claude-fable-5").
        A next-generation model name that doesn't match (e.g. "claude-opus-6")
        silently falls through as if temperature were still accepted — if the
        live API actually rejects it there, this raises a 400 in production
        with no adapter-level warning."""
        from spif.adapters.anthropic_adapter import _temperature_is_deprecated
        assert _temperature_is_deprecated("claude-opus-6") is False

        response = _FakeMessage(model="claude-opus-6", content=[_FakeBlock(type="text", text="ok")])
        client = _FakeAnthropicClient(response)
        adapter = AnthropicSPIFAdapter(client, model="claude-opus-6", temperature=0.2)
        adapter.complete("test")
        assert "temperature" in client.messages.last_kwargs  # unverified assumption

    def test_complete_pending_when_no_executor(self):
        resp = self._make_response_with_tool_call()
        adapter = AnthropicSPIFAdapter(_FakeAnthropicClient(resp))
        doc = adapter.complete("What is the weather?")
        assert doc.pending_tool_results is True

    def test_complete_with_executor_adds_result_nodes(self):
        resp = self._make_response_with_tool_call()

        def executor(name, args):
            return {"temp": 22, "unit": "C"}

        adapter = AnthropicSPIFAdapter(_FakeAnthropicClient(resp), tool_executor=executor)
        doc = adapter.complete("What is the weather?")
        result_nodes = [n for n in doc.payload if n.type == NODE_TOOL_RESULT]
        assert len(result_nodes) == 1
        assert result_nodes[0].value["call_id"] == "tc_001"
        assert result_nodes[0].value["is_error"] is False
        assert result_nodes[0].value["content"] == {"temp": 22, "unit": "C"}
        assert doc.pending_tool_results is False

    def test_complete_executor_exception_sets_is_error(self):
        resp = self._make_response_with_tool_call()

        def failing_executor(name, args):
            raise ValueError("API rate limit exceeded")

        adapter = AnthropicSPIFAdapter(_FakeAnthropicClient(resp), tool_executor=failing_executor)
        doc = adapter.complete("What is the weather?")
        result_nodes = [n for n in doc.payload if n.type == NODE_TOOL_RESULT]
        assert len(result_nodes) == 1
        assert result_nodes[0].value["is_error"] is True
        assert result_nodes[0].value["error_type"] == "ValueError"

    def test_complete_executor_records_latency_ms(self):
        resp = self._make_response_with_tool_call()

        def executor(name, args):
            return "ok"

        adapter = AnthropicSPIFAdapter(_FakeAnthropicClient(resp), tool_executor=executor)
        doc = adapter.complete("test")
        result_nodes = [n for n in doc.payload if n.type == NODE_TOOL_RESULT]
        assert "latency_ms" in result_nodes[0].value
        assert result_nodes[0].value["latency_ms"] >= 0

    def test_complete_no_tools_no_pending(self):
        """Text-only response must not set pending_tool_results."""
        blocks = [_FakeBlock(type="text", text="Hello world")]
        resp = _FakeMessage(model="claude-sonnet-4-6", content=blocks)
        adapter = AnthropicSPIFAdapter(_FakeAnthropicClient(resp))
        doc = adapter.complete("Say hello")
        assert doc.pending_tool_results is False
        assert all(n.type == NODE_TEXT for n in doc.payload)

    def test_duplicate_vendor_tool_call_ids_not_caught_by_adapter(self):
        """BUG: _build_tool_call_node() assumes block.id is unique within a
        response and builds Node.id = f"tool_call_{block.id}" directly with
        no dedup/validation. Two tool_use blocks sharing an id (a vendor SDK
        bug, or a mocked/replayed response) produce duplicate Node ids in
        doc.payload — the adapter doesn't catch it; it only surfaces much
        later as SPIFFormatError on decode after a write/read round trip."""
        from spif import SPIFWriter, SPIFReader
        from spif.reader import SPIFFormatError

        blocks = [
            _FakeBlock(type="tool_use", id="dup", name="get_weather", input={"city": "Paris"}),
            _FakeBlock(type="tool_use", id="dup", name="get_time", input={"city": "Paris"}),
        ]
        resp = _FakeMessage(model="claude-sonnet-4-6", content=blocks)
        adapter = AnthropicSPIFAdapter(_FakeAnthropicClient(resp))
        doc = adapter.complete("weather and time in Paris?")

        tool_call_ids = [n.id for n in doc.payload if n.type == NODE_TOOL_CALL]
        assert tool_call_ids == ["tool_call_dup", "tool_call_dup"]  # adapter let it through

        with pytest.raises(SPIFFormatError, match="Duplicate Node id"):
            SPIFReader().decode(SPIFWriter().encode(doc))

    def test_tool_call_nodes_precede_text_nodes(self):
        """Tool interaction sequence: tool_call, tool_result, then text."""
        resp = self._make_response_with_tool_call()

        def executor(name, args):
            return "sunny"

        adapter = AnthropicSPIFAdapter(_FakeAnthropicClient(resp), tool_executor=executor)
        doc = adapter.complete("Weather?")
        types = [n.type for n in doc.payload]
        tc_idx = types.index(NODE_TOOL_CALL)
        tr_idx = types.index(NODE_TOOL_RESULT)
        # Text node (if present) comes after tool nodes
        text_idxs = [i for i, t in enumerate(types) if t == NODE_TEXT]
        if text_idxs:
            assert tc_idx < text_idxs[0]
            assert tr_idx < text_idxs[0]


# ---------------------------------------------------------------------------
# OpenAI adapter — tool call support
# ---------------------------------------------------------------------------

class TestOpenAIAdapterToolCalls:
    def _make_oai_response_with_tool_call(self):
        tool_calls = [
            _FakeToolCall(id="call_abc", function=_FakeFunction(
                name="search_docs",
                arguments='{"query": "SPIF format"}'
            ))
        ]
        msg = _FakeOAIMessage(role="assistant", content=None, tool_calls=tool_calls)
        choice = _FakeChoice(message=msg, finish_reason="tool_calls")
        return _FakeOAIResponse(model="gpt-4o", choices=[choice])

    def test_complete_produces_tool_call_node(self):
        resp = self._make_oai_response_with_tool_call()
        adapter = OpenAISPIFAdapter(_FakeOAIClient(resp))
        doc = adapter.complete("Search for SPIF docs")
        tool_calls = [n for n in doc.payload if n.type == NODE_TOOL_CALL]
        assert len(tool_calls) == 1
        assert tool_calls[0].value["name"] == "search_docs"
        assert tool_calls[0].value["arguments"] == {"query": "SPIF format"}
        assert tool_calls[0].value["call_id"] == "call_abc"

    def test_complete_pending_when_no_executor(self):
        resp = self._make_oai_response_with_tool_call()
        adapter = OpenAISPIFAdapter(_FakeOAIClient(resp))
        doc = adapter.complete("Search")
        assert doc.pending_tool_results is True

    def test_future_reasoning_model_not_in_heuristic_misdetected(self):
        """BUG: _is_reasoning_model() hardcodes {"o1","o3","o4"} plus a
        _REASONING_MODEL_PREFIXES=("gpt-5.6",) allowlist. A next-generation
        reasoning model like "o5-preview" doesn't match either check, so it's
        silently treated as a non-reasoning model — sending max_tokens instead
        of max_completion_tokens, which the live API rejects for o-series-style
        models."""
        adapter = OpenAISPIFAdapter(_FakeOAIClient(_FakeOAIResponse(model="o5-preview", choices=[])))
        assert adapter._is_reasoning_model("o5-preview") is False  # unverified assumption

    def test_complete_with_executor(self):
        resp = self._make_oai_response_with_tool_call()

        def executor(name, args):
            return ["result1", "result2"]

        adapter = OpenAISPIFAdapter(_FakeOAIClient(resp), tool_executor=executor)
        doc = adapter.complete("Search")
        result_nodes = [n for n in doc.payload if n.type == NODE_TOOL_RESULT]
        assert len(result_nodes) == 1
        assert result_nodes[0].value["is_error"] is False
        assert result_nodes[0].value["content"] == ["result1", "result2"]

    def test_complete_executor_exception_sets_is_error(self):
        resp = self._make_oai_response_with_tool_call()

        def failing_executor(name, args):
            raise TimeoutError("request timed out")

        adapter = OpenAISPIFAdapter(_FakeOAIClient(resp), tool_executor=failing_executor)
        doc = adapter.complete("Search")
        result_nodes = [n for n in doc.payload if n.type == NODE_TOOL_RESULT]
        assert result_nodes[0].value["is_error"] is True
        assert result_nodes[0].value["error_type"] == "TimeoutError"

    def test_logprobs_none_does_not_crash(self):
        """Regression: logprobs=None path must not raise AttributeError."""
        msg = _FakeOAIMessage(role="assistant", content="Hello", tool_calls=None)
        choice = _FakeChoice(message=msg, finish_reason="stop", logprobs=None)
        resp = _FakeOAIResponse(model="gpt-4o", choices=[choice])
        adapter = OpenAISPIFAdapter(_FakeOAIClient(resp))
        doc = adapter.complete("Say hello")
        assert any(n.type == NODE_TEXT for n in doc.payload)

    def test_logprobs_content_none_does_not_crash(self):
        """Regression: logprobs.content=None path must not raise."""
        msg = _FakeOAIMessage(role="assistant", content="Hi", tool_calls=None)
        choice = _FakeChoice(message=msg, finish_reason="stop",
                             logprobs=_FakeLogprobs(content=None))
        resp = _FakeOAIResponse(model="gpt-4o", choices=[choice])
        adapter = OpenAISPIFAdapter(_FakeOAIClient(resp))
        doc = adapter.complete("Hi")
        # Falls back to default confidence
        assert doc.payload[0].confidence.mean > 0


# ---------------------------------------------------------------------------
# _execute_tools unit tests
# ---------------------------------------------------------------------------

class TestExecuteTools:
    def _tc_node(self, name="tool", call_id="c1", args=None):
        return Node(
            id=f"tool_call_{call_id}",
            type=NODE_TOOL_CALL,
            value={"name": name, "arguments": args or {}, "call_id": call_id},
            confidence=Distribution(mean=0.9, var=0.05),
        )

    def test_success(self):
        nodes = _execute_tools([self._tc_node()], lambda n, a: "ok",
                               Distribution(mean=0.9, var=0.05))
        assert len(nodes) == 1
        assert nodes[0].type == NODE_TOOL_RESULT
        assert nodes[0].value["is_error"] is False
        assert nodes[0].value["content"] == "ok"

    def test_exception_captured(self):
        def boom(n, a): raise RuntimeError("boom")
        nodes = _execute_tools([self._tc_node()], boom,
                               Distribution(mean=0.9, var=0.05))
        assert nodes[0].value["is_error"] is True
        assert nodes[0].value["error_type"] == "RuntimeError"
        assert "boom" in nodes[0].value["content"]

    def test_latency_recorded(self):
        nodes = _execute_tools([self._tc_node()], lambda n, a: None,
                               Distribution(mean=0.9, var=0.05))
        assert nodes[0].value["latency_ms"] >= 0

    def test_call_id_forwarded(self):
        nodes = _execute_tools([self._tc_node(call_id="xyz999")],
                               lambda n, a: "result",
                               Distribution(mean=0.9, var=0.05))
        assert nodes[0].value["call_id"] == "xyz999"
