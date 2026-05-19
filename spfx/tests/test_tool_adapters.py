"""Tests for tool call support in Anthropic and OpenAI adapters, and claude_to_sif."""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any
import pytest

from spfx import SPIFDocument, Node, Distribution, Provenance
from spfx.format import NODE_TEXT, NODE_TOOL_CALL, NODE_TOOL_RESULT
from spfx.adapters.anthropic_adapter import AnthropicSPIFAdapter, _execute_tools
from spfx.adapters.openai_adapter import OpenAISPIFAdapter


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

    def create(self, **kwargs):
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
