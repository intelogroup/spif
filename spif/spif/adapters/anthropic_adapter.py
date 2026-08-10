"""
Anthropic → SIF adapter.

Converts a Claude API streaming response into a streaming SIF byte sequence,
or a complete response into a SPIFDocument.

Usage — synchronous streaming generator:

    from anthropic import Anthropic
    from spif.adapters.anthropic_adapter import AnthropicSPIFAdapter

    client = Anthropic()
    adapter = AnthropicSPIFAdapter(client)

    # Yields raw SIF bytes as they are produced.
    # Pipe to a file, websocket, HTTP chunked response, etc.
    for chunk in adapter.stream("Explain quantum entanglement in one sentence."):
        sys.stdout.buffer.write(chunk)

Usage — async:

    async for chunk in adapter.astream("..."):
        await websocket.send(chunk)

Usage — complete (no streaming, returns a SPIFDocument):

    doc = adapter.complete("What is 2+2?")

Provenance mapping
──────────────────
  source_model   ← response.model
  model_version  ← response.model (Anthropic embeds date in model ID)
  temperature    ← passed by caller (API default = 1.0 if omitted)
  input_hash     ← SHA-256 of the serialised messages list
  timestamp_ms   ← measured locally at response start
  context_ref    ← "" (no prior SIF state by default; pass explicitly)

Confidence
──────────
Anthropic does not expose per-token logprobs in the standard API.
The adapter sets a conservative default Distribution(mean=0.85, var=0.05,
shape="gaussian", semantics="output_stability") on every output node.
When extended thinking is enabled, the thinking budget is used to set a
slightly higher mean (0.92) reflecting the extra compute.
Pass `confidence_override=Distribution(...)` to set your own.
"""

from __future__ import annotations

import time
from collections.abc import Generator, AsyncGenerator
from typing import Any

import time as _time_mod
from typing import Callable
from ._common import input_hash as _input_hash, build_provenance as _build_provenance
from ..format import NODE_TEXT, NODE_TOOL_CALL, NODE_TOOL_RESULT
from ..reader import SPIFFormatError
from ..streaming import SPIFStreamWriter
from ..types import (
    Distribution, Node, Provenance, SPIFDocument, TraceStep,
)
from ..writer import SPIFWriter

# The Anthropic API does not expose per-token logprobs — this default is an
# API constraint, not a design choice. This creates an asymmetry with
# openai_adapter.py, which computes real Distributions from logprobs when
# logprobs=True. Do not compare confidence values across providers without
# accounting for this: Anthropic values are a fixed prior, OpenAI values
# are empirical. See _confidence_from_logprobs() in openai_adapter.py.
_DEFAULT_CONFIDENCE = Distribution(
    mean=0.85,
    var=0.05,
    shape="gaussian",
    semantics="output_stability",
)

_THINKING_CONFIDENCE = Distribution(
    mean=0.92,
    var=0.03,
    shape="gaussian",
    semantics="output_stability",
)


def _temperature_is_deprecated(model: str) -> bool:
    """Return whether Anthropic rejects the temperature request parameter."""
    return model.startswith((
        "claude-opus-5",
        "claude-sonnet-5",
        "claude-fable-5",
    ))


def _set_temperature_if_supported(
    request_params: dict[str, Any], model: str, temperature: float
) -> None:
    """Add temperature only for models whose API accepts the parameter."""
    if not _temperature_is_deprecated(model):
        request_params["temperature"] = temperature


def _build_tool_call_node(block: Any, confidence: Distribution) -> Node:
    """Convert an Anthropic tool_use content block to a NODE_TOOL_CALL node."""
    return Node(
        id=f"tool_call_{block.id}",
        type=NODE_TOOL_CALL,
        value={"name": block.name, "arguments": block.input, "call_id": block.id},
        confidence=confidence,
    )


def _execute_tools(
    tool_call_nodes: list[Node],
    executor: "Callable[[str, dict], Any]",
    confidence: Distribution,
) -> list[Node]:
    """Execute each tool call node and return NODE_TOOL_RESULT nodes."""
    result_nodes: list[Node] = []
    for tc in tool_call_nodes:
        val = tc.value
        t0 = _time_mod.monotonic()
        try:
            result = executor(val["name"], val["arguments"])
            latency_ms = (_time_mod.monotonic() - t0) * 1000
            result_nodes.append(Node(
                id=f"tool_result_{val['call_id']}",
                type=NODE_TOOL_RESULT,
                value={
                    "call_id":    val["call_id"],
                    "content":    result,
                    "is_error":   False,
                    "latency_ms": round(latency_ms, 2),
                },
                confidence=confidence,
            ))
        except Exception as exc:
            latency_ms = (_time_mod.monotonic() - t0) * 1000
            result_nodes.append(Node(
                id=f"tool_result_{val['call_id']}",
                type=NODE_TOOL_RESULT,
                value={
                    "call_id":    val["call_id"],
                    "content":    str(exc),
                    "is_error":   True,
                    "error_type": type(exc).__name__,
                    "latency_ms": round(latency_ms, 2),
                },
                confidence=confidence,
            ))
    return result_nodes


def _build_doc(
    text: str,
    provenance: Provenance,
    thinking_blocks: list[str],
    confidence: Distribution,
    model: str,
    *,
    tool_call_nodes: list[Node] | None = None,
    tool_result_nodes: list[Node] | None = None,
) -> SPIFDocument:
    """Assemble a complete SPIFDocument from a finished response."""
    # Tool call/result nodes come first so the interaction sequence is readable
    extra_nodes: list[Node] = list(tool_call_nodes or []) + list(tool_result_nodes or [])

    text_node: list[Node] = []
    if text:
        text_node = [Node(id="response", type=NODE_TEXT, value=text,
                          confidence=confidence, refs=[])]

    # Require at least one node total
    payload = extra_nodes + text_node
    if not payload:
        payload = [Node(id="response", type=NODE_TEXT, value="",
                        confidence=confidence, refs=[])]

    trace: list[TraceStep] = []
    for i, thought in enumerate(thinking_blocks):
        trace.append(TraceStep(
            id=f"thought_{i}",
            type="hypothesis",
            content=thought,
            confidence=Distribution(mean=0.9, var=0.04,
                                    shape="gaussian", semantics="epistemic"),
            deps=[f"thought_{i - 1}"] if i > 0 else [],
            alternatives=[],
        ))

    return SPIFDocument(
        payload=payload,
        provenance=provenance,
        trace=trace,
        trace_method="live" if trace else "post-hoc",
        semantic=None,
        alternatives=[],
        delta=None,
        signature=None,
        signatures=[],
    )


class AnthropicSPIFAdapter:
    """
    Wraps an Anthropic client and produces SIF bytes or SPIFDocuments.

    Parameters
    ----------
    client :
        An `anthropic.Anthropic` (or `anthropic.AsyncAnthropic`) instance.
    model :
        Default model to use (overridable per-call).
    max_tokens :
        Default max_tokens.
    temperature :
        Sampling temperature recorded in provenance.
    confidence_override :
        If given, every response node uses this Distribution instead of the
        default output_stability estimate.
    context_ref :
        Hash of a prior SIF document this response continues (empty = root).
    """

    def __init__(
        self,
        client: Any,
        *,
        model: str = "claude-sonnet-4-6",
        max_tokens: int = 1024,
        temperature: float = 1.0,
        confidence_override: Distribution | None = None,
        context_ref: str = "",
        tools: list[dict[str, Any]] | None = None,
        tool_executor: "Callable[[str, dict], Any] | None" = None,
    ) -> None:
        self._client = client
        self._model = model
        self._max_tokens = max_tokens
        self._temperature = temperature
        self._confidence = confidence_override or _DEFAULT_CONFIDENCE
        self._context_ref = context_ref
        self._tools = tools
        self._tool_executor = tool_executor

    # ------------------------------------------------------------------
    # Synchronous streaming → bytes generator
    # ------------------------------------------------------------------

    def stream(
        self,
        prompt: str | list[dict[str, Any]],
        *,
        model: str | None = None,
        max_tokens: int | None = None,
        thinking: bool = False,
        thinking_budget_tokens: int = 8000,
        context: "SPIFDocument | None" = None,
    ) -> Generator[bytes, None, SPIFDocument]:
        """
        Yields SIF bytes as they are produced.  The return value (accessible
        via generator.send(None) / StopIteration.value) is the final SPIFDocument.

        Pass ``context=prev_doc`` to automatically link this response to the
        previous document via ``context_ref = prev_doc.content_id()``.

        Example::

            gen = adapter.stream("Hello")
            try:
                while True:
                    chunk = next(gen)
                    sys.stdout.buffer.write(chunk)
            except StopIteration as e:
                doc = e.value  # SPIFDocument
        """
        messages = _normalise_messages(prompt)
        use_model = model or self._model
        use_max_tokens = max(max_tokens or self._max_tokens,
                            thinking_budget_tokens + 1 if thinking else 0)
        confidence = _THINKING_CONFIDENCE if thinking else self._confidence
        context_ref = context.content_id() if context is not None else self._context_ref

        timestamp_ms = int(time.time() * 1000)
        provenance = _build_provenance(
            use_model, messages, self._temperature, timestamp_ms, context_ref
        )

        writer = SPIFStreamWriter()
        yield writer.open(provenance)

        text_parts: list[str] = []
        thinking_blocks: list[str] = []

        request_params: dict[str, Any] = {
            "model":      use_model,
            "max_tokens": use_max_tokens,
            "messages":   messages,
        }
        if thinking:
            request_params["thinking"] = {
                "type":          "enabled",
                "budget_tokens": thinking_budget_tokens,
            }
            # Temperature must be 1.0 when extended thinking is enabled.
            _set_temperature_if_supported(request_params, use_model, 1.0)
        else:
            _set_temperature_if_supported(request_params, use_model, self._temperature)

        with self._client.messages.stream(**request_params) as stream:
            for event in stream:
                event_type = getattr(event, "type", None)

                if event_type == "content_block_delta":
                    delta = event.delta
                    delta_type = getattr(delta, "type", None)

                    if delta_type == "text_delta":
                        token = delta.text
                        text_parts.append(token)
                        yield writer.partial_text(token, node_id="response")

                    elif delta_type == "thinking_delta":
                        thinking_blocks.append(delta.thinking)

        full_text = "".join(text_parts)
        doc = _build_doc(full_text, provenance, thinking_blocks, confidence, use_model)
        yield writer.commit(doc)
        return doc

    # ------------------------------------------------------------------
    # Async streaming → bytes async generator
    # ------------------------------------------------------------------

    async def astream(
        self,
        prompt: str | list[dict[str, Any]],
        *,
        model: str | None = None,
        max_tokens: int | None = None,
        thinking: bool = False,
        thinking_budget_tokens: int = 8000,
        context: "SPIFDocument | None" = None,
    ) -> AsyncGenerator[bytes, None]:
        """
        Async version of stream().  Yields SIF bytes.

        Example::

            async for chunk in adapter.astream("Hello"):
                await writer.write(chunk)
        """
        messages = _normalise_messages(prompt)
        use_model = model or self._model
        use_max_tokens = max(max_tokens or self._max_tokens,
                            thinking_budget_tokens + 1 if thinking else 0)
        confidence = _THINKING_CONFIDENCE if thinking else self._confidence
        context_ref = context.content_id() if context is not None else self._context_ref

        timestamp_ms = int(time.time() * 1000)
        provenance = _build_provenance(
            use_model, messages, self._temperature, timestamp_ms, context_ref
        )

        writer = SPIFStreamWriter()
        yield writer.open(provenance)

        text_parts: list[str] = []
        thinking_blocks: list[str] = []

        request_params: dict[str, Any] = {
            "model":      use_model,
            "max_tokens": use_max_tokens,
            "messages":   messages,
        }
        if thinking:
            request_params["thinking"] = {
                "type":          "enabled",
                "budget_tokens": thinking_budget_tokens,
            }
            _set_temperature_if_supported(request_params, use_model, 1.0)
        else:
            _set_temperature_if_supported(request_params, use_model, self._temperature)

        async with self._client.messages.stream(**request_params) as stream:
            async for event in stream:
                event_type = getattr(event, "type", None)

                if event_type == "content_block_delta":
                    delta = event.delta
                    delta_type = getattr(delta, "type", None)

                    if delta_type == "text_delta":
                        token = delta.text
                        text_parts.append(token)
                        yield writer.partial_text(token, node_id="response")

                    elif delta_type == "thinking_delta":
                        thinking_blocks.append(delta.thinking)

        full_text = "".join(text_parts)
        doc = _build_doc(full_text, provenance, thinking_blocks, confidence, use_model)
        yield writer.commit(doc)

    # ------------------------------------------------------------------
    # Non-streaming: returns a complete SPIFDocument
    # ------------------------------------------------------------------

    def complete(
        self,
        prompt: str | list[dict[str, Any]],
        *,
        model: str | None = None,
        max_tokens: int | None = None,
        thinking: bool = False,
        thinking_budget_tokens: int = 8000,
        context: "SPIFDocument | None" = None,
        tools: list[dict[str, Any]] | None = None,
        tool_executor: "Callable[[str, dict], Any] | None" = None,
    ) -> SPIFDocument:
        """
        Non-streaming call.  Blocks until the response is complete and
        returns a fully encoded SPIFDocument (ready to write to disk or sign).

        Pass ``tools=`` to enable tool use.  If ``tool_executor`` is provided,
        tools are executed automatically and NODE_TOOL_RESULT nodes are added.
        Otherwise, tool call nodes are added and ``doc.pending_tool_results``
        is set to True so the caller can supply results.
        """
        messages = _normalise_messages(prompt)
        use_model = model or self._model
        use_max_tokens = max(max_tokens or self._max_tokens,
                            thinking_budget_tokens + 1 if thinking else 0)
        confidence = _THINKING_CONFIDENCE if thinking else self._confidence
        context_ref = context.content_id() if context is not None else self._context_ref
        effective_tools = tools if tools is not None else self._tools
        effective_executor = tool_executor if tool_executor is not None else self._tool_executor

        timestamp_ms = int(time.time() * 1000)
        provenance = _build_provenance(
            use_model, messages, self._temperature, timestamp_ms, context_ref
        )

        request_params: dict[str, Any] = {
            "model":      use_model,
            "max_tokens": use_max_tokens,
            "messages":   messages,
        }
        if thinking:
            request_params["thinking"] = {
                "type":          "enabled",
                "budget_tokens": thinking_budget_tokens,
            }
            _set_temperature_if_supported(request_params, use_model, 1.0)
        else:
            _set_temperature_if_supported(request_params, use_model, self._temperature)
        if effective_tools:
            request_params["tools"] = effective_tools
            request_params["tool_choice"] = {"type": "auto"}

        response = self._client.messages.create(**request_params)

        text_parts: list[str] = []
        thinking_blocks: list[str] = []
        tool_call_nodes: list[Node] = []
        for block in response.content:
            if block.type == "text":
                text_parts.append(block.text)
            elif block.type == "thinking":
                thinking_blocks.append(block.thinking)
            elif block.type == "tool_use":
                tool_call_nodes.append(_build_tool_call_node(block, confidence))

        seen_ids: set[str] = set()
        for n in tool_call_nodes:
            if n.id in seen_ids:
                raise SPIFFormatError(f"Duplicate vendor tool_use id produced Node id {n.id!r}")
            seen_ids.add(n.id)

        tool_result_nodes: list[Node] = []
        pending = False
        if tool_call_nodes:
            if effective_executor is not None:
                tool_result_nodes = _execute_tools(tool_call_nodes, effective_executor, confidence)
            else:
                pending = True

        doc = _build_doc(
            "".join(text_parts), provenance, thinking_blocks, confidence, use_model,
            tool_call_nodes=tool_call_nodes, tool_result_nodes=tool_result_nodes,
        )
        doc.pending_tool_results = pending
        return doc


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _normalise_messages(
    prompt: str | list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Accept either a bare string or an already-formed messages list."""
    if isinstance(prompt, str):
        return [{"role": "user", "content": prompt}]
    return prompt
