"""
OpenAI → SPIF adapter.

Converts an OpenAI chat completions streaming response into a streaming SPIF
byte sequence, or a complete response into a SPIFDocument.

Usage — synchronous streaming generator:

    from openai import OpenAI
    from spif.adapters.openai_adapter import OpenAISPIFAdapter

    client = OpenAI()
    adapter = OpenAISPIFAdapter(client)

    for chunk in adapter.stream("Explain quantum entanglement in one sentence."):
        sys.stdout.buffer.write(chunk)

Usage — async:

    async for chunk in adapter.astream("..."):
        await websocket.send(chunk)

Usage — complete (no streaming, returns a SPIFDocument):

    doc = adapter.complete("What is 2+2?")

Provenance mapping
──────────────────
  source_model   ← response.model (from first chunk or complete response)
  model_version  ← same as source_model
  temperature    ← passed by caller
  input_hash     ← SHA-256 of the serialised messages list
  timestamp_ms   ← measured locally at response start
  context_ref    ← "" (no prior SPIF state by default; pass explicitly)

Confidence
──────────
OpenAI exposes per-token logprobs via logprobs=True.  When enabled (the
default), the adapter computes a real Distribution from the token-level log
probabilities: mean = mean(exp(logprob)), var = var(exp(logprob)).

When logprobs are unavailable or disabled, the adapter falls back to a
conservative default Distribution(mean=0.85, var=0.05, ...).

Reasoning (o1 / o3 models)
──────────────────────────
OpenAI does not expose reasoning token text in streaming mode.  When the
final usage shows reasoning_tokens > 0, the adapter adds a single TraceStep
("reasoning") recording the token count as content.  This preserves the
audit trail — a downstream reader can see that reasoning happened and how
much compute was used, even without the text.
Pass `capture_reasoning=False` to suppress this trace step.
"""

from __future__ import annotations

import json
import math
import time
from collections.abc import Generator, AsyncGenerator
from typing import Any

import time as _time_mod
from typing import Callable
from ._common import input_hash as _input_hash, build_provenance as _build_provenance
from ..format import NODE_TEXT, NODE_TOOL_CALL, NODE_TOOL_RESULT
from ..streaming import SPIFStreamWriter
from ..types import (
    Distribution, Node, Provenance, SPIFDocument, TraceStep,
)

_DEFAULT_CONFIDENCE = Distribution(
    mean=0.85,
    var=0.05,
    shape="gaussian",
    semantics="output_stability",
)


def _confidence_from_logprobs(probs: list[float]) -> Distribution:
    """
    Convert a list of per-token probabilities (already exponentiated) into a
    Distribution.  Uses Welford's online algorithm so it runs in one pass.
    """
    if not probs:
        return _DEFAULT_CONFIDENCE
    n = len(probs)
    mean = sum(probs) / n
    if n > 1:
        var = sum((p - mean) ** 2 for p in probs) / n
    else:
        var = 0.05  # single token — use default variance
    # Clamp to valid range
    mean = max(0.0, min(1.0, mean))
    var = max(0.0, var)
    return Distribution(mean=mean, var=var, shape="gaussian",
                        semantics="output_stability")


def _execute_tools_oai(
    tool_call_nodes: list[Node],
    executor: "Callable[[str, dict], Any]",
    confidence: Distribution,
) -> list[Node]:
    """Execute each OpenAI tool call node and return NODE_TOOL_RESULT nodes."""
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
    confidence: Distribution,
    reasoning_tokens: int,
    capture_reasoning: bool,
    *,
    tool_call_nodes: list[Node] | None = None,
    tool_result_nodes: list[Node] | None = None,
) -> SPIFDocument:
    extra_nodes: list[Node] = list(tool_call_nodes or []) + list(tool_result_nodes or [])
    text_node: list[Node] = []
    if text:
        text_node = [Node(id="response", type=NODE_TEXT, value=text,
                          confidence=confidence, refs=[])]
    payload = extra_nodes + text_node
    if not payload:
        payload = [Node(id="response", type=NODE_TEXT, value="",
                        confidence=confidence, refs=[])]

    trace: list[TraceStep] = []
    if capture_reasoning and reasoning_tokens > 0:
        trace.append(TraceStep(
            id="reasoning",
            type="hypothesis",
            content=f"[OpenAI internal reasoning — {reasoning_tokens} tokens, text not exposed by API]",
            confidence=Distribution(mean=0.92, var=0.03,
                                    shape="gaussian", semantics="epistemic"),
            deps=[],
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


class OpenAISPIFAdapter:
    """
    Wraps an OpenAI client and produces SPIF bytes or SPIFDocuments.

    Parameters
    ----------
    client :
        An `openai.OpenAI` (or `openai.AsyncOpenAI`) instance.
    model :
        Default model to use (overridable per-call).
    max_tokens :
        Default max_tokens (maps to max_completion_tokens for o1/o3 and GPT-5.6).
    temperature :
        Sampling temperature recorded in provenance. Ignored for o1/o3 and
        GPT-5.6 models, which use the reasoning request shape.
    logprobs :
        If True (default), request per-token logprobs and use them to
        compute a real confidence Distribution.
    confidence_override :
        If given, every response node uses this Distribution regardless of
        logprobs.
    context_ref :
        Hash of a prior SPIF document this response continues (empty = root).
    capture_reasoning :
        If True (default), add a TraceStep for o1/o3 reasoning token counts.
    """

    # Models that use max_completion_tokens and omit temperature.
    _REASONING_MODELS = frozenset({
        "o1", "o1-mini", "o1-preview", "o1-pro",
        "o3", "o3-mini", "o3-pro",
        "o4-mini",
    })
    _REASONING_MODEL_PREFIXES = ("gpt-5.6",)

    def __init__(
        self,
        client: Any,
        *,
        model: str = "gpt-4o",
        max_tokens: int = 1024,
        temperature: float = 1.0,
        logprobs: bool = True,
        confidence_override: Distribution | None = None,
        context_ref: str = "",
        capture_reasoning: bool = True,
        tools: list[dict[str, Any]] | None = None,
        tool_executor: "Callable[[str, dict], Any] | None" = None,
    ) -> None:
        self._client = client
        self._model = model
        self._max_tokens = max_tokens
        self._temperature = temperature
        self._logprobs = logprobs
        self._confidence_override = confidence_override
        self._context_ref = context_ref
        self._capture_reasoning = capture_reasoning
        self._tools = tools
        self._tool_executor = tool_executor

    def _is_reasoning_model(self, model: str) -> bool:
        # Match on prefix so "o1-2024-12-17" also matches
        base = model.split("-")[0] if "-" in model else model
        return (
            model in self._REASONING_MODELS
            or base in {"o1", "o3", "o4"}
            or model.startswith(self._REASONING_MODEL_PREFIXES)
        )

    def _request_params(
        self,
        model: str,
        messages: list[dict[str, Any]],
        max_tokens: int,
        stream: bool,
    ) -> dict[str, Any]:
        reasoning = self._is_reasoning_model(model)
        params: dict[str, Any] = {
            "model":    model,
            "messages": messages,
            "stream":   stream,
        }
        # o1/o3 use max_completion_tokens, not max_tokens
        if reasoning:
            params["max_completion_tokens"] = max_tokens
        else:
            params["max_tokens"] = max_tokens
            params["temperature"] = self._temperature

        if self._logprobs and not reasoning:
            params["logprobs"] = True

        if stream:
            params["stream_options"] = {"include_usage": True}

        return params

    # ------------------------------------------------------------------
    # Synchronous streaming → bytes generator
    # ------------------------------------------------------------------

    def stream(
        self,
        prompt: str | list[dict[str, Any]],
        *,
        model: str | None = None,
        max_tokens: int | None = None,
        context: "SPIFDocument | None" = None,
    ) -> Generator[bytes, None, SPIFDocument]:
        """
        Yields SPIF bytes as they arrive.  StopIteration.value is the final
        SPIFDocument.

        Pass ``context=prev_doc`` to automatically link this response to the
        previous document via ``context_ref = prev_doc.content_id()``.

        Example::

            gen = adapter.stream("Hello")
            try:
                while True:
                    chunk = next(gen)
                    sys.stdout.buffer.write(chunk)
            except StopIteration as e:
                doc = e.value
        """
        messages = _normalise_messages(prompt)
        use_model = model or self._model
        use_max_tokens = max_tokens or self._max_tokens
        context_ref = context.content_id() if context is not None else self._context_ref

        timestamp_ms = int(time.time() * 1000)
        provenance = _build_provenance(
            use_model, messages, self._temperature, timestamp_ms, context_ref
        )

        writer = SPIFStreamWriter()
        yield writer.open(provenance)

        text_parts: list[str] = []
        token_probs: list[float] = []
        reasoning_tokens = 0

        params = self._request_params(use_model, messages, use_max_tokens, stream=True)
        for chunk in self._client.chat.completions.create(**params):
            if chunk.choices:
                delta = chunk.choices[0].delta
                if delta.content:
                    text_parts.append(delta.content)
                    yield writer.partial_text(delta.content, node_id="response")

                # Collect logprobs if present
                lp_data = getattr(chunk.choices[0], "logprobs", None)
                if lp_data and lp_data.content:
                    for lp in lp_data.content:
                        token_probs.append(math.exp(lp.logprob))

            # Usage arrives in the final chunk (stream_options include_usage)
            if chunk.usage:
                details = getattr(chunk.usage, "completion_tokens_details", None)
                if details:
                    reasoning_tokens = getattr(details, "reasoning_tokens", 0) or 0

        if self._confidence_override:
            confidence = self._confidence_override
        elif token_probs:
            confidence = _confidence_from_logprobs(token_probs)
        else:
            confidence = _DEFAULT_CONFIDENCE

        full_text = "".join(text_parts)
        doc = _build_doc(full_text, provenance, confidence,
                         reasoning_tokens, self._capture_reasoning)
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
        context: "SPIFDocument | None" = None,
    ) -> AsyncGenerator[bytes, None]:
        """
        Async version of stream().  Yields SPIF bytes.

        Example::

            async for chunk in adapter.astream("Hello"):
                await writer.write(chunk)
        """
        messages = _normalise_messages(prompt)
        use_model = model or self._model
        use_max_tokens = max_tokens or self._max_tokens
        context_ref = context.content_id() if context is not None else self._context_ref

        timestamp_ms = int(time.time() * 1000)
        provenance = _build_provenance(
            use_model, messages, self._temperature, timestamp_ms, context_ref
        )

        writer = SPIFStreamWriter()
        yield writer.open(provenance)

        text_parts: list[str] = []
        token_probs: list[float] = []
        reasoning_tokens = 0

        params = self._request_params(use_model, messages, use_max_tokens, stream=True)
        async with await self._client.chat.completions.create(**params) as stream:
            async for chunk in stream:
                if chunk.choices:
                    delta = chunk.choices[0].delta
                    if delta.content:
                        text_parts.append(delta.content)
                        yield writer.partial_text(delta.content, node_id="response")

                    lp_data = getattr(chunk.choices[0], "logprobs", None)
                    if lp_data and lp_data.content:
                        for lp in lp_data.content:
                            token_probs.append(math.exp(lp.logprob))

                if chunk.usage:
                    details = getattr(chunk.usage, "completion_tokens_details", None)
                    if details:
                        reasoning_tokens = getattr(details, "reasoning_tokens", 0) or 0

        if self._confidence_override:
            confidence = self._confidence_override
        elif token_probs:
            confidence = _confidence_from_logprobs(token_probs)
        else:
            confidence = _DEFAULT_CONFIDENCE

        full_text = "".join(text_parts)
        doc = _build_doc(full_text, provenance, confidence,
                         reasoning_tokens, self._capture_reasoning)
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
        context: "SPIFDocument | None" = None,
        tools: list[dict[str, Any]] | None = None,
        tool_executor: "Callable[[str, dict], Any] | None" = None,
    ) -> SPIFDocument:
        """
        Non-streaming call.  Blocks until the response is complete and
        returns a fully encoded SPIFDocument.

        Pass ``tools=`` to enable function calling.  If ``tool_executor`` is
        provided, tools are executed automatically and NODE_TOOL_RESULT nodes
        are added.  Otherwise ``doc.pending_tool_results`` is set to True.
        """
        messages = _normalise_messages(prompt)
        use_model = model or self._model
        use_max_tokens = max_tokens or self._max_tokens
        context_ref = context.content_id() if context is not None else self._context_ref
        effective_tools = tools if tools is not None else self._tools
        effective_executor = tool_executor if tool_executor is not None else self._tool_executor

        timestamp_ms = int(time.time() * 1000)

        params = self._request_params(use_model, messages, use_max_tokens, stream=False)
        if effective_tools:
            params["tools"] = effective_tools
            params["tool_choice"] = "auto"

        response = self._client.chat.completions.create(**params)

        actual_model = response.model or use_model
        provenance = _build_provenance(
            actual_model, messages, self._temperature, timestamp_ms, context_ref
        )

        msg = response.choices[0].message
        text = msg.content or ""

        # Logprobs: only present for text tokens; tool call responses have no logprobs.
        # Handle all None/empty cases gracefully to avoid AttributeError.
        token_probs: list[float] = []
        lp_obj = getattr(response.choices[0], "logprobs", None)
        lp_content = getattr(lp_obj, "content", None) if lp_obj is not None else None
        if lp_content:
            for lp in lp_content:
                token_probs.append(math.exp(lp.logprob))

        reasoning_tokens = 0
        if response.usage:
            details = getattr(response.usage, "completion_tokens_details", None)
            if details:
                reasoning_tokens = getattr(details, "reasoning_tokens", 0) or 0

        if self._confidence_override:
            confidence = self._confidence_override
        elif token_probs:
            confidence = _confidence_from_logprobs(token_probs)
        else:
            confidence = _DEFAULT_CONFIDENCE

        # Build tool call nodes from function_call response
        tool_call_nodes: list[Node] = []
        if getattr(msg, "tool_calls", None):
            for tc in msg.tool_calls:
                try:
                    args = json.loads(tc.function.arguments)
                except (json.JSONDecodeError, AttributeError):
                    args = {}
                tool_call_nodes.append(Node(
                    id=f"tool_call_{tc.id}",
                    type=NODE_TOOL_CALL,
                    value={"name": tc.function.name, "arguments": args, "call_id": tc.id},
                    confidence=confidence,
                ))

        tool_result_nodes: list[Node] = []
        pending = False
        if tool_call_nodes:
            if effective_executor is not None:
                tool_result_nodes = _execute_tools_oai(tool_call_nodes, effective_executor,
                                                       confidence)
            else:
                pending = True

        doc = _build_doc(text, provenance, confidence, reasoning_tokens,
                         self._capture_reasoning,
                         tool_call_nodes=tool_call_nodes,
                         tool_result_nodes=tool_result_nodes)
        doc.pending_tool_results = pending
        return doc


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _normalise_messages(
    prompt: str | list[dict[str, Any]],
) -> list[dict[str, Any]]:
    if isinstance(prompt, str):
        return [{"role": "user", "content": prompt}]
    return prompt
