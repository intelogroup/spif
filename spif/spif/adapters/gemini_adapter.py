"""
Google Gemini → SPIF adapter.

Converts a Gemini API streaming response into a streaming SPIF byte sequence,
or a complete response into a SPIFDocument.

Usage — synchronous streaming generator:

    import google.generativeai as genai
    from spif.adapters.gemini_adapter import GeminiSPIFAdapter

    genai.configure(api_key="...")
    client = genai.GenerativeModel("gemini-2.0-flash")
    adapter = GeminiSPIFAdapter(client)

    for chunk in adapter.stream("Explain quantum entanglement in one sentence."):
        sys.stdout.buffer.write(chunk)

Usage — new-SDK (google-genai):

    from google import genai
    from spif.adapters.gemini_adapter import GeminiSPIFAdapter

    client = genai.Client(api_key="...")
    model = client.models  # pass client; set model name in GeminiSPIFAdapter(model=...)
    adapter = GeminiSPIFAdapter(client, model="gemini-2.0-flash", use_genai_sdk=True)

Usage — async:

    async for chunk in adapter.astream("..."):
        await websocket.send(chunk)

Usage — complete (no streaming, returns a SPIFDocument):

    doc = adapter.complete("What is 2+2?")

Provenance mapping
──────────────────
  source_model   ← model name passed by caller
  model_version  ← same as source_model
  temperature    ← passed by caller (default 1.0)
  input_hash     ← SHA-256 of the serialised messages list
  timestamp_ms   ← measured locally at response start
  context_ref    ← "" (no prior SPIF state by default; pass explicitly)

Confidence
──────────
The google-generativeai SDK exposes logprobs via `response_logprobs=True`
(Gemini 1.5+).  When available, the adapter converts them to a Distribution
using the same mean/var approach as the OpenAI adapter.

When logprobs are unavailable, the adapter falls back to a conservative
default Distribution(mean=0.85, var=0.05, ...).

Thinking (Gemini 2.0+)
────────────────────────
Gemini 2.0 exposes thinking content as parts where `part.thought == True`.
The adapter captures these as TraceStep entries in the SPIF trace, analogous
to the Anthropic adapter's extended thinking support.
Pass `capture_thinking=False` to suppress this.
"""

from __future__ import annotations

import math
import time
import warnings
from collections.abc import Generator, AsyncGenerator
from typing import Any

from ._common import input_hash as _input_hash, build_provenance as _build_provenance
from ..format import NODE_TEXT
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

_THINKING_CONFIDENCE = Distribution(
    mean=0.92,
    var=0.03,
    shape="gaussian",
    semantics="epistemic",
)


def _make_legacy_generation_config(config: dict[str, Any]) -> Any:
    """
    Build a GenerationConfig for the deprecated google-generativeai SDK.

    The package emits a FutureWarning on import. The adapter still supports the
    legacy client, but callers should not see that warning on every request.
    """
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", FutureWarning)
        import google.generativeai as genai  # type: ignore[import]
    return genai.GenerationConfig(**config)


def _confidence_from_logprobs(probs: list[float]) -> Distribution:
    """Convert per-token probabilities (already exponentiated) into a Distribution."""
    if not probs:
        return _DEFAULT_CONFIDENCE
    n = len(probs)
    mean = sum(probs) / n
    var = sum((p - mean) ** 2 for p in probs) / n if n > 1 else 0.05
    mean = max(0.0, min(1.0, mean))
    var = max(0.0, var)
    return Distribution(mean=mean, var=var, shape="gaussian",
                        semantics="output_stability")


def _build_doc(
    text: str,
    provenance: Provenance,
    confidence: Distribution,
    thinking_parts: list[str],
    capture_thinking: bool,
) -> SPIFDocument:
    payload = [
        Node(
            id="response",
            type=NODE_TEXT,
            value=text,
            confidence=confidence,
            refs=[],
        )
    ]

    trace: list[TraceStep] = []
    if capture_thinking:
        for i, thought in enumerate(thinking_parts):
            trace.append(TraceStep(
                id=f"thought_{i}",
                type="hypothesis",
                content=thought,
                confidence=_THINKING_CONFIDENCE,
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


def _extract_chunk_content(
    chunk: Any,
) -> tuple[list[str], list[str], list[float]]:
    """
    Extract text parts, thinking parts, and logprob probabilities from a
    Gemini streaming chunk.  Works with both the legacy google-generativeai
    SDK and the new google-genai SDK (structurally similar response objects).

    Returns (text_tokens, thinking_tokens, token_probs).
    """
    text_tokens: list[str] = []
    thinking_tokens: list[str] = []
    token_probs: list[float] = []

    # Gemini response: chunk.candidates[0].content.parts
    candidates = getattr(chunk, "candidates", None) or []
    if not candidates:
        # New SDK may expose chunk.text directly for simple cases
        text = getattr(chunk, "text", None)
        if text:
            text_tokens.append(text)
        return text_tokens, thinking_tokens, token_probs

    candidate = candidates[0]
    content = getattr(candidate, "content", None)
    if content is None:
        return text_tokens, thinking_tokens, token_probs

    parts = getattr(content, "parts", None) or []
    for part in parts:
        part_text = getattr(part, "text", None)
        if part_text is None:
            continue
        is_thought = getattr(part, "thought", False)
        if is_thought:
            thinking_tokens.append(part_text)
        else:
            text_tokens.append(part_text)

    # Logprobs — available via candidate.logprobs_result (Gemini 1.5+)
    logprobs_result = getattr(candidate, "logprobs_result", None)
    if logprobs_result:
        chosen_candidates = getattr(logprobs_result, "chosen_candidates", []) or []
        for lp_entry in chosen_candidates:
            log_prob = getattr(lp_entry, "log_probability", None)
            if log_prob is not None:
                token_probs.append(math.exp(log_prob))

    return text_tokens, thinking_tokens, token_probs


class GeminiSPIFAdapter:
    """
    Wraps a Gemini model client and produces SPIF bytes or SPIFDocuments.

    Parameters
    ----------
    client :
        A ``google.generativeai.GenerativeModel`` instance (legacy SDK), or
        a ``google.genai.Client`` instance (new SDK, set ``use_genai_sdk=True``).
    model :
        Model name string.  Used in provenance and as the generation target
        when ``use_genai_sdk=True``.
    max_tokens :
        Maximum output tokens (``max_output_tokens`` in Gemini config).
    temperature :
        Sampling temperature recorded in provenance.
    logprobs :
        If True (default), request per-token logprobs and use them to compute
        a real confidence Distribution.  Only effective on Gemini 1.5+.
    confidence_override :
        If given, every response node uses this Distribution regardless of
        logprobs.
    context_ref :
        Hash of a prior SPIF document this response continues (empty = root).
    capture_thinking :
        If True (default), capture Gemini 2.0 thinking parts as TraceSteps.
    use_genai_sdk :
        Set True when passing a ``google.genai.Client`` instead of a
        ``google.generativeai.GenerativeModel``.
    """

    def __init__(
        self,
        client: Any,
        *,
        model: str = "gemini-2.0-flash",
        max_tokens: int = 1024,
        temperature: float = 1.0,
        logprobs: bool = True,
        confidence_override: Distribution | None = None,
        context_ref: str = "",
        capture_thinking: bool = True,
        use_genai_sdk: bool = False,
    ) -> None:
        self._client = client
        self._model = model
        self._max_tokens = max_tokens
        self._temperature = temperature
        self._logprobs = logprobs
        self._confidence_override = confidence_override
        self._context_ref = context_ref
        self._capture_thinking = capture_thinking
        self._use_genai_sdk = use_genai_sdk

    def _generation_config(self) -> dict[str, Any]:
        config: dict[str, Any] = {
            "max_output_tokens": self._max_tokens,
            "temperature": self._temperature,
        }
        if self._logprobs:
            config["response_logprobs"] = True
        return config

    def _make_request(
        self,
        messages: list[dict[str, Any]],
        *,
        stream: bool,
    ) -> Any:
        """Dispatch to the correct SDK variant."""
        gen_config = self._generation_config()
        if self._use_genai_sdk:
            # google-genai SDK: client.models.generate_content(model=..., contents=...)
            contents = _messages_to_contents(messages)
            if stream:
                return self._client.models.generate_content_stream(
                    model=self._model,
                    contents=contents,
                    config=gen_config,
                )
            return self._client.models.generate_content(
                model=self._model,
                contents=contents,
                config=gen_config,
            )
        else:
            # Legacy google-generativeai SDK: model.generate_content(...)
            # Note: response_logprobs is not supported in GenerationConfig;
            # logprobs are only available via the new google-genai SDK.
            prompt = _messages_to_prompt(messages)
            legacy_config = {k: v for k, v in gen_config.items()
                             if k != "response_logprobs"}
            config = _make_legacy_generation_config(legacy_config)
            return self._client.generate_content(
                prompt,
                generation_config=config,
                stream=stream,
            )

    async def _make_request_async(
        self,
        messages: list[dict[str, Any]],
    ) -> Any:
        """Async streaming — returns an async iterable of chunks."""
        gen_config = self._generation_config()
        if self._use_genai_sdk:
            contents = _messages_to_contents(messages)
            return self._client.models.generate_content_stream(
                model=self._model,
                contents=contents,
                config=gen_config,
            )
        else:
            prompt = _messages_to_prompt(messages)
            legacy_config = {k: v for k, v in gen_config.items()
                             if k != "response_logprobs"}
            config = _make_legacy_generation_config(legacy_config)
            return await self._client.generate_content_async(
                prompt,
                generation_config=config,
                stream=True,
            )

    # ------------------------------------------------------------------
    # Synchronous streaming → bytes generator
    # ------------------------------------------------------------------

    def stream(
        self,
        prompt: str | list[dict[str, Any]],
        *,
        model: str | None = None,
        max_tokens: int | None = None,
    ) -> Generator[bytes, None, SPIFDocument]:
        """
        Yields SPIF bytes as they arrive.  StopIteration.value is the final
        SPIFDocument.

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
        if model:
            orig_model, self._model = self._model, model
        if max_tokens:
            orig_max, self._max_tokens = self._max_tokens, max_tokens

        try:
            timestamp_ms = int(time.time() * 1000)
            provenance = _build_provenance(
                self._model, messages, self._temperature, timestamp_ms, self._context_ref
            )

            writer = SPIFStreamWriter()
            yield writer.open(provenance)

            text_parts: list[str] = []
            thinking_parts: list[str] = []
            token_probs: list[float] = []

            for chunk in self._make_request(messages, stream=True):
                text_tokens, thought_tokens, probs = _extract_chunk_content(chunk)
                for tok in text_tokens:
                    text_parts.append(tok)
                    yield writer.partial_text(tok, node_id="response")
                thinking_parts.extend(thought_tokens)
                token_probs.extend(probs)

            if self._confidence_override:
                confidence = self._confidence_override
            elif token_probs:
                confidence = _confidence_from_logprobs(token_probs)
            else:
                confidence = _THINKING_CONFIDENCE if thinking_parts else _DEFAULT_CONFIDENCE

            full_text = "".join(text_parts)
            doc = _build_doc(full_text, provenance, confidence,
                             thinking_parts, self._capture_thinking)
            yield writer.commit(doc)
            return doc
        finally:
            if model:
                self._model = orig_model
            if max_tokens:
                self._max_tokens = orig_max

    # ------------------------------------------------------------------
    # Async streaming → bytes async generator
    # ------------------------------------------------------------------

    async def astream(
        self,
        prompt: str | list[dict[str, Any]],
        *,
        model: str | None = None,
        max_tokens: int | None = None,
    ) -> AsyncGenerator[bytes, None]:
        """
        Async version of stream().  Yields SPIF bytes.

        Example::

            async for chunk in adapter.astream("Hello"):
                await writer.write(chunk)
        """
        messages = _normalise_messages(prompt)
        if model:
            orig_model, self._model = self._model, model
        if max_tokens:
            orig_max, self._max_tokens = self._max_tokens, max_tokens

        try:
            timestamp_ms = int(time.time() * 1000)
            provenance = _build_provenance(
                self._model, messages, self._temperature, timestamp_ms, self._context_ref
            )

            writer = SPIFStreamWriter()
            yield writer.open(provenance)

            text_parts: list[str] = []
            thinking_parts: list[str] = []
            token_probs: list[float] = []

            stream = await self._make_request_async(messages)
            async for chunk in stream:
                text_tokens, thought_tokens, probs = _extract_chunk_content(chunk)
                for tok in text_tokens:
                    text_parts.append(tok)
                    yield writer.partial_text(tok, node_id="response")
                thinking_parts.extend(thought_tokens)
                token_probs.extend(probs)

            if self._confidence_override:
                confidence = self._confidence_override
            elif token_probs:
                confidence = _confidence_from_logprobs(token_probs)
            else:
                confidence = _THINKING_CONFIDENCE if thinking_parts else _DEFAULT_CONFIDENCE

            full_text = "".join(text_parts)
            doc = _build_doc(full_text, provenance, confidence,
                             thinking_parts, self._capture_thinking)
            yield writer.commit(doc)
        finally:
            if model:
                self._model = orig_model
            if max_tokens:
                self._max_tokens = orig_max

    # ------------------------------------------------------------------
    # Non-streaming: returns a complete SPIFDocument
    # ------------------------------------------------------------------

    def complete(
        self,
        prompt: str | list[dict[str, Any]],
        *,
        model: str | None = None,
        max_tokens: int | None = None,
    ) -> SPIFDocument:
        """
        Non-streaming call.  Blocks until the response is complete and
        returns a fully encoded SPIFDocument.
        """
        messages = _normalise_messages(prompt)
        if model:
            orig_model, self._model = self._model, model
        if max_tokens:
            orig_max, self._max_tokens = self._max_tokens, max_tokens

        try:
            timestamp_ms = int(time.time() * 1000)
            provenance = _build_provenance(
                self._model, messages, self._temperature, timestamp_ms, self._context_ref
            )

            response = self._make_request(messages, stream=False)

            text_parts: list[str] = []
            thinking_parts: list[str] = []
            token_probs: list[float] = []

            # Non-streaming response — use the same extraction logic
            text_tokens, thought_tokens, probs = _extract_chunk_content(response)
            text_parts.extend(text_tokens)
            thinking_parts.extend(thought_tokens)
            token_probs.extend(probs)

            if self._confidence_override:
                confidence = self._confidence_override
            elif token_probs:
                confidence = _confidence_from_logprobs(token_probs)
            else:
                confidence = _THINKING_CONFIDENCE if thinking_parts else _DEFAULT_CONFIDENCE

            return _build_doc(
                "".join(text_parts), provenance, confidence,
                thinking_parts, self._capture_thinking,
            )
        finally:
            if model:
                self._model = orig_model
            if max_tokens:
                self._max_tokens = orig_max


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


def _messages_to_prompt(messages: list[dict[str, Any]]) -> str:
    """
    Convert a messages list to a simple string prompt for the legacy
    google-generativeai SDK (which expects a string or list of parts).
    For multi-turn conversations, join with role prefixes.
    """
    if len(messages) == 1 and messages[0]["role"] == "user":
        return messages[0]["content"]
    parts = []
    for m in messages:
        role = m["role"].capitalize()
        parts.append(f"{role}: {m['content']}")
    return "\n".join(parts)


def _messages_to_contents(messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    Convert messages list to the google-genai SDK's ``contents`` format.
    Maps "assistant" role → "model".
    """
    result = []
    for m in messages:
        role = m["role"]
        if role == "assistant":
            role = "model"
        result.append({"role": role, "parts": [{"text": m["content"]}]})
    return result
