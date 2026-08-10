"""
Live API benchmark for SPIF adapters.

Measures real provider latency using the API keys already present in the
environment, with separate timing for:
  1. Blocking complete() latency
  2. Raw provider time-to-first-token (TTFT)
  3. SPIF adapter streaming latency and output size
  4. Optional thinking-mode latency and trace size
  5. Optional multi-turn context_ref chaining

Run:
    cd /path/to/sif
    python benchmarks/live_api_bench.py
    python benchmarks/live_api_bench.py --provider anthropic --reps 3
    python benchmarks/live_api_bench.py --json

Environment:
    ANTHROPIC_API_KEY for Anthropic
    OPENAI_API_KEY    for OpenAI
"""

from __future__ import annotations

import argparse
import json
import os
import statistics
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "spif"))

from spif.reader import SPIFReader
from spif.streaming import SPIFStreamReader
from spif.writer import SPIFWriter


DEFAULT_COMPLETE_PROMPT = "Reply with exactly: SPIF"
DEFAULT_STREAM_PROMPT = "Count from 1 to 5, one number per line."
DEFAULT_THINKING_PROMPT = "What is 17 * 23? Show your reasoning."
DEFAULT_CONTEXT_PROMPT_1 = "My favourite colour is blue. Acknowledge this in one word."
DEFAULT_CONTEXT_PROMPT_2 = "What did I just tell you my favourite colour is?"


@dataclass
class Sample:
    complete_ms: float
    raw_ttft_ms: float
    raw_stream_ms: float
    adapter_first_chunk_ms: float
    adapter_first_partial_ms: float | None
    adapter_stream_ms: float
    adapter_chunks: int
    adapter_partial_events: int
    complete_bytes: int
    stream_bytes: int
    complete_chars: int
    stream_chars: int
    trace_steps: int
    checksum_verified: bool


def _mean(values: list[float]) -> float:
    return statistics.fmean(values) if values else 0.0


def _stdev(values: list[float]) -> float:
    return statistics.pstdev(values) if len(values) > 1 else 0.0


def _summarize(samples: list[Sample]) -> dict[str, Any]:
    return {
        "runs": len(samples),
        "complete_ms": {
            "mean": round(_mean([s.complete_ms for s in samples]), 1),
            "stdev": round(_stdev([s.complete_ms for s in samples]), 1),
        },
        "raw_ttft_ms": {
            "mean": round(_mean([s.raw_ttft_ms for s in samples]), 1),
            "stdev": round(_stdev([s.raw_ttft_ms for s in samples]), 1),
        },
        "raw_stream_ms": {
            "mean": round(_mean([s.raw_stream_ms for s in samples]), 1),
            "stdev": round(_stdev([s.raw_stream_ms for s in samples]), 1),
        },
        "adapter_first_chunk_ms": {
            "mean": round(_mean([s.adapter_first_chunk_ms for s in samples]), 1),
            "stdev": round(_stdev([s.adapter_first_chunk_ms for s in samples]), 1),
        },
        "adapter_first_partial_ms": {
            "mean": round(_mean([s.adapter_first_partial_ms for s in samples if s.adapter_first_partial_ms is not None]), 1),
            "stdev": round(_stdev([s.adapter_first_partial_ms for s in samples if s.adapter_first_partial_ms is not None]), 1),
        },
        "adapter_stream_ms": {
            "mean": round(_mean([s.adapter_stream_ms for s in samples]), 1),
            "stdev": round(_stdev([s.adapter_stream_ms for s in samples]), 1),
        },
        "adapter_chunks": round(_mean([float(s.adapter_chunks) for s in samples]), 1),
        "adapter_partial_events": round(_mean([float(s.adapter_partial_events) for s in samples]), 1),
        "complete_bytes": round(_mean([float(s.complete_bytes) for s in samples]), 1),
        "stream_bytes": round(_mean([float(s.stream_bytes) for s in samples]), 1),
        "complete_chars": round(_mean([float(s.complete_chars) for s in samples]), 1),
        "stream_chars": round(_mean([float(s.stream_chars) for s in samples]), 1),
        "trace_steps": round(_mean([float(s.trace_steps) for s in samples]), 1),
        "checksum_verified_runs": sum(1 for s in samples if s.checksum_verified),
    }


def _summarize_numeric_samples(samples: list[dict[str, float | int | bool | str]]) -> dict[str, Any]:
    summary: dict[str, Any] = {"runs": len(samples)}
    if not samples:
        return summary
    keys = samples[0].keys()
    for key in keys:
        values = [sample[key] for sample in samples]
        if all(isinstance(value, bool) for value in values):
            summary[key] = sum(1 for value in values if value)
        elif all(isinstance(value, (int, float)) and not isinstance(value, bool) for value in values):
            numeric = [float(value) for value in values]
            summary[key] = {
                "mean": round(_mean(numeric), 1),
                "stdev": round(_stdev(numeric), 1),
            }
        else:
            summary[key] = values[0]
    return summary


class ProviderBench:
    name: str
    model: str

    def run_once(self, complete_prompt: str, stream_prompt: str, max_tokens: int) -> Sample:
        raise NotImplementedError

    def run_thinking_once(
        self,
        prompt: str,
        max_tokens: int,
        thinking_budget_tokens: int,
    ) -> dict[str, float | int | bool | str] | None:
        return None

    def run_context_chain_once(
        self,
        prompt1: str,
        prompt2: str,
        max_tokens: int,
    ) -> dict[str, float | int | bool | str] | None:
        return None


class AnthropicBench(ProviderBench):
    def __init__(self, model: str, thinking_model: str) -> None:
        try:
            import anthropic
        except ImportError as e:
            raise SystemExit("anthropic SDK not installed. Run: pip install anthropic") from e
        if not os.environ.get("ANTHROPIC_API_KEY"):
            raise SystemExit("ANTHROPIC_API_KEY not set")
        from spif.adapters.anthropic_adapter import AnthropicSPIFAdapter

        self.name = "anthropic"
        self.model = model
        self.thinking_model = thinking_model
        self._client = anthropic.Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])
        self._adapter_cls = AnthropicSPIFAdapter

    def _raw_stream_metrics(self, prompt: str, max_tokens: int) -> tuple[float, float]:
        started = time.perf_counter()
        first_token_ms: float | None = None
        with self._client.messages.stream(
            model=self.model,
            max_tokens=max_tokens,
            messages=[{"role": "user", "content": prompt}],
            temperature=1.0,
        ) as stream:
            for event in stream:
                event_type = getattr(event, "type", None)
                if event_type != "content_block_delta":
                    continue
                delta = getattr(event, "delta", None)
                if getattr(delta, "type", None) != "text_delta":
                    continue
                token = getattr(delta, "text", "")
                if token and first_token_ms is None:
                    first_token_ms = (time.perf_counter() - started) * 1000
        total_ms = (time.perf_counter() - started) * 1000
        return first_token_ms or total_ms, total_ms

    def run_once(self, complete_prompt: str, stream_prompt: str, max_tokens: int) -> Sample:
        adapter = self._adapter_cls(self._client, model=self.model, max_tokens=max_tokens)
        reader = SPIFReader()
        writer = SPIFWriter()

        t0 = time.perf_counter()
        doc = adapter.complete(complete_prompt)
        complete_ms = (time.perf_counter() - t0) * 1000
        complete_bytes = writer.encode(doc)
        reader.decode(complete_bytes)

        raw_ttft_ms, raw_stream_ms = self._raw_stream_metrics(stream_prompt, max_tokens)

        stream_reader = SPIFStreamReader()
        chunks: list[bytes] = []
        first_chunk_ms: float | None = None
        first_partial_ms: float | None = None
        partial_events = 0
        final_doc = None
        start = time.perf_counter()
        gen = adapter.stream(stream_prompt)
        try:
            while True:
                chunk = next(gen)
                now_ms = (time.perf_counter() - start) * 1000
                if first_chunk_ms is None:
                    first_chunk_ms = now_ms
                chunks.append(chunk)
                for event in stream_reader.feed(chunk):
                    if event.type == "partial_text":
                        partial_events += 1
                        if first_partial_ms is None:
                            first_partial_ms = (time.perf_counter() - start) * 1000
                    elif event.type == "verified":
                        final_doc = event.document
        except StopIteration as exc:
            if final_doc is None:
                final_doc = exc.value
        adapter_stream_ms = (time.perf_counter() - start) * 1000
        full_stream = b"".join(chunks)
        decoded = reader.decode(full_stream)

        return Sample(
            complete_ms=complete_ms,
            raw_ttft_ms=raw_ttft_ms,
            raw_stream_ms=raw_stream_ms,
            adapter_first_chunk_ms=first_chunk_ms or 0.0,
            adapter_first_partial_ms=first_partial_ms,
            adapter_stream_ms=adapter_stream_ms,
            adapter_chunks=len(chunks),
            adapter_partial_events=partial_events,
            complete_bytes=len(complete_bytes),
            stream_bytes=len(full_stream),
            complete_chars=len(str(doc.payload[0].value)),
            stream_chars=len(str(decoded.payload[0].value)),
            trace_steps=len(doc.trace),
            checksum_verified=final_doc is not None,
        )

    def run_thinking_once(
        self,
        prompt: str,
        max_tokens: int,
        thinking_budget_tokens: int,
    ) -> dict[str, float | int | bool | str]:
        adapter = self._adapter_cls(
            self._client,
            model=self.thinking_model,
            max_tokens=max(max_tokens, thinking_budget_tokens + 1),
        )
        reader = SPIFReader()
        writer = SPIFWriter()

        started = time.perf_counter()
        doc = adapter.complete(
            prompt,
            thinking=True,
            thinking_budget_tokens=thinking_budget_tokens,
        )
        latency_ms = (time.perf_counter() - started) * 1000
        encoded = writer.encode(doc)
        reader.decode(encoded)

        return {
            "model": self.thinking_model,
            "latency_ms": round(latency_ms, 1),
            "trace_steps": len(doc.trace),
            "payload_chars": len(str(doc.payload[0].value)),
            "encoded_bytes": len(encoded),
            "checksum_verified": True,
            "trace_method_live": doc.trace_method == "live",
        }

    def run_context_chain_once(
        self,
        prompt1: str,
        prompt2: str,
        max_tokens: int,
    ) -> dict[str, float | int | bool | str]:
        adapter = self._adapter_cls(self._client, model=self.model, max_tokens=max_tokens)
        reader = SPIFReader()
        writer = SPIFWriter()

        started_1 = time.perf_counter()
        doc1 = adapter.complete(prompt1)
        first_ms = (time.perf_counter() - started_1) * 1000

        started_2 = time.perf_counter()
        doc2 = adapter.complete(prompt2, context=doc1)
        second_ms = (time.perf_counter() - started_2) * 1000

        encoded_1 = writer.encode(doc1)
        encoded_2 = writer.encode(doc2)
        reader.decode(encoded_1)
        reader.decode(encoded_2)

        return {
            "first_turn_ms": round(first_ms, 1),
            "second_turn_ms": round(second_ms, 1),
            "chain_total_ms": round(first_ms + second_ms, 1),
            "context_ref_matches": doc2.provenance.context_ref == doc1.content_id(),
            "first_bytes": len(encoded_1),
            "second_bytes": len(encoded_2),
        }


class OpenAIBench(ProviderBench):
    def __init__(self, model: str) -> None:
        try:
            from openai import OpenAI
        except ImportError as e:
            raise SystemExit("openai SDK not installed. Run: pip install openai") from e
        if not os.environ.get("OPENAI_API_KEY"):
            raise SystemExit("OPENAI_API_KEY not set")
        from spif.adapters.openai_adapter import OpenAISPIFAdapter

        self.name = "openai"
        self.model = model
        self._client = OpenAI(api_key=os.environ["OPENAI_API_KEY"])
        self._adapter_cls = OpenAISPIFAdapter

    def _raw_stream_metrics(self, prompt: str, max_tokens: int) -> tuple[float, float]:
        started = time.perf_counter()
        first_token_ms: float | None = None
        for chunk in self._client.chat.completions.create(
            model=self.model,
            messages=[{"role": "user", "content": prompt}],
            max_tokens=max_tokens,
            temperature=1.0,
            stream=True,
        ):
            if not chunk.choices:
                continue
            delta = chunk.choices[0].delta
            content = getattr(delta, "content", None)
            if content and first_token_ms is None:
                first_token_ms = (time.perf_counter() - started) * 1000
        total_ms = (time.perf_counter() - started) * 1000
        return first_token_ms or total_ms, total_ms

    def run_once(self, complete_prompt: str, stream_prompt: str, max_tokens: int) -> Sample:
        adapter = self._adapter_cls(self._client, model=self.model, max_tokens=max_tokens)
        reader = SPIFReader()
        writer = SPIFWriter()

        t0 = time.perf_counter()
        doc = adapter.complete(complete_prompt)
        complete_ms = (time.perf_counter() - t0) * 1000
        complete_bytes = writer.encode(doc)
        reader.decode(complete_bytes)

        raw_ttft_ms, raw_stream_ms = self._raw_stream_metrics(stream_prompt, max_tokens)

        stream_reader = SPIFStreamReader()
        chunks: list[bytes] = []
        first_chunk_ms: float | None = None
        first_partial_ms: float | None = None
        partial_events = 0
        final_doc = None
        start = time.perf_counter()
        gen = adapter.stream(stream_prompt)
        try:
            while True:
                chunk = next(gen)
                now_ms = (time.perf_counter() - start) * 1000
                if first_chunk_ms is None:
                    first_chunk_ms = now_ms
                chunks.append(chunk)
                for event in stream_reader.feed(chunk):
                    if event.type == "partial_text":
                        partial_events += 1
                        if first_partial_ms is None:
                            first_partial_ms = (time.perf_counter() - start) * 1000
                    elif event.type == "verified":
                        final_doc = event.document
        except StopIteration as exc:
            if final_doc is None:
                final_doc = exc.value
        adapter_stream_ms = (time.perf_counter() - start) * 1000
        full_stream = b"".join(chunks)
        decoded = reader.decode(full_stream)

        return Sample(
            complete_ms=complete_ms,
            raw_ttft_ms=raw_ttft_ms,
            raw_stream_ms=raw_stream_ms,
            adapter_first_chunk_ms=first_chunk_ms or 0.0,
            adapter_first_partial_ms=first_partial_ms,
            adapter_stream_ms=adapter_stream_ms,
            adapter_chunks=len(chunks),
            adapter_partial_events=partial_events,
            complete_bytes=len(complete_bytes),
            stream_bytes=len(full_stream),
            complete_chars=len(str(doc.payload[0].value)),
            stream_chars=len(str(decoded.payload[0].value)),
            trace_steps=len(doc.trace),
            checksum_verified=final_doc is not None,
        )

    def run_context_chain_once(
        self,
        prompt1: str,
        prompt2: str,
        max_tokens: int,
    ) -> dict[str, float | int | bool | str]:
        adapter = self._adapter_cls(self._client, model=self.model, max_tokens=max_tokens)
        reader = SPIFReader()
        writer = SPIFWriter()

        started_1 = time.perf_counter()
        doc1 = adapter.complete(prompt1)
        first_ms = (time.perf_counter() - started_1) * 1000

        started_2 = time.perf_counter()
        doc2 = adapter.complete(prompt2, context=doc1)
        second_ms = (time.perf_counter() - started_2) * 1000

        encoded_1 = writer.encode(doc1)
        encoded_2 = writer.encode(doc2)
        reader.decode(encoded_1)
        reader.decode(encoded_2)

        return {
            "first_turn_ms": round(first_ms, 1),
            "second_turn_ms": round(second_ms, 1),
            "chain_total_ms": round(first_ms + second_ms, 1),
            "context_ref_matches": doc2.provenance.context_ref == doc1.content_id(),
            "first_bytes": len(encoded_1),
            "second_bytes": len(encoded_2),
        }


def _available_providers() -> list[str]:
    providers: list[str] = []
    if os.environ.get("ANTHROPIC_API_KEY"):
        providers.append("anthropic")
    if os.environ.get("OPENAI_API_KEY"):
        providers.append("openai")
    return providers


def _make_provider(
    name: str,
    anthropic_model: str,
    anthropic_thinking_model: str,
    openai_model: str,
) -> ProviderBench:
    if name == "anthropic":
        return AnthropicBench(anthropic_model, anthropic_thinking_model)
    if name == "openai":
        return OpenAIBench(openai_model)
    raise SystemExit(f"Unsupported provider: {name}")


def _print_summary(provider: str, model: str, summary: dict[str, Any]) -> None:
    print(f"\n## {provider} ({model})")
    print(f"runs                  {summary['runs']}")
    print(
        f"complete ms           {summary['complete_ms']['mean']:.1f} ± {summary['complete_ms']['stdev']:.1f}"
    )
    print(
        f"raw TTFT ms           {summary['raw_ttft_ms']['mean']:.1f} ± {summary['raw_ttft_ms']['stdev']:.1f}"
    )
    print(
        f"raw stream ms         {summary['raw_stream_ms']['mean']:.1f} ± {summary['raw_stream_ms']['stdev']:.1f}"
    )
    print(
        f"SPIF first chunk ms   {summary['adapter_first_chunk_ms']['mean']:.1f} ± {summary['adapter_first_chunk_ms']['stdev']:.1f}"
    )
    print(
        f"SPIF first partial ms {summary['adapter_first_partial_ms']['mean']:.1f} ± {summary['adapter_first_partial_ms']['stdev']:.1f}"
    )
    print(
        f"SPIF stream ms        {summary['adapter_stream_ms']['mean']:.1f} ± {summary['adapter_stream_ms']['stdev']:.1f}"
    )
    print(f"SPIF chunks           {summary['adapter_chunks']}")
    print(f"SPIF partial events   {summary['adapter_partial_events']}")
    print(f"complete bytes        {summary['complete_bytes']}")
    print(f"stream bytes          {summary['stream_bytes']}")
    print(f"checksum verified     {summary['checksum_verified_runs']}/{summary['runs']}")


def _print_optional_summary(title: str, summary: dict[str, Any]) -> None:
    print(f"\n### {title}")
    print(f"runs                  {summary['runs']}")
    for key, value in summary.items():
        if key == "runs":
            continue
        if isinstance(value, dict) and "mean" in value and "stdev" in value:
            print(f"{key:<22} {value['mean']:.1f} ± {value['stdev']:.1f}")
        else:
            print(f"{key:<22} {value}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Live API benchmark for SPIF adapters")
    parser.add_argument(
        "--provider",
        choices=["auto", "anthropic", "openai"],
        default="auto",
        help="Which provider to benchmark. 'auto' uses every provider with a configured API key.",
    )
    parser.add_argument("--reps", type=int, default=1, help="Number of live runs per provider")
    parser.add_argument("--max-tokens", type=int, default=64, help="max_tokens for each live request")
    parser.add_argument("--complete-prompt", default=DEFAULT_COMPLETE_PROMPT)
    parser.add_argument("--stream-prompt", default=DEFAULT_STREAM_PROMPT)
    parser.add_argument("--anthropic-model", default="claude-haiku-4-5-20251001")
    parser.add_argument("--anthropic-thinking-model", default="claude-sonnet-4-6")
    parser.add_argument("--openai-model", default="gpt-4o-mini")
    parser.add_argument("--with-thinking", action="store_true", help="Run an extra thinking-mode benchmark when supported")
    parser.add_argument("--thinking-prompt", default=DEFAULT_THINKING_PROMPT)
    parser.add_argument("--thinking-budget-tokens", type=int, default=2000)
    parser.add_argument("--with-context-chain", action="store_true", help="Run a two-turn context_ref chaining benchmark")
    parser.add_argument("--context-prompt-1", default=DEFAULT_CONTEXT_PROMPT_1)
    parser.add_argument("--context-prompt-2", default=DEFAULT_CONTEXT_PROMPT_2)
    parser.add_argument("--json", action="store_true", help="Emit JSON instead of a text summary")
    parser.add_argument("--out", metavar="PATH", help="Write the benchmark report JSON to a file")
    args = parser.parse_args()

    provider_names = _available_providers() if args.provider == "auto" else [args.provider]
    if not provider_names:
        raise SystemExit("No supported API keys found in the environment")

    report: dict[str, Any] = {
        "generated_at_ms": int(time.time() * 1000),
        "reps": args.reps,
        "providers": {},
    }

    for provider_name in provider_names:
        provider = _make_provider(
            provider_name,
            args.anthropic_model,
            args.anthropic_thinking_model,
            args.openai_model,
        )
        samples = [
            provider.run_once(args.complete_prompt, args.stream_prompt, args.max_tokens)
            for _ in range(args.reps)
        ]
        provider_report: dict[str, Any] = {
            "model": provider.model,
            "summary": _summarize(samples),
            "samples": [
                {
                    "complete_ms": round(s.complete_ms, 1),
                    "raw_ttft_ms": round(s.raw_ttft_ms, 1),
                    "raw_stream_ms": round(s.raw_stream_ms, 1),
                    "adapter_first_chunk_ms": round(s.adapter_first_chunk_ms, 1),
                    "adapter_first_partial_ms": None if s.adapter_first_partial_ms is None else round(s.adapter_first_partial_ms, 1),
                    "adapter_stream_ms": round(s.adapter_stream_ms, 1),
                    "adapter_chunks": s.adapter_chunks,
                    "adapter_partial_events": s.adapter_partial_events,
                    "complete_bytes": s.complete_bytes,
                    "stream_bytes": s.stream_bytes,
                    "complete_chars": s.complete_chars,
                    "stream_chars": s.stream_chars,
                    "trace_steps": s.trace_steps,
                    "checksum_verified": s.checksum_verified,
                }
                for s in samples
            ],
        }
        if args.with_thinking:
            thinking_samples = [
                provider.run_thinking_once(
                    args.thinking_prompt,
                    args.max_tokens,
                    args.thinking_budget_tokens,
                )
                for _ in range(args.reps)
            ]
            thinking_samples = [sample for sample in thinking_samples if sample is not None]
            if thinking_samples:
                provider_report["thinking"] = {
                    "summary": _summarize_numeric_samples(thinking_samples),
                    "samples": thinking_samples,
                }
        if args.with_context_chain:
            context_samples = [
                provider.run_context_chain_once(
                    args.context_prompt_1,
                    args.context_prompt_2,
                    args.max_tokens,
                )
                for _ in range(args.reps)
            ]
            context_samples = [sample for sample in context_samples if sample is not None]
            if context_samples:
                provider_report["context_chain"] = {
                    "summary": _summarize_numeric_samples(context_samples),
                    "samples": context_samples,
                }
        report["providers"][provider_name] = provider_report

    if args.out:
        Path(args.out).write_text(json.dumps(report, indent=2) + "\n")

    if args.json:
        print(json.dumps(report, indent=2))
        return

    print("# Live API Benchmark")
    print(f"reps: {args.reps}")
    for provider_name, provider_report in report["providers"].items():
        _print_summary(provider_name, provider_report["model"], provider_report["summary"])
        if "thinking" in provider_report:
            _print_optional_summary("thinking", provider_report["thinking"]["summary"])
        if "context_chain" in provider_report:
            _print_optional_summary("context_chain", provider_report["context_chain"]["summary"])


if __name__ == "__main__":
    main()
