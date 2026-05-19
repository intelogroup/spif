"""
Claude API extended thinking → SIF transformer.

Extended thinking blocks are the closest thing current LLMs produce to a
"live" reasoning trace — they are generated simultaneously with the output,
not narrated afterwards. This transformer maps them to SIF TraceStep nodes
with trace_method="live".

Usage:
    python tools/claude_to_sif.py --prompt "Why is the sky blue?" --output sky.sif
    sif render sky.sif
"""

from __future__ import annotations
import argparse
import hashlib
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import anthropic

from spfx import (
    SPIFDocument, Node, TraceStep, Distribution, Provenance, SPIFWriter, SPIFRenderer,
)
from spfx.format import (
    DIST_SEM_EPISTEMIC, TRACE_LIVE, TRACE_POSTHOC,
    STEP_EVIDENCE, STEP_INFERENCE, STEP_CONCLUSION,
    NODE_TOOL_CALL, NODE_TOOL_RESULT,
)

MODEL = "claude-sonnet-4-6"
THINKING_BUDGET = 8000


# ---------------------------------------------------------------------------
# Transformer
# ---------------------------------------------------------------------------

def _classify_step_type(content: str, index: int, total: int) -> str:
    """Heuristic: classify a thinking block as evidence/inference/conclusion."""
    if index == 0:
        return STEP_EVIDENCE
    if index == total - 1:
        return STEP_CONCLUSION
    return STEP_INFERENCE


def _heuristic_confidence_bucket(content: str) -> Distribution:
    """
    4-bucket word classifier over hedging language in thinking content.

    NOT statistically calibrated. Do not use for downstream decisions or
    quantitative comparisons. Outputs one of four fixed (mean, var) pairs
    based on which marker category dominates by count.

    semantics="custom:heuristic": explicitly not epistemic — this is a weak proxy
    signal for display/debugging only. Uses the "custom:" prefix per SPIF convention
    for non-standard semantics values.
    """
    low_markers = ["uncertain", "not sure", "unclear", "might", "possibly", "perhaps",
                   "i'm not confident", "hard to say", "it's unclear"]
    high_markers = ["definitely", "certainly", "clearly", "i'm confident", "i know",
                    "without doubt", "obviously", "sure"]
    medium_markers = ["likely", "probably", "seems", "appears", "i think", "i believe"]

    text = content.lower()
    low = sum(1 for m in low_markers if m in text)
    high = sum(1 for m in high_markers if m in text)
    medium = sum(1 for m in medium_markers if m in text)

    if high > low and high > medium:
        mean, var = 0.88, 0.02
    elif low > high:
        mean, var = 0.45, 0.08
    elif medium > 0:
        mean, var = 0.70, 0.05
    else:
        mean, var = 0.75, 0.05  # default

    return Distribution(mean=mean, var=var, shape="gaussian", semantics="custom:heuristic")


def _extract_tool_content(block) -> object:
    """Extract content from a tool_result block (may be string or list of content blocks)."""
    content = getattr(block, "content", None)
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for item in content:
            if hasattr(item, "text"):
                parts.append(item.text)
            else:
                parts.append(str(item))
        return "\n".join(parts)
    return str(content) if content is not None else ""


def claude_response_to_sif(
    response,
    prompt: str,
    request_params: dict,
) -> SPIFDocument:
    """Convert an Anthropic API response with extended thinking to a SIF document."""

    thinking_blocks = [b for b in response.content if b.type == "thinking"]
    text_blocks = [b for b in response.content if b.type == "text"]
    tool_use_blocks = [b for b in response.content if b.type == "tool_use"]
    # NOTE: tool_result blocks never appear in response.content — they are user-turn
    # messages. Tool results must be added by callers who manage multi-turn context.

    total = len(thinking_blocks)
    trace: list[TraceStep] = []

    for i, block in enumerate(thinking_blocks):
        step_type = _classify_step_type(block.thinking, i, total)
        confidence = _heuristic_confidence_bucket(block.thinking)
        deps = [f"s{i-1}"] if i > 0 else []

        trace.append(TraceStep(
            id=f"s{i}",
            type=step_type,
            content=block.thinking,
            confidence=confidence,
            deps=deps,
        ))

    tool_confidence = Distribution(mean=0.95, var=0.02, shape="gaussian",
                                   semantics="custom:heuristic")

    tool_call_nodes: list[Node] = [
        Node(
            id=f"tool_call_{b.id}",
            type=NODE_TOOL_CALL,
            value={"name": b.name, "arguments": b.input, "call_id": b.id},
            confidence=tool_confidence,
        )
        for b in tool_use_blocks
    ]

    # Payload: tool nodes first, then text output nodes
    text_nodes: list[Node] = []
    for j, block in enumerate(text_blocks):
        # Averaged heuristic bucket — not calibrated, semantics="custom:heuristic"
        if trace:
            avg_mean = sum(s.confidence.mean for s in trace) / len(trace)
            avg_var = sum(s.confidence.var for s in trace) / len(trace)
            conf = Distribution(mean=avg_mean, var=avg_var, shape="gaussian",
                                semantics="custom:heuristic")
        else:
            conf = Distribution.certain()

        text_nodes.append(Node(
            id=f"output_{j}",
            type="text",
            value=block.text,
            confidence=conf,
        ))

    payload_nodes = tool_call_nodes + text_nodes
    if not payload_nodes:
        payload_nodes = [Node(id="output_0", type="text", value="(no text output)")]

    input_hash = hashlib.sha256(prompt.encode()).hexdigest()

    return SPIFDocument(
        payload=payload_nodes,
        trace=trace,
        trace_method=TRACE_LIVE if thinking_blocks else TRACE_POSTHOC,
        provenance=Provenance(
            source_model=response.model,
            model_version=response.model,
            temperature=request_params.get("temperature", 1.0),
            input_hash=input_hash,
            timestamp_ms=int(time.time() * 1000),
        ),
    )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Claude API → SIF transformer")
    parser.add_argument("--prompt", required=True, help="Prompt to send to Claude")
    parser.add_argument("--output", default="output.sif", help="Output SIF file path")
    parser.add_argument("--model", default=MODEL, help="Claude model ID")
    parser.add_argument("--budget", type=int, default=THINKING_BUDGET,
                        help="Extended thinking token budget")
    parser.add_argument("--no-render", action="store_true",
                        help="Skip rendering to stdout")
    args = parser.parse_args()

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        print("ERROR: ANTHROPIC_API_KEY not set", file=sys.stderr)
        sys.exit(1)

    client = anthropic.Anthropic(api_key=api_key)

    print(f"Calling {args.model} with extended thinking (budget={args.budget})...")
    request_params = {
        "model": args.model,
        "max_tokens": args.budget + 2000,
        "thinking": {"type": "enabled", "budget_tokens": args.budget},
        "temperature": 1,  # required for extended thinking
        "messages": [{"role": "user", "content": args.prompt}],
    }

    response = client.messages.create(**request_params)

    thinking_count = sum(1 for b in response.content if b.type == "thinking")
    text_count = sum(1 for b in response.content if b.type == "text")
    tool_call_count = sum(1 for b in response.content if b.type == "tool_use")
    parts = [f"{thinking_count} thinking block(s)", f"{text_count} text block(s)"]
    if tool_call_count:
        parts.append(f"{tool_call_count} tool call(s)")
    print(f"Got {', '.join(parts)}")

    doc = claude_response_to_sif(response, args.prompt, request_params)

    SPIFWriter().write(doc, args.output)
    print(f"Written: {args.output}  ({Path(args.output).stat().st_size} bytes)")

    if not args.no_render:
        print()
        print(SPIFRenderer().render(doc))


if __name__ == "__main__":
    main()
