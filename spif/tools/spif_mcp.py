"""
SPIF MCP Server — expose SPIF as Model Context Protocol tools.

Tools:
  call_claude   — call Claude and return the response as SPIF lossless-JSON
  wrap_text     — wrap a pre-existing plain text response into SPIF lossless-JSON

Usage (standalone):
    python tools/spif_mcp.py

Claude Desktop config (~/.claude/claude_desktop_config.json):
    {
      "mcpServers": {
        "spfx": {
          "command": "python",
          "args": ["/path/to/brainex/sif/tools/spif_mcp.py"]
        }
      }
    }

Requirements (not in core spfx dependencies):
    pip install anthropic fastmcp
"""

from __future__ import annotations

import hashlib
import json
import sys
import time
from pathlib import Path
from typing import Optional

# Allow running directly without installing the package
sys.path.insert(0, str(Path(__file__).parent.parent))

from fastmcp import FastMCP

from spif.exporters.lossless_json import to_lossless_json
from spif.format import NODE_TEXT
from spif.types import Distribution, Node, Provenance, SPIFDocument

mcp = FastMCP(
    "spfx",
    instructions=(
        "Tools for calling Claude and wrapping model responses as SPIF documents. "
        "SPIF (Semantic Provenance Inference Format) adds provenance, uncertainty, "
        "and reasoning trace metadata to AI outputs. "
        "call_claude returns lossless-JSON — pass it directly to another model. "
        "wrap_text adds SPIF metadata to any pre-existing text response."
    ),
)

_DEFAULT_CONFIDENCE = Distribution(
    mean=0.85,
    var=0.05,
    shape="gaussian",
    semantics="output_stability",
)


@mcp.tool()
def call_claude(
    prompt: str,
    model: str = "claude-sonnet-4-6",
    thinking: bool = False,
    thinking_budget_tokens: int = 8000,
    context_ref: str = "",
) -> str:
    """
    Call Claude and return the response as a SPIF lossless-JSON document.

    The returned JSON preserves full provenance (model, timestamp, input hash),
    uncertainty metadata, and reasoning trace (if thinking=True).
    Pass it directly to another model — no base64 encoding needed.
    Size scales with content: a minimal single-node response is ~80 tokens;
    a full trace with 10+ steps is ~400–600 tokens.

    Use from_lossless_json() to reconstruct a SPIFDocument from the result.

    Args:
        prompt: The user message to send to Claude.
        model: Claude model ID (default: claude-sonnet-4-6).
        thinking: Enable extended thinking (provides richer trace, forces temperature=1).
        thinking_budget_tokens: Token budget for thinking blocks (default: 8000).
        context_ref: content_id() of a prior SPIF document this continues (for audit chains).

    Returns:
        SPIF lossless-JSON string.
    """
    try:
        import anthropic
    except ImportError:
        raise RuntimeError("anthropic package required: pip install anthropic")

    from spif.adapters.anthropic_adapter import AnthropicSPIFAdapter

    client = anthropic.Anthropic()
    adapter = AnthropicSPIFAdapter(client, model=model, context_ref=context_ref)
    doc = adapter.complete(
        prompt,
        thinking=thinking,
        thinking_budget_tokens=thinking_budget_tokens,
    )
    return to_lossless_json(doc)


@mcp.tool()
def wrap_text(
    text: str,
    model: str,
    temperature: float = 1.0,
    prompt: str = "",
    context_ref: str = "",
) -> str:
    """
    Wrap a plain text model response in a SPIF lossless-JSON document.

    Use this when you already have a response from any model and want to add
    SPIF provenance (model identity, timestamp, input hash, context chain).
    Confidence uses a conservative fixed prior — no logprobs available.

    Args:
        text: The model response text to wrap.
        model: Model identifier (e.g. "gpt-4o", "claude-sonnet-4-6").
        temperature: Sampling temperature used (recorded in provenance).
        prompt: The prompt that produced this text (used to compute input_hash).
        context_ref: content_id() of a prior SPIF document (for audit chains).

    Returns:
        SPIF lossless-JSON string.
    """
    messages = [{"role": "user", "content": prompt}] if prompt else []
    input_hash = (
        hashlib.sha256(
            json.dumps(messages, sort_keys=True, ensure_ascii=False).encode()
        ).hexdigest()
        if messages
        else ""
    )

    doc = SPIFDocument(
        payload=[
            Node(
                id="response",
                type=NODE_TEXT,
                value=text,
                confidence=_DEFAULT_CONFIDENCE,
                refs=[],
            )
        ],
        provenance=Provenance(
            source_model=model,
            model_version=model,
            temperature=temperature,
            input_hash=input_hash,
            context_ref=context_ref,
            timestamp_ms=int(time.time() * 1000),
        ),
        trace=[],
        trace_method="post-hoc",
        semantic=None,
        alternatives=[],
        delta=None,
        signature=None,
        signatures=[],
    )
    return to_lossless_json(doc)


if __name__ == "__main__":
    mcp.run()
