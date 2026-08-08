"""
Live demo: Claude API → streaming SPIF → terminal + saved file.

Run:
    ANTHROPIC_API_KEY=sk-... python examples/streaming_claude.py
    ANTHROPIC_API_KEY=sk-... python examples/streaming_claude.py --thinking
    ANTHROPIC_API_KEY=sk-... python examples/streaming_claude.py --save out.spfx

Requires: pip install anthropic
"""

from __future__ import annotations

import argparse
import sys
import time

try:
    import anthropic
except ImportError:
    sys.exit("anthropic SDK not installed.  Run: pip install anthropic")

from spif.adapters.anthropic_adapter import AnthropicSPIFAdapter
from spif.streaming import SPIFStreamReader
from spif.renderer import SPIFRenderer


def main() -> None:
    parser = argparse.ArgumentParser(description="Stream Claude → SPIF")
    parser.add_argument("prompt", nargs="?",
                        default="Explain what makes a binary file format trustworthy "
                                "in exactly three sentences.")
    parser.add_argument("--thinking", action="store_true",
                        help="Enable extended thinking (claude-sonnet-4-6 only)")
    parser.add_argument("--save", metavar="PATH",
                        help="Save the final SPIF document to this path")
    parser.add_argument("--model", default="claude-sonnet-4-6")
    args = parser.parse_args()

    client = anthropic.Anthropic()
    adapter = AnthropicSPIFAdapter(client, model=args.model, temperature=1.0)

    print(f"\n[streaming SPIF ← {args.model}]\n")
    print("─" * 60)

    all_bytes: list[bytes] = []
    reader = SPIFStreamReader()
    doc = None
    t0 = time.perf_counter()

    gen = adapter.stream(
        args.prompt,
        thinking=args.thinking,
        thinking_budget_tokens=4000 if args.thinking else 0,
    )

    try:
        while True:
            chunk = next(gen)
            all_bytes.append(chunk)
            for event in reader.feed(chunk):
                if event.type == "partial_text":
                    print(event.text, end="", flush=True)
                elif event.type == "verified":
                    doc = event.document
                elif event.type == "error":
                    print(f"\n[SPIF stream error: {event.error}]", file=sys.stderr)
    except StopIteration as e:
        if doc is None:
            doc = e.value

    elapsed = time.perf_counter() - t0
    full_spif = b"".join(all_bytes)

    print(f"\n{'─' * 60}")
    print(f"[{len(full_spif):,} bytes  |  {elapsed:.2f}s  |  checksum verified]")

    if doc:
        print("\n" + SPIFRenderer().render(doc))

    if args.save:
        with open(args.save, "wb") as f:
            f.write(full_spif)
        print(f"\n[saved → {args.save}]")


if __name__ == "__main__":
    main()
