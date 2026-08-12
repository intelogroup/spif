"""
Live demo: OpenAI API → streaming SPIF → terminal + saved file.

Run:
    OPENAI_API_KEY=sk-... python examples/streaming_openai.py
    OPENAI_API_KEY=sk-... python examples/streaming_openai.py --model gpt-4o-mini
    OPENAI_API_KEY=sk-... python examples/streaming_openai.py --save out.spif
    OPENAI_API_KEY=sk-... python examples/streaming_openai.py --no-logprobs

Requires: pip install openai
"""

from __future__ import annotations

import argparse
import sys
import time

try:
    import openai
except ImportError:
    sys.exit("openai SDK not installed.  Run: pip install openai")

from spif.adapters.openai_adapter import OpenAISPIFAdapter
from spif.streaming import SPIFStreamReader
from spif.renderer import SPIFRenderer


def main() -> None:
    parser = argparse.ArgumentParser(description="Stream OpenAI → SPIF")
    parser.add_argument("prompt", nargs="?",
                        default="Explain what makes a binary file format trustworthy "
                                "in exactly three sentences.")
    parser.add_argument("--model", default="gpt-4o")
    parser.add_argument("--save", metavar="PATH",
                        help="Save the final SPIF document to this path")
    parser.add_argument("--no-logprobs", action="store_true",
                        help="Disable logprob-based confidence (use default distribution)")
    args = parser.parse_args()

    client = openai.OpenAI()
    adapter = OpenAISPIFAdapter(
        client,
        model=args.model,
        logprobs=not args.no_logprobs,
    )

    print(f"\n[streaming SPIF ← {args.model}]\n")
    print("─" * 60)

    all_bytes: list[bytes] = []
    reader = SPIFStreamReader()
    doc = None
    t0 = time.perf_counter()

    gen = adapter.stream(args.prompt)
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
