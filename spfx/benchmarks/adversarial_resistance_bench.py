"""
Adversarial resistance benchmark: systematic byte mutation across N SPIF documents.

For each document encoded in SPIF, JSON, CBOR, and MsgPack, applies M random single-byte
mutations and records whether each format detected or silently accepted the corruption.

Outputs: human-readable summary table + optional JSON results file.

Usage:
    python benchmarks/adversarial_resistance_bench.py [--docs N] [--mutations M] [--seed S] [--output FILE] [--quick]
"""
from __future__ import annotations

import argparse
import json
import os
import random
import sys
import time as _time
from dataclasses import dataclass, field, asdict
from pathlib import Path

import cbor2
import msgpack

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from spfx import SPIFDocument, SPIFWriter, SPIFReader, Node
from spfx.types import Distribution, Provenance, TraceStep
from spfx import SemanticLayer
from benchmarks.bench_size import (
    doc_minimal, doc_medium, doc_with_trace, doc_full,
    to_json_dict, to_cbor_raw, to_msgpack_raw,
)

# ---------------------------------------------------------------------------
# Document corpus
# ---------------------------------------------------------------------------

def _make_corpus(n: int, rng: random.Random) -> list[SPIFDocument]:
    """Produce n documents evenly spread across complexity levels."""
    factories = [doc_minimal, doc_medium, doc_with_trace, doc_full]
    return [factories[i % len(factories)]() for i in range(n)]


# ---------------------------------------------------------------------------
# Mutation
# ---------------------------------------------------------------------------

def _mutate(data: bytes, rng: random.Random, pos: int | None = None) -> bytes:
    """Flip one random byte (uniform xor with 0x01–0xFF)."""
    arr = bytearray(data)
    idx = pos if pos is not None else rng.randint(0, len(arr) - 1)
    arr[idx] ^= rng.randint(1, 255)
    return bytes(arr)


# ---------------------------------------------------------------------------
# Per-format decode attempt
# ---------------------------------------------------------------------------

_writer = SPIFWriter()
_reader = SPIFReader()


def _try_spif(data: bytes) -> str:
    """Return error category or 'silent'."""
    try:
        _reader.decode(data)
        return "silent"
    except Exception as e:
        name = type(e).__name__
        if "Checksum" in name:
            return "checksum"
        if "Signature" in name:
            return "signature"
        if "Magic" in name:
            return "magic"
        if "Version" in name:
            return "version"
        return "format"


def _try_json(data: bytes) -> str:
    try:
        json.loads(data)
        return "silent"
    except Exception:
        return "parse"


def _try_cbor(data: bytes) -> str:
    try:
        cbor2.loads(data)
        return "silent"
    except Exception:
        return "parse"


def _try_msgpack(data: bytes) -> str:
    try:
        msgpack.unpackb(data, raw=False)
        return "silent"
    except Exception:
        return "parse"


# ---------------------------------------------------------------------------
# Benchmark
# ---------------------------------------------------------------------------

@dataclass
class FormatStats:
    name: str
    total_mutations: int = 0
    detected: int = 0
    silent: int = 0
    error_types: dict = field(default_factory=dict)

    @property
    def detection_rate(self) -> float:
        return self.detected / self.total_mutations if self.total_mutations else 0.0

    def record(self, outcome: str) -> None:
        self.total_mutations += 1
        if outcome == "silent":
            self.silent += 1
        else:
            self.detected += 1
        self.error_types[outcome] = self.error_types.get(outcome, 0) + 1


@dataclass
class BenchResult:
    n_docs: int
    mutations_per_doc: int
    seed: int
    formats: list[FormatStats]
    elapsed_s: float


def run(n_docs: int = 100, mutations: int = 50, seed: int = 42,
        output: str | None = None) -> BenchResult:
    rng = random.Random(seed)
    corpus = _make_corpus(n_docs, rng)

    stats = {
        "SPIF":    FormatStats("SPIF"),
        "JSON":    FormatStats("JSON"),
        "CBOR":    FormatStats("CBOR"),
        "MsgPack": FormatStats("MsgPack"),
    }

    # False-positive check: encode valid docs, decode — must all succeed
    fp_errors = 0
    for doc in corpus:
        try:
            _reader.decode(_writer.encode(doc))
        except Exception:
            fp_errors += 1
    if fp_errors:
        print(f"WARNING: {fp_errors}/{n_docs} valid SPIF docs failed to decode (false positives)")

    t0 = _time.perf_counter()

    for doc in corpus:
        spif_data = _writer.encode(doc)
        json_data = json.dumps(to_json_dict(doc)).encode()
        cbor_data = to_cbor_raw(doc)
        mp_data   = to_msgpack_raw(doc)

        for _ in range(mutations):
            stats["SPIF"].record(_try_spif(_mutate(spif_data, rng)))
            stats["JSON"].record(_try_json(_mutate(json_data, rng)))
            stats["CBOR"].record(_try_cbor(_mutate(cbor_data, rng)))
            stats["MsgPack"].record(_try_msgpack(_mutate(mp_data, rng)))

    elapsed = _time.perf_counter() - t0

    result = BenchResult(
        n_docs=n_docs,
        mutations_per_doc=mutations,
        seed=seed,
        formats=list(stats.values()),
        elapsed_s=elapsed,
    )

    _print_results(result, fp_errors)

    if output:
        _save_json(result, fp_errors, output)
        print(f"\nResults saved to {output}")

    return result


def _print_results(r: BenchResult, fp_errors: int) -> None:
    total = r.n_docs * r.mutations_per_doc
    print(f"\n## Adversarial Resistance Benchmark\n")
    print(f"  Documents: {r.n_docs}  |  Mutations/doc: {r.mutations_per_doc}  "
          f"|  Total mutations: {total}  |  Seed: {r.seed}")
    print(f"  SPIF false positives (valid docs rejected): {fp_errors}/{r.n_docs}")
    print(f"  Elapsed: {r.elapsed_s:.1f}s\n")

    hdr = f"{'Format':<10} {'Detected':>10} {'Silent':>8} {'Rate':>8}  {'Error type distribution'}"
    print(hdr)
    print("-" * 70)

    for fs in r.formats:
        rate_pct = fs.detection_rate * 100
        # sort error types by count desc
        et_sorted = sorted(fs.error_types.items(), key=lambda x: -x[1])
        et_str = "  ".join(f"{k}={v}" for k, v in et_sorted)
        print(f"{fs.name:<10} {fs.detected:>10,} {fs.silent:>8,} {rate_pct:>7.1f}%  {et_str}")

    print()
    print("Notes:")
    print("  SPIF: SHA-256 checksum covers full body — any byte change is detected on decode.")
    print("  JSON: only detects mutations that break UTF-8 / JSON syntax (rare for body bytes).")
    print("  CBOR: structured encoding catches some mutations via type/length field corruption.")
    print("  MsgPack: similar to CBOR.")
    print("  Detection rate = % of mutations that raised an error on decode/parse.")


def _save_json(r: BenchResult, fp_errors: int, path: str) -> None:
    data = {
        "n_docs": r.n_docs,
        "mutations_per_doc": r.mutations_per_doc,
        "seed": r.seed,
        "elapsed_s": round(r.elapsed_s, 3),
        "false_positives": fp_errors,
        "formats": [
            {
                "name": fs.name,
                "total_mutations": fs.total_mutations,
                "detected": fs.detected,
                "silent": fs.silent,
                "detection_rate": round(fs.detection_rate, 4),
                "error_types": fs.error_types,
            }
            for fs in r.formats
        ],
    }
    Path(path).write_text(json.dumps(data, indent=2))


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--docs",      type=int, default=100,  help="Number of documents")
    ap.add_argument("--mutations", type=int, default=50,   help="Mutations per document")
    ap.add_argument("--seed",      type=int, default=42,   help="RNG seed")
    ap.add_argument("--output",    type=str, default=None, help="Save JSON results to this path")
    ap.add_argument("--quick",     action="store_true",    help="Quick run: 10 docs, 20 mutations")
    args = ap.parse_args()

    if args.quick:
        run(n_docs=10, mutations=20, seed=args.seed, output=args.output)
    else:
        run(n_docs=args.docs, mutations=args.mutations, seed=args.seed, output=args.output)
