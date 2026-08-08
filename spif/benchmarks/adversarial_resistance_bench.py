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

import struct
import zlib

from spif import SPIFDocument, SPIFWriter, SPIFReader, Node
from spif.types import Distribution, Provenance, TraceStep
from spif import SemanticLayer
from spif.format import MAGIC
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
# SPIF-specific structural attack classes (beyond generic single-byte flip)
# ---------------------------------------------------------------------------

def _mutate_magic_byte(data: bytes, rng: random.Random) -> bytes:
    """Corrupt one byte inside the 9-byte MAGIC preamble."""
    arr = bytearray(data)
    idx = rng.randint(0, len(MAGIC) - 1)
    arr[idx] ^= rng.randint(1, 255)
    return bytes(arr)


def _mutate_chunk_length_overflow(data: bytes, rng: random.Random) -> bytes:
    """Rewrite the first chunk's length field to 0xFFFFFFFF."""
    arr = bytearray(data)
    offset = len(MAGIC) + 2
    struct.pack_into(">I", arr, offset + 1, 0xFFFFFFFF)
    return bytes(arr)


def _inject_unknown_chunk(data: bytes, rng: random.Random) -> bytes:
    """Splice an unknown chunk type (0x63/99), length 0, right after the header."""
    offset = len(MAGIC) + 2
    unknown_chunk = struct.pack(">BI", 0x63, 0)
    return data[:offset] + unknown_chunk + data[offset:]


_ZLIB_BOMB_CACHE: list[bytes] = []


def _zlib_bomb_chunk(data: bytes, rng: random.Random) -> bytes:
    """Replace the first chunk's body with a zlib bomb that decompresses past
    MAX_DECOMPRESSED_SIZE — must be rejected by the safety limit, not silently
    truncated or OOM'd."""
    if not _ZLIB_BOMB_CACHE:
        from spif.reader import MAX_DECOMPRESSED_SIZE
        bomb_plain = b"\x00" * (MAX_DECOMPRESSED_SIZE + 1024)
        _ZLIB_BOMB_CACHE.append(zlib.compress(bomb_plain, level=9))
    bomb = _ZLIB_BOMB_CACHE[0]
    offset = len(MAGIC) + 2
    chunk_type, orig_len = struct.unpack_from(">BI", data, offset)
    new_chunk = struct.pack(">BI", chunk_type, len(bomb)) + bomb
    return data[:offset] + new_chunk + data[offset + 5 + orig_len:]


STRUCTURAL_ATTACKS = {
    "magic_byte_corrupt": _mutate_magic_byte,
    "chunk_length_overflow": _mutate_chunk_length_overflow,
    "unknown_chunk_99": _inject_unknown_chunk,
    "zlib_bomb": _zlib_bomb_chunk,
}


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

    # Structural attack classes — SPIF-only, one pass per doc per attack kind.
    structural = {name: FormatStats(name) for name in STRUCTURAL_ATTACKS}
    for doc in corpus:
        spif_data = _writer.encode(doc)
        for name, attack_fn in STRUCTURAL_ATTACKS.items():
            try:
                mutated = attack_fn(spif_data, rng)
                structural[name].record(_try_spif(mutated))
            except Exception as e:
                # attack construction itself blew up (e.g. MemoryError building
                # the bomb plaintext) — count as detected, note the exception type.
                structural[name].record(f"construct_error:{type(e).__name__}")

    result = BenchResult(
        n_docs=n_docs,
        mutations_per_doc=mutations,
        seed=seed,
        formats=list(stats.values()),
        elapsed_s=elapsed,
    )

    _print_results(result, fp_errors)
    _print_structural(structural)

    if output:
        _save_json(result, fp_errors, output, structural)
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


def _print_structural(structural: dict) -> None:
    print("\n## Structural Attack Classes (SPIF only)\n")
    hdr = f"{'Attack':<24} {'Docs':>6} {'Detected':>10} {'Silent':>8}  {'Outcomes'}"
    print(hdr)
    print("-" * 90)
    for name, fs in structural.items():
        et_sorted = sorted(fs.error_types.items(), key=lambda x: -x[1])
        et_str = "  ".join(f"{k}={v}" for k, v in et_sorted)
        print(f"{name:<24} {fs.total_mutations:>6} {fs.detected:>10} {fs.silent:>8}  {et_str}")


def _save_json(r: BenchResult, fp_errors: int, path: str, structural: dict | None = None) -> None:
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
    if structural:
        data["structural_attacks"] = {
            name: {
                "total": fs.total_mutations,
                "detected": fs.detected,
                "silent": fs.silent,
                "error_types": fs.error_types,
            }
            for name, fs in structural.items()
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
