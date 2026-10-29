#!/usr/bin/env python3
"""
PQ hybrid benchmark — SPIF v1.4 integrated path (SPEC §7.9).

Re-measures the Phase D spike numbers against the shipped v1.4
implementation (spif.pq_hybrid as a supported module, the reader gate,
and the trust layer), to confirm the integration added no regression:

- sign: `sign_document_hybrid` (spike prototype: median 14.73 ms)
- strict verify: `SPIFReader.verify_signature(require_pq=True)` and
  `spif.trust.verify_artifact(require_pq=True)` (spike's strict report
  path: median 0.53 ms)
- classical verify for contrast: `SPIFReader.verify_signature()`
  (ed25519 component only)
- artifact sizes: unsigned / ed25519 / hybrid (SPEC §7.9.1 records the
  hybrid delta: +5,925 B with the self-describing signer)

Timings are medians over N runs (default 50).

Usage:  python benchmarks/pq_hybrid_bench.py [--runs 50] [--write]
--write also saves the markdown table to benchmarks/pq_hybrid_results.md.
Requires: the spif package plus the `pqcrypto` backend (the 'pq' extra).
"""

from __future__ import annotations

import argparse
import statistics
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "spif-py"))

from spif import Node, Provenance, SPIFDocument, SPIFReader, SPIFWriter
from spif.crypto import derive_key_from_mnemonic, sign_document
from spif.pq_hybrid import generate_hybrid_keypair, sign_document_hybrid
from spif.trust import verify_artifact
from spif.types import Distribution

RUNS_DEFAULT = 50


def _doc() -> SPIFDocument:
    return SPIFDocument(
        payload=[
            Node(
                id=f"n{i}",
                type="fact",
                value={"kind": "text", "data": f"pq bench fact {i}"},
                confidence=Distribution.certain("epistemic"),
            )
            for i in range(5)
        ],
        provenance=Provenance(source_model="bench-model", timestamp_ms=1700000000000),
    )


def _median_ms(fn, runs: int) -> float:
    samples = []
    for _ in range(runs):
        t0 = time.perf_counter()
        fn()
        samples.append((time.perf_counter() - t0) * 1000.0)
    return statistics.median(samples)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs", type=int, default=RUNS_DEFAULT)
    ap.add_argument("--write", action="store_true")
    args = ap.parse_args()

    doc = _doc()
    unsigned = SPIFWriter().encode(doc)
    ed_priv = derive_key_from_mnemonic(" ".join(["legal"] * 24), "")
    ed_signed = sign_document(_doc(), ed_priv)
    kp = generate_hybrid_keypair()
    hybrid = sign_document_hybrid(
        _doc(), kp.ed_private_key, kp.ml_secret_key, kp.ml_public_key
    )

    reader = SPIFReader()
    rows = [
        ("sign hybrid (integrated)", _median_ms(
            lambda: sign_document_hybrid(
                _doc(), kp.ed_private_key, kp.ml_secret_key, kp.ml_public_key
            ), args.runs), "14.73 (spike prototype)"),
        ("verify hybrid strict — reader gate", _median_ms(
            lambda: reader.verify_signature(hybrid, require_pq=True),
            args.runs), "0.53 (spike strict report)"),
        ("verify hybrid strict — trust layer", _median_ms(
            lambda: verify_artifact(hybrid, require_pq=True), args.runs), "—"),
        ("verify hybrid classical — reader gate", _median_ms(
            lambda: reader.verify_signature(hybrid), args.runs), "—"),
        ("sign ed25519 (baseline)", _median_ms(
            lambda: sign_document(_doc(), ed_priv), args.runs), "0.16 (spike)"),
        ("verify ed25519 (baseline)", _median_ms(
            lambda: reader.verify_signature(ed_signed), args.runs), "0.19 (spike)"),
    ]

    lines = [
        "# PQ hybrid benchmark — v1.4 integrated path",
        "",
        f"Medians of {args.runs} runs, this machine. Spike reference: "
        "docs/PQ_SPIKE_VERDICT.md (Phase D).",
        "",
        "| Operation | Median (ms) | Spike reference (ms) |",
        "|---|---|---|",
    ]
    for name, ms, ref in rows:
        lines.append(f"| {name} | {ms:.2f} | {ref} |")
    lines += [
        "",
        f"Artifact sizes: unsigned {len(unsigned)} B · ed25519 "
        f"{len(ed_signed)} B · hybrid {len(hybrid)} B "
        f"(hybrid − ed25519 = {len(hybrid) - len(ed_signed):+} B; "
        "SPEC §7.9.1 records +5,925 B).",
        "",
    ]
    out = "\n".join(lines)
    print(out)
    if args.write:
        target = Path(__file__).with_name("pq_hybrid_results.md")
        target.write_text(out)
        print(f"wrote {target}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
