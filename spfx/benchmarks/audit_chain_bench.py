"""
Audit chain benchmark: SPIF context_ref chains vs. alternative approaches.

Creates N-hop AI call chains and measures:
  - Chain construction time (μs/hop)
  - Chain verification time (μs)
  - Tamper detection (modify one link → verify chain)
  - Ergonomics: LOC to build + verify

Alternatives:
  1. SPIF context_ref    — built-in deterministic content_id, checksum per hop
  2. External manifest   — separate JSON file mapping step→SHA-256
  3. JSON hash chain     — each dict stores SHA-256 of previous dict bytes
  4. Flat JSON array     — ordered list, no integrity

Usage:
    python benchmarks/audit_chain_bench.py [--hops N] [--chains N] [--quick]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time as _time
from dataclasses import dataclass

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from spfx import SPIFDocument, SPIFWriter, SPIFReader, Node, compute_content_id
from spfx.types import Distribution, Provenance

# ---------------------------------------------------------------------------
# Synthetic hop factory
# ---------------------------------------------------------------------------

def _make_hop(step: int, context_ref: str = "", model: str = "claude-sonnet-4-6") -> SPIFDocument:
    return SPIFDocument(
        payload=[
            Node(
                id=f"step_{step}_response",
                type="text",
                value=f"Response at step {step}: reasoning about the problem continues here.",
                confidence=Distribution(mean=0.85, var=0.03, shape="gaussian",
                                        semantics="output_stability"),
            )
        ],
        provenance=Provenance(
            source_model=model,
            model_version=model,
            temperature=0.7,
            input_hash=hashlib.sha256(f"step_{step}".encode()).hexdigest(),
            context_ref=context_ref,
            timestamp_ms=1_700_000_000_000 + step * 1000,
        ),
    )


def _hop_to_json_dict(step: int, content: str, prev_hash: str = "") -> dict:
    return {
        "step": step,
        "model": "claude-sonnet-4-6",
        "content": content,
        "timestamp_ms": 1_700_000_000_000 + step * 1000,
        "prev_hash": prev_hash,
    }


# ---------------------------------------------------------------------------
# SPIF chain
# ---------------------------------------------------------------------------

def _build_spif_chain(hops: int) -> list[bytes]:
    writer = SPIFWriter()
    chain: list[bytes] = []
    prev_doc: SPIFDocument | None = None

    for step in range(hops):
        context_ref = prev_doc.content_id() if prev_doc else ""
        doc = _make_hop(step, context_ref=context_ref)
        encoded = writer.encode(doc)
        chain.append(encoded)
        prev_doc = SPIFReader().decode(encoded)  # round-trip to normalise

    return chain


def _verify_spif_chain(chain: list[bytes]) -> tuple[bool, str]:
    """Walk chain from start, verify each hop's context_ref links to previous."""
    reader = SPIFReader()
    prev_cid: str | None = None

    for i, encoded in enumerate(chain):
        try:
            doc = reader.decode(encoded)  # raises on checksum failure
        except Exception as e:
            return False, f"hop {i} decode failed: {e}"

        if i == 0:
            if doc.provenance and doc.provenance.context_ref:
                return False, f"hop 0 must have empty context_ref"
        else:
            cref = doc.provenance.context_ref if doc.provenance else ""
            if cref != prev_cid:
                return False, (
                    f"hop {i} context_ref mismatch: "
                    f"expected {prev_cid!r}, got {cref!r}"
                )

        prev_cid = doc.content_id()

    return True, "ok"


# ---------------------------------------------------------------------------
# External manifest chain
# ---------------------------------------------------------------------------

def _build_manifest_chain(hops: int) -> tuple[list[dict], list[str]]:
    """Returns (manifest_entries, json_docs_as_strings). Manifest holds SHA-256 per hop."""
    manifest: list[dict] = []
    docs: list[str] = []

    for step in range(hops):
        d = _hop_to_json_dict(step, f"Response at step {step}: reasoning continues.")
        doc_str = json.dumps(d)
        sha256 = hashlib.sha256(doc_str.encode()).hexdigest()
        manifest.append({"step": step, "sha256": sha256})
        docs.append(doc_str)

    return manifest, docs


def _verify_manifest_chain(manifest: list[dict], docs: list[str]) -> tuple[bool, str]:
    for entry in manifest:
        step = entry["step"]
        expected_sha = entry["sha256"]
        actual_sha = hashlib.sha256(docs[step].encode()).hexdigest()
        if actual_sha != expected_sha:
            return False, f"hop {step} SHA-256 mismatch"
    return True, "ok"


# ---------------------------------------------------------------------------
# JSON hash chain
# ---------------------------------------------------------------------------

def _build_json_hash_chain(hops: int) -> list[str]:
    """Each dict stores SHA-256 of previous doc bytes (blockchain-lite)."""
    chain: list[str] = []
    prev_hash = ""

    for step in range(hops):
        d = _hop_to_json_dict(step, f"Response at step {step}: reasoning continues.",
                              prev_hash=prev_hash)
        doc_str = json.dumps(d)
        chain.append(doc_str)
        prev_hash = hashlib.sha256(doc_str.encode()).hexdigest()

    return chain


def _verify_json_hash_chain(chain: list[str]) -> tuple[bool, str]:
    prev_hash = ""
    for i, doc_str in enumerate(chain):
        d = json.loads(doc_str)
        if d.get("prev_hash", "") != prev_hash:
            return False, f"hop {i} prev_hash mismatch"
        prev_hash = hashlib.sha256(doc_str.encode()).hexdigest()
    return True, "ok"


# ---------------------------------------------------------------------------
# Flat JSON array (no chain)
# ---------------------------------------------------------------------------

def _build_flat_array(hops: int) -> str:
    docs = [
        _hop_to_json_dict(step, f"Response at step {step}: reasoning continues.")
        for step in range(hops)
    ]
    return json.dumps(docs)


def _verify_flat_array(_data: str) -> tuple[bool, str]:
    return False, "no integrity mechanism — cannot verify"


# ---------------------------------------------------------------------------
# Tamper helpers
# ---------------------------------------------------------------------------

def _tamper_spif_chain(chain: list[bytes], step: int) -> list[bytes]:
    """Replace SPIF doc at `step` with a different document (different content_id)."""
    writer = SPIFWriter()
    tampered = list(chain)
    modified_doc = _make_hop(step, context_ref="", model="gpt-4o")  # different model
    tampered[step] = writer.encode(modified_doc)
    return tampered


def _tamper_manifest_docs(docs: list[str], step: int) -> list[str]:
    tampered = list(docs)
    d = json.loads(docs[step])
    d["content"] = "MODIFIED CONTENT"
    tampered[step] = json.dumps(d)
    return tampered


def _tamper_hash_chain(chain: list[str], step: int) -> list[str]:
    tampered = list(chain)
    d = json.loads(chain[step])
    d["content"] = "MODIFIED CONTENT"
    tampered[step] = json.dumps(d)
    return tampered


# ---------------------------------------------------------------------------
# Benchmark
# ---------------------------------------------------------------------------

def _mean_us(fn, reps: int) -> float:
    t = _time.perf_counter()
    for _ in range(reps):
        fn()
    return (_time.perf_counter() - t) / reps * 1_000_000


@dataclass
class ChainResult:
    name: str
    build_us_per_hop: float
    verify_us: float
    verify_ok: bool
    tamper_detected: bool
    chain_bytes: int
    loc_build: int
    loc_verify: int


def run(hops: int = 5, chains: int = 50) -> None:
    results: list[ChainResult] = []

    # ---- SPIF ----
    spif_chain = _build_spif_chain(hops)
    spif_chain_bytes = sum(len(b) for b in spif_chain)

    build_spif_us = _mean_us(lambda: _build_spif_chain(hops), chains) / hops
    verify_spif_us = _mean_us(lambda: _verify_spif_chain(spif_chain), chains)
    spif_ok, _ = _verify_spif_chain(spif_chain)

    tampered_spif = _tamper_spif_chain(spif_chain, hops // 2)
    spif_tamper_ok, _ = _verify_spif_chain(tampered_spif)

    results.append(ChainResult(
        name="SPIF context_ref",
        build_us_per_hop=build_spif_us,
        verify_us=verify_spif_us,
        verify_ok=spif_ok,
        tamper_detected=not spif_tamper_ok,
        chain_bytes=spif_chain_bytes,
        loc_build=3,   # context_ref=prev.content_id()
        loc_verify=4,  # decode + context_ref == prev_cid
    ))

    # ---- External manifest ----
    manifest, docs = _build_manifest_chain(hops)
    manifest_bytes = len(json.dumps(manifest).encode()) + sum(len(d.encode()) for d in docs)

    build_manifest_us = _mean_us(lambda: _build_manifest_chain(hops), chains) / hops
    verify_manifest_us = _mean_us(lambda: _verify_manifest_chain(manifest, docs), chains)
    manifest_ok, _ = _verify_manifest_chain(manifest, docs)

    tampered_docs = _tamper_manifest_docs(docs, hops // 2)
    manifest_tamper_ok, _ = _verify_manifest_chain(manifest, tampered_docs)

    results.append(ChainResult(
        name="External manifest",
        build_us_per_hop=build_manifest_us,
        verify_us=verify_manifest_us,
        verify_ok=manifest_ok,
        tamper_detected=not manifest_tamper_ok,
        chain_bytes=manifest_bytes,
        loc_build=5,   # sha256(doc) → manifest entry
        loc_verify=6,  # recompute sha256, compare with manifest
    ))

    # ---- JSON hash chain ----
    hash_chain = _build_json_hash_chain(hops)
    hash_chain_bytes = sum(len(d.encode()) for d in hash_chain)

    build_hash_us = _mean_us(lambda: _build_json_hash_chain(hops), chains) / hops
    verify_hash_us = _mean_us(lambda: _verify_json_hash_chain(hash_chain), chains)
    hash_ok, _ = _verify_json_hash_chain(hash_chain)

    tampered_hash = _tamper_hash_chain(hash_chain, hops // 2)
    hash_tamper_ok, _ = _verify_json_hash_chain(tampered_hash)

    results.append(ChainResult(
        name="JSON hash chain",
        build_us_per_hop=build_hash_us,
        verify_us=verify_hash_us,
        verify_ok=hash_ok,
        tamper_detected=not hash_tamper_ok,
        chain_bytes=hash_chain_bytes,
        loc_build=4,   # prev_hash = sha256(prev_doc)
        loc_verify=5,  # recompute, compare
    ))

    # ---- Flat array ----
    flat = _build_flat_array(hops)
    flat_bytes = len(flat.encode())

    build_flat_us = _mean_us(lambda: _build_flat_array(hops), chains) / hops
    verify_flat_us = _mean_us(lambda: _verify_flat_array(flat), chains)
    flat_ok, _ = _verify_flat_array(flat)

    results.append(ChainResult(
        name="Flat JSON array",
        build_us_per_hop=build_flat_us,
        verify_us=verify_flat_us,
        verify_ok=flat_ok,
        tamper_detected=False,  # flat array has no integrity
        chain_bytes=flat_bytes,
        loc_build=1,
        loc_verify=0,
    ))

    _print_results(results, hops)


def _yn(v: bool) -> str:
    return "YES" if v else "NO"


def _print_results(results: list[ChainResult], hops: int) -> None:
    print(f"\n## Audit Chain Benchmark ({hops}-hop chains)\n")

    hdr = (f"{'Approach':<22} {'Build μs/hop':>13} {'Verify μs':>10} "
           f"{'Chain OK':>9} {'Tamper det.':>12} {'Chain B':>8} "
           f"{'Build LOC':>10} {'Verify LOC':>11}")
    print(hdr)
    print("-" * len(hdr))

    for r in results:
        print(
            f"{r.name:<22} {r.build_us_per_hop:>12.1f}μ {r.verify_us:>9.1f}μ "
            f"{_yn(r.verify_ok):>9} {_yn(r.tamper_detected):>12} {r.chain_bytes:>8,} "
            f"{r.loc_build:>10} {r.loc_verify:>11}"
        )

    print()
    print("Notes:")
    print("  Build μs/hop = time to produce one chained document (encode + link).")
    print("  Verify μs    = time to walk the full chain and verify all links.")
    print("  Tamper det.  = modifying one hop in the middle is detected by verify().")
    print()
    print("  SPIF: context_ref + content_id are built-in — no external manifest file.")
    print("  SPIF: checksum on decode catches byte-level corruption before chain walk.")
    print("  SPIF: content_id is stable across re-encodes (excludes signature/embedding).")
    print("  External manifest: requires keeping manifest in sync with docs (operational burden).")
    print("  JSON hash chain: tamper in step N breaks verification of N+1 too (good),")
    print("    but requires re-signing the whole tail on any legitimate update.")
    print("  Flat array: no integrity — cannot detect insertion, deletion, or modification.")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--hops",   type=int, default=5,  help="Chain length")
    ap.add_argument("--chains", type=int, default=50, help="Bench repetitions")
    ap.add_argument("--quick",  action="store_true",  help="Fewer reps")
    args = ap.parse_args()

    run(hops=args.hops, chains=10 if args.quick else args.chains)
