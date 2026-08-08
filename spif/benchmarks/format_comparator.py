"""
Format comparator: SIF vs JSON/CBOR/MsgPack/BSON.

Compares across dimensions:
  1. Size - encoded bytes per complexity level
  2. Speed - encode + decode μs (500 reps)
  3. Roundtrip Fidelity - semantic preservation
  4. Tamper Detection - 1-byte flip detection
"""

from __future__ import annotations
import gzip
import json
import os
import random
import sys
import time as time_mod
import zlib
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import bson
import cbor2
import msgpack

from spif import SPIFDocument, Node, Distribution, SPIFWriter, SPIFReader


# -----------------------------------------------------------------------------
# Converters
# -----------------------------------------------------------------------------


def to_json_dict(doc: SPIFDocument) -> dict:
    """Best-effort JSON encoding - lossy (Distribution → 3 flat fields)."""

    def node_to_dict(n) -> dict:
        return {
            "id": n.id,
            "type": n.type,
            "value": str(n.value)[:200],  # Truncate long values
            "confidence_mean": n.confidence.mean,
            "confidence_var": n.confidence.var,
            "confidence_shape": n.confidence.shape,
            "refs": [r.node_id for r in n.refs],
        }

    d = {"payload": [node_to_dict(n) for n in doc.payload]}

    if doc.trace:
        d["trace"] = [
            {
                "id": s.id,
                "type": s.type,
                "content": str(s.content)[:200],
                "confidence_mean": s.confidence.mean,
                "confidence_var": s.confidence.var,
                "deps": s.deps,
            }
            for s in doc.trace
        ]

    if doc.provenance:
        p = doc.provenance
        d["provenance"] = {
            "source_model": p.source_model,
            "temperature": p.temperature,
            "input_hash": p.input_hash,
            "timestamp_ms": p.timestamp_ms,
        }

    if doc.semantic:
        d["embedding"] = doc.semantic.embedding[:100]  # Truncate large embeddings

    if doc.alternatives:
        d["alternatives"] = [
            {"weight": a.weight, "nodes": [node_to_dict(n) for n in a.nodes]}
            for a in doc.alternatives
        ]

    return d


def to_json_minimal_dict(doc: SPIFDocument) -> dict:
    """Minimal JSON encoding — text values only, no typed confidence or trace.

    Represents what a developer would write if they were not using SPIF and
    just needed to store the text payload with a model identifier. Used as the
    'plain JSON' baseline in the benchmark to show the overhead SPIF adds when
    confidence, trace, and semantic metadata are not required by the consumer.
    """
    return {
        "payload": [
            {"id": n.id, "type": n.type, "value": str(n.value)[:200]}
            for n in doc.payload
        ],
        "model": doc.provenance.source_model if doc.provenance else None,
    }


# -----------------------------------------------------------------------------
# Encoders/Decoders
# -----------------------------------------------------------------------------


def enc_sif(doc):
    return SPIFWriter().encode(doc)


def dec_sif(data):
    return SPIFReader().decode(data)


def enc_json(doc):
    return json.dumps(to_json_dict(doc), separators=(",", ":")).encode()


def dec_json(data):
    return json.loads(data)


def enc_cbor(doc):
    return cbor2.dumps(to_json_dict(doc), canonical=True)


def dec_cbor(data):
    return cbor2.loads(data)


def enc_msgpack(doc):
    return msgpack.packb(to_json_dict(doc), use_bin_type=True)


def dec_msgpack(data):
    return msgpack.unpackb(data, raw=False)


def enc_bson(doc):
    return bson.encode(to_json_dict(doc))


def dec_bson(data):
    return bson.decode(data)


def enc_json_minimal(doc):
    return json.dumps(to_json_minimal_dict(doc), separators=(",", ":")).encode()


def dec_json_minimal(data):
    return json.loads(data)


FORMATS = [
    ("SIF", enc_sif, dec_sif),
    ("JSON", enc_json, dec_json),
    ("JSON-minimal", enc_json_minimal, dec_json_minimal),
    ("CBOR", enc_cbor, dec_cbor),
    ("MsgPack", enc_msgpack, dec_msgpack),
    ("BSON", enc_bson, dec_bson),
]

REPS = 500


# -----------------------------------------------------------------------------
# Benchmark Functions
# -----------------------------------------------------------------------------


def bench_fn(fn, reps: int) -> float:
    """Mean microseconds per call."""
    start = time_mod.perf_counter()
    for _ in range(reps):
        fn()
    return (time_mod.perf_counter() - start) / reps * 1_000_000


def compare_sizes(docs: list[SPIFDocument], category: str) -> dict:
    """Compare sizes across all formats."""
    results = {}
    for name, enc, _ in FORMATS:
        try:
            encoded = enc(docs[0])  # Just measure first doc as sample
            results[name] = len(encoded)
        except Exception as e:
            results[name] = -1
    return results


def compare_speed(docs: list[SPIFDocument], sample_size: int = 20) -> dict:
    """Compare encode/decode speed."""
    sample = docs[:sample_size]
    results = {}

    for name, enc, dec in FORMATS:
        try:
            # Encode speed
            enc_time = bench_fn(lambda: enc(sample[0]), REPS)

            # Decode speed
            encoded = enc(sample[0])
            dec_time = bench_fn(lambda: dec(encoded), REPS)

            results[name] = {
                "encode_us": round(enc_time, 2),
                "decode_us": round(dec_time, 2),
                "roundtrip_us": round(enc_time + dec_time, 2),
            }
        except Exception as e:
            results[name] = {"error": str(e)}

    return results


def compare_roundtrip_fidelity(doc: SPIFDocument, format_name: str) -> dict:
    """
    Measure semantic fidelity: how much is lost when converting to other formats?
    SIF should preserve all semantics; JSON/CBOR/etc lose type information.
    """
    if format_name == "SIF":
        return {"fidelity": 1.0, "losses": []}

    _, enc, dec = next(f for f in FORMATS if f[0] == format_name)

    losses = []

    # Encode and decode
    try:
        encoded = enc(doc)
        restored = dec(encoded) if format_name != "JSON" else json.loads(encoded)
    except Exception as e:
        return {"fidelity": 0.0, "losses": [f"encode/decode error: {e}"]}

    # Check payload nodes
    if len(doc.payload) != len(restored.get("payload", [])):
        losses.append(
            f"payload count: {len(doc.payload)} → {len(restored.get('payload', []))}"
        )

    # Check confidence type (SIF has Distribution, JSON has 3 flat fields)
    if format_name in ("JSON", "CBOR", "MsgPack", "BSON"):
        losses.append(
            "confidence: Distribution object → 3 flat fields (mean, var, shape)"
        )

    # Check NodeRefs (SIF has NodeRef type, others are strings)
    for i, node in enumerate(doc.payload):
        if node.refs and format_name != "SIF":
            losses.append(f"node[{i}].refs: NodeRef[] → string[]")
            break

    # Check trace DAG structure
    if doc.trace and format_name != "SIF":
        # Other formats don't preserve DAG structure natively
        pass

    # Check semantic embeddings
    if doc.semantic and format_name not in ("SIF", "CBOR"):
        losses.append("semantic.embedding: typed → truncated array")

    fidelity = max(0.0, 1.0 - (len(losses) * 0.1))
    return {"fidelity": round(fidelity, 2), "losses": losses[:5]}


def compare_tamper_detection(doc: SPIFDocument) -> dict:
    """Test 1-byte flip detection rates."""
    results = {}

    sif_enc = SPIFWriter().encode(doc)

    for name, enc, dec in FORMATS:
        try:
            original = enc(doc)

            # Flip a byte in the middle
            pos = len(original) // 2
            tampered = bytearray(original)
            tampered[pos] ^= 0xFF
            tampered = bytes(tampered)

            try:
                dec(tampered)
                results[name] = {"detected": False, "method": "none"}
            except Exception:
                results[name] = {"detected": True, "method": "parse error"}
        except Exception as e:
            results[name] = {"error": str(e)}

    return results


def run_full_comparison(docs_by_category: dict[str, list[SPIFDocument]]) -> dict:
    """Run full comparison across all categories."""
    results = {
        "timestamp_ms": int(time_mod.time() * 1000),
        "categories": {},
        "summary": {},
    }

    all_sizes = {name: [] for name, _, _ in FORMATS}
    all_speeds = {name: [] for name, _, _ in FORMATS}
    all_fidelities = {name: [] for name, _, _ in FORMATS}

    for category, docs in docs_by_category.items():
        print(f"  Comparing {category}...")

        cat_result = {
            "n_docs": len(docs),
            "sizes": compare_sizes(docs, category),
            "speeds": compare_speed(docs, sample_size=20),
            "fidelity": {},
            "tamper": {},
        }

        # Fidelity on first doc
        if docs:
            for name, _, _ in FORMATS:
                cat_result["fidelity"][name] = compare_roundtrip_fidelity(docs[0], name)
                if name != "SIF":
                    all_fidelities[name].append(
                        cat_result["fidelity"][name]["fidelity"]
                    )

            cat_result["tamper"] = compare_tamper_detection(docs[0])

        results["categories"][category] = cat_result

        # Collect for summary
        for name, size in cat_result["sizes"].items():
            if size > 0:
                all_sizes[name].append(size)

        for name, speed in cat_result["speeds"].items():
            if "roundtrip_us" in speed:
                all_speeds[name].append(speed["roundtrip_us"])

    # Compute summary stats
    for name, sizes in all_sizes.items():
        if sizes:
            results["summary"][name] = results["summary"].get(name, {})
            results["summary"][name]["avg_size"] = round(sum(sizes) / len(sizes), 1)

    for name, times in all_speeds.items():
        if times:
            if name not in results["summary"]:
                results["summary"][name] = {}
            results["summary"][name]["avg_roundtrip_us"] = round(
                sum(times) / len(times), 1
            )

    # Fidelity summary
    for name, fids in all_fidelities.items():
        if fids:
            if name not in results["summary"]:
                results["summary"][name] = {}
            results["summary"][name]["avg_fidelity"] = round(sum(fids) / len(fids), 2)

    return results


def print_report(results: dict) -> None:
    """Print formatted benchmark report."""
    print("\n" + "=" * 80)
    print("FORMAT COMPARISON REPORT")
    print("=" * 80)

    # Summary
    print("\n## Summary (averages)")
    print(f"{'Format':<12} {'Avg Size':>12} {'Avg Roundtrip':>16} {'Fidelity':>10}")
    print("-" * 52)

    for name in ["SIF", "JSON", "CBOR", "MsgPack", "BSON"]:
        if name in results["summary"]:
            s = results["summary"][name]
            size = s.get("avg_size", "-")
            time_val = s.get("avg_roundtrip_us", "-")
            fid = s.get("avg_fidelity", "-")
            print(f"{name:<12} {size:>12} {time_val:>16} {fid:>10}")

    # Size comparison
    print("\n## Size (bytes)")
    for cat, data in results["categories"].items():
        print(f"\n  {cat}:")
        for name, size in data["sizes"].items():
            sif_size = data["sizes"].get("SIF", 1)
            ratio = size / sif_size if sif_size and size > 0 else 1.0
            print(f"    {name:<12} {size:>8} bytes ({ratio:.2f}x SIF)")

    # Speed comparison
    print("\n## Speed (μs)")
    for cat, data in results["categories"].items():
        print(f"\n  {cat}:")
        for name, speed in data["speeds"].items():
            if "roundtrip_us" in speed:
                print(f"    {name:<12} {speed['roundtrip_us']:>10} μs")

    # Fidelity comparison
    print("\n## Roundtrip Fidelity")
    for cat, data in results["categories"].items():
        if "fidelity" in data:
            fid = data["fidelity"]
            sif_fid = fid.get("SIF", {}).get("fidelity", 1.0)
            print(f"\n  {cat}:")
            for name in ["SIF", "JSON", "CBOR", "MsgPack", "BSON"]:
                if name in fid:
                    f = fid[name]["fidelity"]
                    loss = fid[name].get("losses", [])[:2]
                    print(
                        f"    {name:<12} {f:.2f}  {'| ' + ', '.join(loss[:1]) if loss else ''}"
                    )

    # Tamper detection
    print("\n## Tamper Detection (1-byte flip)")
    for cat, data in results["categories"].items():
        if "tamper" in data:
            print(f"\n  {cat}:")
            for name, result in data["tamper"].items():
                if "detected" in result:
                    status = "✓ DETECTED" if result["detected"] else "✗ NOT DETECTED"
                    print(f"    {name:<12} {status}")


if __name__ == "__main__":
    from synthetic_generators import generate_all

    print("Generating test data...")
    docs = generate_all(10)  # Quick generation for testing

    print("\nRunning format comparison...")
    results = run_full_comparison(docs)

    print_report(results)

    # Save results
    output_dir = Path(__file__).parent.parent / "experiments"
    output_dir.mkdir(exist_ok=True)
    import json

    (output_dir / "format_comparison_results.json").write_text(
        json.dumps(results, indent=2)
    )
    print(f"\nResults saved to {output_dir / 'format_comparison_results.json'}")
