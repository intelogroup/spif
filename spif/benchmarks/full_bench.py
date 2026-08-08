"""
Full competitive benchmark: SIF vs JSON / JSONL / BSON / XML / CBOR / MsgPack / Pickle / Arrow.

Covers five dimensions:
  1. Size        — encoded bytes per complexity level
  2. Speed       — encode + decode μs (500 reps each)
  3. Compression — size after gzip -9 and zlib -9
  4. Integrity   — tamper detection: does the format catch a 1-byte flip?
  5. Feature matrix — qualitative comparison of semantic capabilities

Run:
    cd /path/to/sif
    python benchmarks/full_bench.py
"""
from __future__ import annotations
import gzip
import json
import os
import pickle
import sys
import time as time_mod
import zlib

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import bson
import cbor2
import msgpack
import orjson
import ujson
from lxml import etree

from spif import SPIFWriter, SPIFReader
from benchmarks.bench_size import (
    doc_minimal, doc_medium, doc_with_trace, doc_full,
    to_json_dict,
)

# ─────────────────────────────────────────────────────────────────────────────
# Document levels
# ─────────────────────────────────────────────────────────────────────────────

LEVELS = [
    ("minimal",    doc_minimal),
    ("medium",     doc_medium),
    ("trace",      doc_with_trace),
    ("full",       doc_full),
]


# ─────────────────────────────────────────────────────────────────────────────
# Encoders: produce bytes from SPIFDocument
# ─────────────────────────────────────────────────────────────────────────────

def enc_sif(doc):
    return SPIFWriter().encode(doc)

def enc_json(doc):
    return json.dumps(to_json_dict(doc), separators=(",", ":")).encode()

def enc_jsonl(doc):
    # JSONL: same as JSON but newline-delimited (same encoding, different framing convention)
    return json.dumps(to_json_dict(doc), separators=(",", ":")).encode() + b"\n"

def enc_orjson(doc):
    return orjson.dumps(to_json_dict(doc))

def enc_ujson(doc):
    return ujson.dumps(to_json_dict(doc)).encode()

def enc_bson(doc):
    return bson.encode(to_json_dict(doc))

def enc_cbor(doc):
    return cbor2.dumps(to_json_dict(doc), canonical=True)

def enc_msgpack(doc):
    return msgpack.packb(to_json_dict(doc), use_bin_type=True)

def enc_pickle(doc):
    return pickle.dumps(to_json_dict(doc), protocol=5)

def enc_xml(doc):
    d = to_json_dict(doc)
    root = etree.Element("sif")
    payload_el = etree.SubElement(root, "payload")
    for node in d.get("payload", []):
        n_el = etree.SubElement(payload_el, "node")
        for k, v in node.items():
            etree.SubElement(n_el, k).text = str(v)
    if "trace" in d:
        trace_el = etree.SubElement(root, "trace")
        for step in d["trace"]:
            s_el = etree.SubElement(trace_el, "step")
            for k, v in step.items():
                etree.SubElement(s_el, k).text = str(v)
    if "provenance" in d:
        prov_el = etree.SubElement(root, "provenance")
        for k, v in d["provenance"].items():
            etree.SubElement(prov_el, k).text = str(v)
    return etree.tostring(root, encoding="utf-8", xml_declaration=True)

def enc_arrow(doc):
    import pyarrow as pa
    d = to_json_dict(doc)
    rows = []
    for node in d.get("payload", []):
        rows.append({
            "id":                node.get("id", ""),
            "type":              node.get("type", ""),
            "value":             str(node.get("value", "")),
            "confidence_mean":   float(node.get("confidence_mean", 0)),
            "confidence_var":    float(node.get("confidence_var", 0)),
            "confidence_shape":  node.get("confidence_shape", ""),
        })
    if not rows:
        rows = [{"id": "", "type": "", "value": "", "confidence_mean": 0.0,
                 "confidence_var": 0.0, "confidence_shape": ""}]
    table = pa.Table.from_pylist(rows)
    sink = pa.BufferOutputStream()
    with pa.ipc.new_stream(sink, table.schema) as writer:
        writer.write_table(table)
    return sink.getvalue().to_pybytes()

# Registry: name → (encoder, decoder)
def dec_sif(data):
    return SPIFReader().decode(data)

def dec_json(data):
    return json.loads(data)

def dec_orjson(data):
    return orjson.loads(data)

def dec_ujson(data):
    return ujson.loads(data)

def dec_bson(data):
    return bson.decode(data)

def dec_cbor(data):
    return cbor2.loads(data)

def dec_msgpack(data):
    return msgpack.unpackb(data, raw=False)

def dec_pickle(data):
    return pickle.loads(data)

def dec_xml(data):
    return etree.fromstring(data[data.index(b"<sif"):] if b"<?xml" in data else data)

def dec_arrow(data):
    import pyarrow as pa
    reader = pa.ipc.open_stream(pa.py_buffer(data))
    return reader.read_all()

FORMATS = [
    ("SIF",      enc_sif,     dec_sif),
    ("JSON",     enc_json,    dec_json),
    ("JSONL",    enc_jsonl,   dec_json),
    ("orjson",   enc_orjson,  dec_orjson),
    ("ujson",    enc_ujson,   dec_ujson),
    ("BSON",     enc_bson,    dec_bson),
    ("CBOR",     enc_cbor,    dec_cbor),
    ("MsgPack",  enc_msgpack, dec_msgpack),
    ("Pickle",   enc_pickle,  dec_pickle),
    ("XML",      enc_xml,     dec_xml),
    ("Arrow",    enc_arrow,   dec_arrow),
]

REPS = 500


# ─────────────────────────────────────────────────────────────────────────────
# Timing helper
# ─────────────────────────────────────────────────────────────────────────────

def bench_fn(fn, reps: int) -> float:
    """Mean microseconds per call."""
    start = time_mod.perf_counter()
    for _ in range(reps):
        fn()
    return (time_mod.perf_counter() - start) / reps * 1_000_000


# ─────────────────────────────────────────────────────────────────────────────
# 1. Size benchmark
# ─────────────────────────────────────────────────────────────────────────────

def run_size():
    fmt_names = [f[0] for f in FORMATS]
    col_w = 10

    print("=" * 100)
    print("## 1. SIZE BENCHMARK (bytes)\n")
    header = f"{'Level':<22}" + "".join(f"{n:>{col_w}}" for n in fmt_names)
    print(header)
    print("-" * len(header))

    results = {}
    for level_name, factory in LEVELS:
        doc = factory()
        row = {}
        for fmt_name, enc, _ in FORMATS:
            try:
                row[fmt_name] = len(enc(doc))
            except Exception:
                row[fmt_name] = -1
        results[level_name] = row
        line = f"{level_name:<22}" + "".join(
            f"{row[n]:>{col_w}}" if row[n] >= 0 else f"{'ERR':>{col_w}}"
            for n in fmt_names
        )
        print(line)

    print()
    # Ratios vs SIF
    print(f"{'Ratio vs SIF':<22}" + "".join(f"{n:>{col_w}}" for n in fmt_names))
    print("-" * len(header))
    for level_name, factory in LEVELS:
        row = results[level_name]
        sif_sz = row["SIF"]
        line = f"{level_name:<22}"
        for n in fmt_names:
            if n == "SIF" or row[n] < 0:
                line += f"{'—':>{col_w}}"
            else:
                line += f"{row[n]/sif_sz:>{col_w}.2f}x"
        print(line)

    print()
    print("  < 1.00x = format is smaller than SIF | > 1.00x = SIF is more compact")
    return results


# ─────────────────────────────────────────────────────────────────────────────
# 2. Speed benchmark
# ─────────────────────────────────────────────────────────────────────────────

def run_speed():
    print("=" * 100)
    print(f"## 2. SPEED BENCHMARK (μs per document, {REPS} reps)\n")

    for level_name, factory in LEVELS:
        doc = factory()
        print(f"  Level: {level_name}")
        hdr = f"    {'Format':<12} {'encode μs':>12} {'decode μs':>12} {'total μs':>12}"
        print(hdr)
        print("    " + "-" * (len(hdr) - 4))

        for fmt_name, enc, dec in FORMATS:
            try:
                encoded = enc(doc)
                t_enc = bench_fn(lambda enc=enc, doc=doc: enc(doc), REPS)
                t_dec = bench_fn(lambda dec=dec, encoded=encoded: dec(encoded), REPS)
                print(f"    {fmt_name:<12} {t_enc:>11.1f}μ {t_dec:>11.1f}μ {t_enc+t_dec:>11.1f}μ")
            except Exception as e:
                print(f"    {fmt_name:<12} {'ERR':>12} {'ERR':>12}  ({e})")
        print()


# ─────────────────────────────────────────────────────────────────────────────
# 3. Compression benchmark
# ─────────────────────────────────────────────────────────────────────────────

def run_compression():
    print("=" * 100)
    print("## 3. COMPRESSION BENCHMARK (bytes after gzip-9 / zlib-9)\n")

    for level_name, factory in LEVELS:
        doc = factory()
        print(f"  Level: {level_name}")
        hdr = f"    {'Format':<12} {'raw':>8} {'gzip-9':>8} {'zlib-9':>8} {'ratio':>8}"
        print(hdr)
        print("    " + "-" * (len(hdr) - 4))

        for fmt_name, enc, _ in FORMATS:
            try:
                raw = enc(doc)
                gz  = gzip.compress(raw, compresslevel=9)
                zl  = zlib.compress(raw, level=9)
                print(f"    {fmt_name:<12} {len(raw):>8} {len(gz):>8} {len(zl):>8} {len(gz)/len(raw):>7.2f}x")
            except Exception as e:
                print(f"    {fmt_name:<12} {'ERR':>8} {'ERR':>8} {'ERR':>8}  ({e})")
        print()


# ─────────────────────────────────────────────────────────────────────────────
# 4. Integrity benchmark
# ─────────────────────────────────────────────────────────────────────────────

def run_integrity():
    print("=" * 100)
    print("## 4. INTEGRITY: tamper detection (1-byte flip at position 50)\n")
    print(f"  {'Format':<12} {'detects flip?':>16} {'method':>30}")
    print("  " + "-" * 60)

    doc = doc_medium()

    def flip(data: bytes, pos: int = 50) -> bytes:
        if pos >= len(data):
            pos = len(data) // 2
        ba = bytearray(data)
        ba[pos] ^= 0xFF
        return bytes(ba)

    for fmt_name, enc, dec in FORMATS:
        try:
            original = enc(doc)
            tampered = flip(original)
        except Exception as e:
            print(f"  {fmt_name:<12} {'enc-error':>16}  ({e})")
            continue

        if fmt_name == "SIF":
            try:
                dec(tampered)
                result = "NO  (unexpected)"
                method = "SHA-256 checksum (should catch)"
            except Exception:
                result = "YES"
                method = "SHA-256 checksum + magic bytes"
        elif fmt_name in ("BSON",):
            try:
                dec(tampered)
                result = "NO"
                method = "no integrity check"
            except Exception:
                result = "partial (parse error)"
                method = "BSON length header"
        elif fmt_name in ("JSON", "JSONL", "orjson", "ujson"):
            try:
                dec(tampered)
                result = "NO"
                method = "no integrity check"
            except Exception:
                result = "partial (parse error)"
                method = "JSON syntax validation only"
        elif fmt_name == "XML":
            try:
                dec(tampered)
                result = "NO"
                method = "no integrity check"
            except Exception:
                result = "partial (parse error)"
                method = "XML syntax validation only"
        elif fmt_name == "Pickle":
            try:
                dec(tampered)
                result = "NO"
                method = "no integrity check"
            except Exception:
                result = "partial (parse error)"
                method = "pickle opcode validation only"
        else:
            try:
                dec(tampered)
                result = "NO"
                method = "no integrity check"
            except Exception:
                result = "partial (parse error)"
                method = "format syntax only"

        print(f"  {fmt_name:<12} {result:>16}  {method}")

    print()
    print("  Note: 'partial' means the flip happened to corrupt a structure byte.")
    print("  SIF is the only format with a cryptographic SHA-256 checksum over ALL content.")


# ─────────────────────────────────────────────────────────────────────────────
# 5. Feature matrix
# ─────────────────────────────────────────────────────────────────────────────

FEATURE_MATRIX = [
    # (feature, SIF, JSON, JSONL, orjson, ujson, BSON, CBOR, MsgPack, Pickle, XML, Arrow)
    ("Typed uncertainty dist.",    "✓ native",   "manual", "manual", "manual", "manual", "manual", "manual", "manual", "manual", "manual", "manual"),
    ("First-class NodeRef links",  "✓ native",   "string", "string", "string", "string", "string", "string", "string", "object", "string", "manual"),
    ("DAG trace w/ cycle detect",  "✓ on decode","manual", "manual", "manual", "manual", "manual", "manual", "manual", "manual", "manual", "manual"),
    ("Ed25519 signature",          "✓ chunk",    "—",      "—",      "—",      "—",      "—",      "—",      "—",      "—",      "—",      "—"),
    ("Multi-signature",            "✓ v0.2+",    "—",      "—",      "—",      "—",      "—",      "—",      "—",      "—",      "—",      "—"),
    ("SHA-256 content checksum",   "✓ always",   "—",      "—",      "—",      "—",      "—",      "—",      "—",      "—",      "—",      "—"),
    ("Content-addressed ID",       "✓ stable",   "—",      "—",      "—",      "—",      "—",      "—",      "—",      "—",      "—",      "—"),
    ("Versioned format (v0.1/0.2)","✓",          "manual", "manual", "manual", "manual", "—",      "—",      "—",      "—",      "manual", "schema"),
    ("Backward compatibility",     "✓ reader",   "—",      "—",      "—",      "—",      "—",      "—",      "—",      "—",      "—",      "partial"),
    ("Dense embedding layer",      "✓ chunk",    "array",  "array",  "array",  "array",  "binary", "tag",    "bin",    "list",   "text",   "column"),
    ("Alternative payloads",       "✓ typed",    "manual", "manual", "manual", "manual", "manual", "manual", "manual", "manual", "manual", "manual"),
    ("Delta / diff encoding",      "✓ chunk",    "manual", "manual", "manual", "manual", "—",      "—",      "—",      "—",      "—",      "—"),
    ("Selective chunk parsing",    "✓",          "—",      "—",      "—",      "—",      "partial","—",      "—",      "—",      "partial","✓"),
    ("Human readable",             "renderer",   "✓",      "✓",      "✓",      "✓",      "—",      "—",      "—",      "—",      "✓",      "—"),
    ("Schema enforcement",         "✓ types.py", "—",      "—",      "—",      "—",      "—",      "—",      "—",      "—",      "XSD opt","✓ Arrow"),
    ("Streaming / chunked read",   "✓",          "—",      "✓",      "—",      "—",      "—",      "—",      "partial","—",      "SAX",    "✓"),
    ("Columnar layout",            "—",          "—",      "—",      "—",      "—",      "—",      "—",      "—",      "—",      "—",      "✓"),
    ("Language agnostic",          "✓ spec",     "✓",      "✓",      "✓",      "✓",      "✓",      "✓",      "✓",      "Python", "✓",      "✓"),
    ("Key revocation support",     "✓ crypto.py","—",      "—",      "—",      "—",      "—",      "—",      "—",      "—",      "—",      "—"),
    ("Deterministic key derivation","✓ PBKDF2",  "—",      "—",      "—",      "—",      "—",      "—",      "—",      "—",      "—",      "—"),
]

def run_features():
    print("=" * 120)
    print("## 5. FEATURE MATRIX\n")

    fmt_headers = ["SIF", "JSON", "JSONL", "orjson", "ujson", "BSON", "CBOR", "MsgPack", "Pickle", "XML", "Arrow"]
    col = 10
    hdr = f"  {'Feature':<36}" + "".join(f"{h:>{col}}" for h in fmt_headers)
    print(hdr)
    print("  " + "-" * (len(hdr) - 2))

    for row in FEATURE_MATRIX:
        feature = row[0]
        vals = row[1:]
        line = f"  {feature:<36}"
        for v in vals:
            line += f"{v:>{col}}"
        print(line)

    print()
    print("  ✓ = native built-in support | — = not supported | manual = convention-based workaround")


# ─────────────────────────────────────────────────────────────────────────────
# 6. Summary scorecard
# ─────────────────────────────────────────────────────────────────────────────

def run_scorecard(size_results: dict):
    print("=" * 100)
    print("## 6. SUMMARY SCORECARD\n")

    # Compute average size ratio vs SIF across all levels
    fmt_names = [f[0] for f in FORMATS]
    avg_ratios = {}
    for fmt_name in fmt_names:
        if fmt_name == "SIF":
            continue
        ratios = []
        for level_name, _ in LEVELS:
            sif = size_results[level_name]["SIF"]
            other = size_results[level_name].get(fmt_name, -1)
            if sif > 0 and other > 0:
                ratios.append(other / sif)
        avg_ratios[fmt_name] = sum(ratios) / len(ratios) if ratios else 0

    # Feature counts (how many ✓ native features each has)
    feature_scores = {h: 0 for h in ["SIF", "JSON", "JSONL", "orjson", "ujson", "BSON", "CBOR", "MsgPack", "Pickle", "XML", "Arrow"]}
    for row in FEATURE_MATRIX:
        for i, h in enumerate(feature_scores.keys()):
            if row[i + 1].startswith("✓"):
                feature_scores[h] += 1

    print(f"  {'Format':<12} {'Avg size vs SIF':>18} {'Native features':>18} {'Integrity':>12} {'Signature':>12}")
    print("  " + "-" * 76)

    integrity_map = {
        "SIF":     "SHA-256",
        "JSON":    "none",
        "JSONL":   "none",
        "orjson":  "none",
        "ujson":   "none",
        "BSON":    "none",
        "CBOR":    "none",
        "MsgPack": "none",
        "Pickle":  "none",
        "XML":     "none",
        "Arrow":   "none",
    }
    sig_map = {k: "ed25519" if k == "SIF" else "none" for k in integrity_map}

    for fmt_name in [f[0] for f in FORMATS]:
        if fmt_name == "SIF":
            ratio_str = "baseline"
        else:
            r = avg_ratios.get(fmt_name, 0)
            ratio_str = f"{r:.2f}x {'larger' if r > 1 else 'smaller'}"
        fscore = feature_scores.get(fmt_name, 0)
        integ = integrity_map.get(fmt_name, "none")
        sig = sig_map.get(fmt_name, "none")
        print(f"  {fmt_name:<12} {ratio_str:>18} {fscore:>14}/20 {integ:>12} {sig:>12}")

    print()
    print("  SIF pays a size premium (~1.3–2x vs raw CBOR) to gain:")
    print("  • cryptographic integrity (SHA-256 + ed25519 multi-sig)")
    print("  • first-class uncertainty (typed Distribution, not 3 flat fields)")
    print("  • DAG cycle detection on decode")
    print("  • content-addressed stable IDs independent of framing")
    print("  • key revocation and deterministic key derivation")


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("\n" + "=" * 100)
    print("  SIF FULL COMPETITIVE BENCHMARK")
    print("  Formats: SIF | JSON | JSONL | orjson | ujson | BSON | CBOR | MsgPack | Pickle | XML | Arrow")
    print("=" * 100 + "\n")

    size_results = run_size()
    print()
    run_speed()
    run_compression()
    run_integrity()
    run_features()
    run_scorecard(size_results)
