"""
Readability Benchmark — Scenarios A & B
========================================
A: Signal-to-noise ratio across formats (content bytes vs total bytes).
B: Field find-time — how fast can you locate model name and confidence?

No API key required. All data is synthetic.

Run:
    cd /path/to/sif
    python benchmarks/bench_readability.py
"""
from __future__ import annotations

import io
import json
import os
import re
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import cbor2
import msgpack
import yaml
from lxml import etree

from spif import SPIFDocument, SPIFWriter, SPIFReader, Node, TraceStep, Distribution, Provenance
from spif.renderer import SPIFRenderer

REPS = 500

# ─────────────────────────────────────────────────────────────────────────────
# Synthetic document (same as ai_native_bench)
# ─────────────────────────────────────────────────────────────────────────────

RESPONSE_TEXT = (
    "Remote work has fundamentally reshaped urban office demand. "
    "JLL (2024) reports average occupancy at 54% in major US cities, "
    "down from 87% pre-pandemic. This structural shift is likely permanent "
    "for knowledge-worker roles, though in-person collaboration remains "
    "critical for onboarding and creative work."
)
MODEL_NAME   = "claude-sonnet-4-6"
CONFIDENCE   = 0.85
TRACE_STEPS  = [
    "User is asking about remote work impact on commercial real estate.",
    "I should cite recent data — JLL 2024 occupancy figures are authoritative.",
    "Need to balance: some roles benefit from in-person, others don't.",
    "Conclude with a nuanced position, not a blanket claim.",
]
INPUT_HASH = "a" * 64


def make_spif_doc() -> SPIFDocument:
    return SPIFDocument(
        payload=[Node(id="response", type="text", value=RESPONSE_TEXT,
                      confidence=Distribution(mean=CONFIDENCE, var=0.05,
                                              shape="gaussian", semantics="output_stability"))],
        provenance=Provenance(source_model=MODEL_NAME, model_version=MODEL_NAME,
                              temperature=0.7, input_hash=INPUT_HASH,
                              timestamp_ms=1712000000000),
        trace=[TraceStep(id=f"t{i}", type="inference", content=step,
                         confidence=Distribution(mean=0.82 + i * 0.02, var=0.04,
                                                 shape="gaussian", semantics="epistemic"),
                         deps=[f"t{i-1}"] if i > 0 else [])
               for i, step in enumerate(TRACE_STEPS)],
        trace_method="live",
    )


def make_json_doc() -> bytes:
    return json.dumps({
        "response": RESPONSE_TEXT,
        "provenance": {"source_model": MODEL_NAME, "timestamp_ms": 1712000000000,
                       "temperature": 0.7, "input_hash": INPUT_HASH},
        "confidence": {"mean": CONFIDENCE, "var": 0.05, "shape": "gaussian"},
        "trace": [{"id": f"t{i}", "type": "inference", "content": s,
                   "confidence_mean": round(0.82 + i * 0.02, 4),
                   "deps": [f"t{i-1}"] if i > 0 else []}
                  for i, s in enumerate(TRACE_STEPS)],
        "trace_method": "live",
    }, separators=(",", ":")).encode()


def make_xml_doc() -> bytes:
    root = etree.Element("ai-output")
    prov = etree.SubElement(root, "provenance")
    etree.SubElement(prov, "source_model").text = MODEL_NAME
    etree.SubElement(prov, "timestamp_ms").text = "1712000000000"
    resp = etree.SubElement(root, "response")
    resp.text = RESPONSE_TEXT
    etree.SubElement(resp, "confidence_mean").text = str(CONFIDENCE)
    tr = etree.SubElement(root, "trace")
    for i, s in enumerate(TRACE_STEPS):
        step = etree.SubElement(tr, "step", id=f"t{i}")
        step.text = s
    return etree.tostring(root)


def make_yaml_doc() -> bytes:
    return yaml.dump({
        "response": RESPONSE_TEXT,
        "provenance": {"source_model": MODEL_NAME, "timestamp_ms": 1712000000000},
        "confidence": {"mean": CONFIDENCE, "var": 0.05},
        "trace": [{"id": f"t{i}", "content": s} for i, s in enumerate(TRACE_STEPS)],
    }, default_flow_style=False).encode()


def make_msgpack_doc() -> bytes:
    return msgpack.packb({
        "response": RESPONSE_TEXT,
        "provenance": {"source_model": MODEL_NAME, "timestamp_ms": 1712000000000},
        "confidence": {"mean": CONFIDENCE, "var": 0.05},
        "trace": [{"id": f"t{i}", "content": s} for i, s in enumerate(TRACE_STEPS)],
    }, use_bin_type=True)


def bench(fn, reps: int = REPS) -> float:
    t0 = time.perf_counter()
    for _ in range(reps):
        fn()
    return (time.perf_counter() - t0) / reps * 1_000_000


# ─────────────────────────────────────────────────────────────────────────────
# Scenario A — Signal-to-noise ratio
# ─────────────────────────────────────────────────────────────────────────────

def scenario_a():
    writer = SPIFWriter()
    doc    = make_spif_doc()

    spif_bytes    = writer.encode(doc)
    json_bytes    = make_json_doc()
    xml_bytes     = make_xml_doc()
    yaml_bytes    = make_yaml_doc()
    mp_bytes      = make_msgpack_doc()
    render_bytes  = SPIFRenderer().render(doc).encode()

    # "Signal": actual content that matters to an AI consumer
    # response text + model name + 3 confidence floats (8 bytes each) + 4 trace strings
    content_bytes = (
        len(RESPONSE_TEXT.encode())
        + len(MODEL_NAME.encode())
        + 3 * 8  # mean, var, temperature as f64
        + sum(len(s.encode()) for s in TRACE_STEPS)
    )

    print("\n## Scenario A — Signal-to-Noise Ratio\n")
    print(f"  Content (actual AI data): {content_bytes} bytes\n")
    print(f"  {'Format':<16} {'Total B':>8} {'Overhead B':>11} {'Signal %':>10}  Notes")
    print("  " + "─" * 72)

    rows = [
        ("SPIF (binary)",  spif_bytes,   "binary, typed, CBOR-encoded"),
        ("SPIF (render)",  render_bytes, "human-readable, visual bars, ASCII"),
        ("JSON",           json_bytes,   "text, untyped, full field names"),
        ("XML",            xml_bytes,    "text, verbose tag overhead"),
        ("YAML",           yaml_bytes,   "text, compact, human-friendly"),
        ("MsgPack",        mp_bytes,     "binary, dict-keyed, no typing"),
    ]

    for name, raw, note in rows:
        overhead = len(raw) - content_bytes
        signal_pct = content_bytes / len(raw) * 100
        print(f"  {name:<16} {len(raw):>8} {overhead:>11} {signal_pct:>9.1f}%  {note}")

    print(f"\n  SPIF render is {len(render_bytes) / len(spif_bytes):.1f}x larger than raw SPIF binary")
    print(f"  SPIF render is {len(render_bytes) / len(json_bytes):.1f}x larger than JSON")
    print(f"  SPIF render is {len(render_bytes) / len(yaml_bytes):.1f}x larger than YAML")


# ─────────────────────────────────────────────────────────────────────────────
# Scenario B — Field find-time
# ─────────────────────────────────────────────────────────────────────────────

def scenario_b():
    writer = SPIFWriter()
    reader = SPIFReader()
    doc = make_spif_doc()

    spif_bytes   = writer.encode(doc)
    json_bytes   = make_json_doc()
    xml_bytes    = make_xml_doc()
    yaml_bytes   = make_yaml_doc()
    mp_bytes     = make_msgpack_doc()
    render_bytes = SPIFRenderer().render(doc).encode()

    target_model = b"claude-sonnet"

    # Find the byte offset where the model name first appears
    def find_offset(data: bytes, target: bytes) -> int:
        idx = data.find(target)
        return idx if idx >= 0 else len(data)

    print("\n## Scenario B — Field Find-Time\n")
    print("  Target fields: model name ('claude-sonnet') + confidence value (0.85)\n")
    print(f"  {'Format':<16} {'Find μs':>9} {'Model @ byte':>14} {'Scan %':>8}  Method")
    print("  " + "─" * 74)

    # SPIF binary: model name is in CBOR string — scannable but not grepped easily
    spif_offset = find_offset(spif_bytes, target_model)
    t_spif = bench(lambda: reader.decode(spif_bytes).provenance.source_model)
    print(f"  {'SPIF (typed)':<16} {t_spif:>8.1f}μ {spif_offset:>14} "
          f"{spif_offset/len(spif_bytes)*100:>7.1f}%  SPIFReader → .provenance.source_model")

    # SPIF render: grep on ASCII output
    t_render = bench(lambda: re.search(rb"claude-sonnet", render_bytes))
    render_offset = find_offset(render_bytes, target_model)
    print(f"  {'SPIF (render)':<16} {t_render:>8.1f}μ {render_offset:>14} "
          f"{render_offset/len(render_bytes)*100:>7.1f}%  grep on rendered ASCII")

    # JSON: grep
    t_json = bench(lambda: re.search(rb"claude-sonnet", json_bytes))
    json_offset = find_offset(json_bytes, target_model)
    print(f"  {'JSON':<16} {t_json:>8.1f}μ {json_offset:>14} "
          f"{json_offset/len(json_bytes)*100:>7.1f}%  grep on raw bytes")

    # XML: grep
    t_xml = bench(lambda: re.search(rb"claude-sonnet", xml_bytes))
    xml_offset = find_offset(xml_bytes, target_model)
    print(f"  {'XML':<16} {t_xml:>8.1f}μ {xml_offset:>14} "
          f"{xml_offset/len(xml_bytes)*100:>7.1f}%  grep on raw bytes")

    # YAML: grep
    t_yaml = bench(lambda: re.search(rb"claude-sonnet", yaml_bytes))
    yaml_offset = find_offset(yaml_bytes, target_model)
    print(f"  {'YAML':<16} {t_yaml:>8.1f}μ {yaml_offset:>14} "
          f"{yaml_offset/len(yaml_bytes)*100:>7.1f}%  grep on raw bytes")

    # MsgPack: binary grep (model name is a msgpack string, embedded as-is)
    t_mp = bench(lambda: re.search(rb"claude-sonnet", mp_bytes))
    mp_offset = find_offset(mp_bytes, target_model)
    print(f"  {'MsgPack':<16} {t_mp:>8.1f}μ {mp_offset:>14} "
          f"{mp_offset/len(mp_bytes)*100:>7.1f}%  grep on raw bytes (works — msgpack embeds strings)")

    print()
    print("  Confidence (0.85) find-time:")
    print(f"  {'Format':<16} {'Find μs':>9}  Method")
    print("  " + "─" * 45)

    # SPIF typed: direct field
    t = bench(lambda: reader.decode(spif_bytes).payload[0].confidence.mean)
    print(f"  {'SPIF (typed)':<16} {t:>8.1f}μ  .payload[0].confidence.mean")

    # JSON parsed: key navigation
    t = bench(lambda: json.loads(json_bytes)["confidence"]["mean"])
    print(f"  {'JSON':<16} {t:>8.1f}μ  json.loads → ['confidence']['mean']")

    # XML XPath
    t = bench(lambda: float(etree.fromstring(xml_bytes).find("response/confidence_mean").text))
    print(f"  {'XML':<16} {t:>8.1f}μ  XPath → float()")

    # YAML
    t = bench(lambda: yaml.safe_load(yaml_bytes)["confidence"]["mean"])
    print(f"  {'YAML':<16} {t:>8.1f}μ  yaml.safe_load → ['confidence']['mean']")

    # MsgPack
    t = bench(lambda: msgpack.unpackb(mp_bytes, raw=False)["confidence"]["mean"])
    print(f"  {'MsgPack':<16} {t:>8.1f}μ  msgpack.unpackb → ['confidence']['mean']")

    # SPIF render grep for confidence
    t = bench(lambda: re.search(rb"confidence.*?(\d+)%", render_bytes))
    print(f"  {'SPIF (render)':<16} {t:>8.1f}μ  grep '\\d+%' on rendered text")

    # CLI spif inspect
    with tempfile.NamedTemporaryFile(suffix=".spif", delete=False) as f:
        f.write(spif_bytes)
        tmp = f.name
    try:
        t0 = time.perf_counter()
        result = subprocess.run(
            [sys.executable, "-m", "spif", "inspect", tmp, "--layer", "provenance"],
            capture_output=True, text=True
        )
        cli_ms = (time.perf_counter() - t0) * 1000
        print(f"\n  CLI 'spif inspect --layer provenance': {cli_ms:.1f}ms  (one-shot, includes Python startup)")
        if result.returncode == 0:
            print(f"  CLI output ({len(result.stdout)} chars):\n")
            for line in result.stdout.splitlines()[:8]:
                print(f"    {line}")
    finally:
        os.unlink(tmp)


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 80)
    print("SPIF Readability Benchmark — Scenarios A & B")
    print("=" * 80)
    scenario_a()
    scenario_b()
    print("\n" + "=" * 80)
    print("Key: 'signal' = response text + model name + confidence floats + trace strings")
    print("     'overhead' = format tags, field names, structural bytes, checksums")
    print("     Find-time measured at 500 reps.")
    print("=" * 80)
