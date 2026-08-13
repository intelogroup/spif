"""
Real-world SPIF benchmark — angles not covered by bench_speed.py.

Measures:
  1. Throughput (docs/second) at realistic payload sizes
  2. Memory footprint (peak KB via tracemalloc) per encode/decode
  3. Signature overhead: unsigned vs ed25519-signed encode/decode
  4. Compression tradeoffs: ratio vs encode/decode speed at 5 doc sizes
  5. Streaming first-token latency
  6. Streaming throughput (tokens/second)
  7. AI pipeline simulation: 100 heterogeneous docs with real-world distribution

Run:
    cd /path/to/sif
    python benchmarks/bench_realworld.py
"""

from __future__ import annotations

import hashlib
import os
import struct
import time
import tracemalloc
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "spif"))

from spif import SPIFDocument, Node, Distribution, TraceStep, Provenance, SemanticLayer, SPIFWriter, SPIFReader
from spif.crypto import generate_key
from spif.streaming import SPIFStreamWriter, SPIFStreamReader
from spif.types import Signature

REPS = 200


# ---------------------------------------------------------------------------
# Document factories
# ---------------------------------------------------------------------------

def _d(mean: float = 0.9) -> Distribution:
    return Distribution(mean=mean, var=0.01, shape="gaussian", semantics="epistemic")


def _prov() -> Provenance:
    return Provenance(
        source_model="claude-sonnet-4-6",
        model_version="claude-sonnet-4-6-20250514",
        temperature=0.7,
        input_hash="a" * 64,
        timestamp_ms=1712000000000,
    )


def doc_qa() -> SPIFDocument:
    """Typical QA response: one fact node, one text node, light trace."""
    return SPIFDocument(
        payload=[
            Node(id="q", type="fact", value="What is the capital of France?", confidence=_d(1.0)),
            Node(id="a", type="text", value="Paris is the capital of France.", confidence=_d(0.99)),
        ],
        trace=[
            TraceStep(id="s0", type="hypothesis", content="The question is about geography.", confidence=_d(0.99), deps=[]),
            TraceStep(id="s1", type="conclusion", content="Paris.", confidence=_d(0.99), deps=["s0"]),
        ],
        trace_method="post-hoc",
        provenance=_prov(),
    )


def doc_long_answer() -> SPIFDocument:
    """Long-form answer: 20 paragraphs, each as a separate node."""
    nodes = [
        Node(id=f"p{i}", type="text",
             value=f"Paragraph {i}: " + ("This is a detailed explanation. " * 15),
             confidence=_d(0.85))
        for i in range(20)
    ]
    return SPIFDocument(payload=nodes, provenance=_prov())


def doc_reasoning_trace() -> SPIFDocument:
    """Chain-of-thought: 15-step linear reasoning trace."""
    steps = [
        TraceStep(id=f"s{i}", type="inference",
                  content=f"Step {i}: Considering the implications of step {i-1}... " + "analysis " * 5,
                  confidence=_d(0.7 + i * 0.02),
                  deps=[f"s{i-1}"] if i > 0 else [])
        for i in range(15)
    ]
    return SPIFDocument(
        payload=[Node(id="conclusion", type="text",
                      value="Final answer based on the reasoning trace.",
                      confidence=_d(0.92))],
        trace=steps,
        trace_method="post-hoc",
        provenance=_prov(),
    )


def doc_with_embedding() -> SPIFDocument:
    """Document with 1536-dim embedding (ada-002 size)."""
    embedding = [float(i) / 1536 for i in range(1536)]
    return SPIFDocument(
        payload=[Node(id="n0", type="text", value="Embedded content.", confidence=_d())],
        provenance=_prov(),
        semantic=SemanticLayer(embedding=embedding, embedding_model="text-embedding-ada-002"),
    )


def doc_agent_pipeline() -> SPIFDocument:
    """Agent pipeline: 5 tool calls + 5 tool results + final response."""
    nodes = []
    for i in range(5):
        nodes.append(Node(
            id=f"call{i}", type="tool_call",
            value={"name": f"search_{i}", "arguments": {"query": f"query {i}"}, "call_id": f"c{i}"},
            confidence=_d(1.0),
        ))
        nodes.append(Node(
            id=f"res{i}", type="tool_result",
            value={"call_id": f"c{i}", "content": f"Result text for query {i}.", "is_error": False},
            confidence=_d(1.0),
        ))
    nodes.append(Node(
        id="response", type="text",
        value="Based on my research, here is the comprehensive answer...",
        confidence=_d(0.91),
    ))
    return SPIFDocument(payload=nodes, provenance=_prov())


# ---------------------------------------------------------------------------
# Benchmark harness
# ---------------------------------------------------------------------------

def bench_fn(fn, reps: int = REPS) -> tuple[float, float]:
    """Run fn() reps times. Returns (mean_us, std_us)."""
    times = []
    for _ in range(reps):
        t0 = time.perf_counter()
        fn()
        times.append(time.perf_counter() - t0)
    mean = sum(times) / len(times)
    std = (sum((t - mean) ** 2 for t in times) / len(times)) ** 0.5
    return mean * 1e6, std * 1e6  # → μs


def peak_kb(fn) -> float:
    tracemalloc.start()
    fn()
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    return peak / 1024


def throughput(doc_size_bytes: int, mean_us: float) -> float:
    """Docs per second."""
    return 1_000_000 / mean_us


def bandwidth_mb(doc_size_bytes: int, mean_us: float) -> float:
    """Effective throughput in MB/s."""
    return (doc_size_bytes / mean_us)  # bytes/μs = MB/s


# ---------------------------------------------------------------------------
# 1. Encode/decode throughput at realistic sizes
# ---------------------------------------------------------------------------

def bench_throughput():
    print("\n## 1. Encode/Decode Throughput (docs/sec, MB/s)")
    print(f"{'Doc type':<22} {'size':>6}  "
          f"{'enc μs':>7} {'dec μs':>7}  "
          f"{'enc docs/s':>12} {'dec docs/s':>12}  "
          f"{'enc MB/s':>9} {'dec MB/s':>9}")
    print("-" * 110)

    levels = [
        ("qa",          doc_qa),
        ("long_answer", doc_long_answer),
        ("trace",       doc_reasoning_trace),
        ("embedding",   doc_with_embedding),
        ("agent",       doc_agent_pipeline),
    ]

    writer = SPIFWriter()
    reader = SPIFReader()

    for name, factory in levels:
        doc = factory()
        data = writer.encode(doc)
        enc_us, _ = bench_fn(lambda d=doc: writer.encode(d))
        dec_us, _ = bench_fn(lambda b=data: reader.decode(b))
        sz = len(data)
        print(f"  {name:<20} {sz:>6}B  "
              f"{enc_us:>7.1f} {dec_us:>7.1f}  "
              f"{throughput(sz, enc_us):>12,.0f} {throughput(sz, dec_us):>12,.0f}  "
              f"{bandwidth_mb(sz, enc_us):>9.1f} {bandwidth_mb(sz, dec_us):>9.1f}")


# ---------------------------------------------------------------------------
# 2. Memory footprint
# ---------------------------------------------------------------------------

def bench_memory():
    print("\n## 2. Peak Memory Footprint (KB per encode/decode)")
    print(f"{'Doc type':<22} {'size':>6}  {'enc peak KB':>12} {'dec peak KB':>12}  {'enc KB/doc':>11} {'dec KB/doc':>11}")
    print("-" * 90)

    levels = [
        ("qa",          doc_qa),
        ("long_answer", doc_long_answer),
        ("trace",       doc_reasoning_trace),
        ("embedding",   doc_with_embedding),
        ("agent",       doc_agent_pipeline),
    ]
    writer = SPIFWriter()
    reader = SPIFReader()

    for name, factory in levels:
        doc = factory()
        data = writer.encode(doc)
        enc_peak = peak_kb(lambda d=doc: writer.encode(d))
        dec_peak = peak_kb(lambda b=data: reader.decode(b))
        sz = len(data)
        print(f"  {name:<20} {sz:>6}B  "
              f"{enc_peak:>12.0f} {dec_peak:>12.0f}  "
              f"{enc_peak / (sz / 1024):>11.1f} {dec_peak / (sz / 1024):>11.1f}")


# ---------------------------------------------------------------------------
# 3. Signature overhead
# ---------------------------------------------------------------------------

def bench_signature_overhead():
    print("\n## 3. Signature Overhead (ed25519)")
    print(f"{'Doc type':<22} {'unsigned enc':>13} {'signed enc':>11} {'overhead':>10}  "
          f"{'unsigned dec':>13} {'signed dec':>11} {'overhead':>10}")
    print("-" * 105)

    # Benchmarks must not use a deterministic signing identity.  The key is
    # generated for this process only and must never be trusted outside it.
    private_key = generate_key()
    writer = SPIFWriter()
    reader = SPIFReader()

    def sign_doc(doc):
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        import base64, dataclasses
        body = writer.encode(doc)[:-37]  # strip checksum
        raw_sig = private_key.sign(body)
        pub = base64.b64encode(
            private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        ).decode()
        return dataclasses.replace(doc, signature=Signature(
            algorithm="ed25519", signer=pub, signature=raw_sig
        ))

    for name, factory in [("qa", doc_qa), ("trace", doc_reasoning_trace)]:
        doc = factory()
        signed = sign_doc(doc)
        unsigned_data = writer.encode(doc)
        signed_data = writer.encode(signed)

        enc_u, _ = bench_fn(lambda d=doc: writer.encode(d))
        enc_s, _ = bench_fn(lambda d=signed: writer.encode(d))
        dec_u, _ = bench_fn(lambda b=unsigned_data: reader.decode(b))
        dec_s, _ = bench_fn(lambda b=signed_data: reader.decode(b))

        enc_overhead = f"+{enc_s - enc_u:.0f}μs ({(enc_s/enc_u - 1)*100:.0f}%)"
        dec_overhead = f"+{dec_s - dec_u:.0f}μs ({(dec_s/dec_u - 1)*100:.0f}%)"
        print(f"  {name:<20} {enc_u:>10.1f}μs {enc_s:>10.1f}μs {enc_overhead:>12}  "
              f"{dec_u:>10.1f}μs {dec_s:>10.1f}μs {dec_overhead:>12}")


# ---------------------------------------------------------------------------
# 4. Compression tradeoffs
# ---------------------------------------------------------------------------

def bench_compression():
    print("\n## 4. Compression Tradeoffs (zlib, default level)")
    print(f"{'Doc type':<22} {'raw bytes':>10} {'cmp bytes':>10} {'ratio':>7}  "
          f"{'enc uncompressed':>17} {'enc compressed':>16} {'dec uncompressed':>17} {'dec compressed':>16}")
    print("-" * 125)

    writer_raw = SPIFWriter(compress=False)
    writer_cmp = SPIFWriter(compress=True)
    reader = SPIFReader()

    levels = [
        ("qa",          doc_qa),
        ("long_answer", doc_long_answer),
        ("trace",       doc_reasoning_trace),
        ("embedding",   doc_with_embedding),
        ("agent",       doc_agent_pipeline),
    ]

    for name, factory in levels:
        doc = factory()
        raw_data = writer_raw.encode(doc)
        cmp_data = writer_cmp.encode(doc)
        ratio = len(cmp_data) / len(raw_data)

        enc_r, _ = bench_fn(lambda d=doc: writer_raw.encode(d))
        enc_c, _ = bench_fn(lambda d=doc: writer_cmp.encode(d))
        dec_r, _ = bench_fn(lambda b=raw_data: reader.decode(b))
        dec_c, _ = bench_fn(lambda b=cmp_data: reader.decode(b))

        print(f"  {name:<20} {len(raw_data):>10} {len(cmp_data):>10} {ratio:>7.2f}  "
              f"{enc_r:>14.1f}μs {enc_c:>14.1f}μs {dec_r:>14.1f}μs {dec_c:>14.1f}μs")


# ---------------------------------------------------------------------------
# 5. Streaming: first-token latency
# ---------------------------------------------------------------------------

def bench_streaming_latency():
    print("\n## 5. Streaming First-Token Latency")
    print(f"{'Scenario':<30} {'open() latency':>15} {'first partial_text':>18} {'commit() latency':>18}")
    print("-" * 85)

    doc = doc_qa()
    prov = _prov()

    # open() latency
    open_us, _ = bench_fn(lambda: SPIFStreamWriter().open(prov))
    # partial_text latency (after open)
    def _first_token():
        w = SPIFStreamWriter()
        w.open(prov)
        w.partial_text("hello")
    first_us, _ = bench_fn(_first_token)
    first_us -= open_us  # net cost of first partial_text

    # commit() latency
    def _commit():
        w = SPIFStreamWriter()
        w.open(prov)
        w.commit(doc)
    commit_us, _ = bench_fn(_commit)
    commit_us -= open_us  # net cost of commit

    print(f"  {'with provenance':<28} {open_us:>14.1f}μs {first_us:>17.1f}μs {commit_us:>17.1f}μs")

    # Without provenance
    open_np_us, _ = bench_fn(lambda: SPIFStreamWriter().open())
    print(f"  {'no provenance':<28} {open_np_us:>14.1f}μs")


# ---------------------------------------------------------------------------
# 6. Streaming throughput (tokens/second)
# ---------------------------------------------------------------------------

def bench_streaming_throughput():
    print("\n## 6. Streaming Throughput (tokens/second)")

    token_counts = [10, 100, 500, 2000]
    doc = doc_qa()
    prov = _prov()

    print(f"  {'tokens':>8}  {'total stream bytes':>18}  {'stream time μs':>16}  {'tokens/sec':>12}  {'MB/s':>8}")
    print("  " + "-" * 70)

    for n_tokens in token_counts:
        tokens = [f"word{i} " for i in range(n_tokens)]

        def _stream():
            w = SPIFStreamWriter()
            parts = [w.open(prov)]
            for tok in tokens:
                parts.append(w.partial_text(tok))
            parts.append(w.commit(doc))
            return b"".join(parts)

        reps = max(10, min(200, 10_000 // n_tokens))
        total_us, _ = bench_fn(_stream, reps=reps)
        stream_bytes = len(_stream())
        tok_per_sec = n_tokens / (total_us / 1e6)
        mb_per_sec = (stream_bytes / total_us)  # bytes/μs = MB/s

        print(f"  {n_tokens:>8}  {stream_bytes:>18}  {total_us:>16.1f}  {tok_per_sec:>12,.0f}  {mb_per_sec:>8.1f}")


# ---------------------------------------------------------------------------
# 7. AI pipeline simulation
# ---------------------------------------------------------------------------

FIXTURES_DIR = Path(__file__).resolve().parents[1] / "spif-py" / "spif" / "fixtures" / "cross_lang"


def _load_fixture_docs(reader: "SPIFReader") -> list:
    """Real previously-encoded .spif files, as a proxy for real-world payload mix.

    Falls back to the synthetic factories below if the fixtures dir is
    missing or a fixture fails to decode (e.g. sample_corrupted.spif).
    """
    if not FIXTURES_DIR.is_dir():
        return []
    docs = []
    for path in sorted(FIXTURES_DIR.glob("*.spif")):
        try:
            docs.append(reader.decode(path.read_bytes()))
        except Exception:
            continue
    return docs


def bench_pipeline_simulation():
    print("\n## 7. AI Pipeline Simulation (100 docs, realistic distribution)")

    reader = SPIFReader()
    fixture_docs = _load_fixture_docs(reader)

    if fixture_docs:
        print(f"     Source: {len(fixture_docs)} real fixtures from {FIXTURES_DIR.relative_to(FIXTURES_DIR.parents[3])}, repeated/shuffled to 100")
        import random
        rng = random.Random(42)
        docs = [rng.choice(fixture_docs) for _ in range(100)]
    else:
        print("     Mix: 40% QA, 25% long answer, 15% reasoning, 10% embedding, 10% agent")
        factories = (
            [doc_qa] * 40 +
            [doc_long_answer] * 25 +
            [doc_reasoning_trace] * 15 +
            [doc_with_embedding] * 10 +
            [doc_agent_pipeline] * 10
        )
        import random
        rng = random.Random(42)
        rng.shuffle(factories)
        docs = [f() for f in factories]

    writer = SPIFWriter()
    total_bytes = sum(len(writer.encode(d)) for d in docs)

    # Time the whole pipeline: encode all 100, then decode all 100
    t0 = time.perf_counter()
    encoded = [writer.encode(d) for d in docs]
    enc_time = time.perf_counter() - t0

    t0 = time.perf_counter()
    decoded = [reader.decode(b) for b in encoded]
    dec_time = time.perf_counter() - t0

    total_time = enc_time + dec_time
    print(f"  100 docs, {total_bytes:,} bytes total")
    print(f"  Encode:   {enc_time*1000:.1f}ms  ({100/enc_time:.0f} docs/sec,  {total_bytes/enc_time/1e6:.1f} MB/s)")
    print(f"  Decode:   {dec_time*1000:.1f}ms  ({100/dec_time:.0f} docs/sec,  {total_bytes/dec_time/1e6:.1f} MB/s)")
    print(f"  Combined: {total_time*1000:.1f}ms  ({100/total_time:.0f} round-trips/sec)")

    # With compression
    writer_c = SPIFWriter(compress=True)
    t0 = time.perf_counter()
    encoded_c = [writer_c.encode(d) for d in docs]
    enc_c = time.perf_counter() - t0
    t0 = time.perf_counter()
    [reader.decode(b) for b in encoded_c]
    dec_c = time.perf_counter() - t0
    total_c_bytes = sum(len(b) for b in encoded_c)
    ratio = total_c_bytes / total_bytes

    print(f"\n  With compression:")
    print(f"  {total_c_bytes:,} bytes  (ratio {ratio:.2f}, {(1-ratio)*100:.0f}% smaller)")
    print(f"  Encode:   {enc_c*1000:.1f}ms  Decode:   {dec_c*1000:.1f}ms")
    print(f"  Combined: {(enc_c+dec_c)*1000:.1f}ms  ({100/(enc_c+dec_c):.0f} round-trips/sec)")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print(f"SPIF Real-World Benchmark  ({REPS} reps per measurement)")
    print("=" * 80)

    bench_throughput()
    bench_memory()
    bench_signature_overhead()
    bench_compression()
    bench_streaming_latency()
    bench_streaming_throughput()
    bench_pipeline_simulation()

    print("\n" + "=" * 80)
    print("Done.")
