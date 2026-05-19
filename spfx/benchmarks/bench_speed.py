"""
A2 — Speed benchmark: encode/decode throughput.

Measures encode + decode time in microseconds per document
across 4 complexity levels, comparing SIF vs JSON vs CBOR vs MessagePack vs Protobuf.

Protobuf column requires: pip install protobuf
"""

from __future__ import annotations
import json
import time as time_mod

import cbor2
import msgpack

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from spfx import SPIFWriter, SPIFReader
from benchmarks.bench_size import doc_minimal, doc_medium, doc_with_trace, doc_full, to_json_dict, to_cbor_raw, to_msgpack_raw

try:
    from proto_compat import to_proto_raw, HAVE_PROTOBUF, Proto_SPIFDocument
except Exception:
    HAVE_PROTOBUF = False
    def to_proto_raw(doc):
        return None
    Proto_SPIFDocument = None

REPS = 500


def bench(fn, reps: int) -> float:
    """Return mean time per call in microseconds."""
    start = time_mod.perf_counter()
    for _ in range(reps):
        fn()
    end = time_mod.perf_counter()
    return (end - start) / reps * 1_000_000  # μs


LEVELS = [
    ("minimal",  doc_minimal),
    ("medium",   doc_medium),
    ("trace",    doc_with_trace),
    ("full",     doc_full),
]


def run():
    writer = SPIFWriter()
    reader = SPIFReader()

    proto_col = HAVE_PROTOBUF

    if proto_col:
        hdr = f"{'Document':<12} {'Op':<8} {'SIF':>10} {'JSON':>10} {'CBOR':>10} {'MsgPack':>10} {'Proto':>10}"
    else:
        hdr = f"{'Document':<12} {'Op':<8} {'SIF':>10} {'JSON':>10} {'CBOR':>10} {'MsgPack':>10}"

    print("## Speed Benchmark (μs per document)\n")
    print(hdr)
    print("-" * len(hdr))

    for label, factory in LEVELS:
        doc = factory()
        sif_data  = writer.encode(doc)
        json_data = json.dumps(to_json_dict(doc)).encode()
        cbor_data = to_cbor_raw(doc)
        mp_data   = to_msgpack_raw(doc)
        pb_data   = to_proto_raw(doc)

        enc_sif  = bench(lambda: writer.encode(doc), REPS)
        enc_json = bench(lambda: json.dumps(to_json_dict(doc)).encode(), REPS)
        enc_cbor = bench(lambda: cbor2.dumps(to_json_dict(doc)), REPS)
        enc_mp   = bench(lambda: msgpack.packb(to_json_dict(doc), use_bin_type=True), REPS)

        dec_sif  = bench(lambda: reader.decode(sif_data), REPS)
        dec_json = bench(lambda: json.loads(json_data), REPS)
        dec_cbor = bench(lambda: cbor2.loads(cbor_data), REPS)
        dec_mp   = bench(lambda: msgpack.unpackb(mp_data, raw=False), REPS)

        if proto_col and pb_data and Proto_SPIFDocument:
            enc_pb = bench(lambda: to_proto_raw(doc), REPS)
            dec_pb = bench(lambda: Proto_SPIFDocument.FromString(pb_data), REPS)
            print(f"{label:<12} {'encode':<8} {enc_sif:>9.1f}μ {enc_json:>9.1f}μ {enc_cbor:>9.1f}μ {enc_mp:>9.1f}μ {enc_pb:>9.1f}μ")
            print(f"{'':12} {'decode':<8} {dec_sif:>9.1f}μ {dec_json:>9.1f}μ {dec_cbor:>9.1f}μ {dec_mp:>9.1f}μ {dec_pb:>9.1f}μ")
        else:
            print(f"{label:<12} {'encode':<8} {enc_sif:>9.1f}μ {enc_json:>9.1f}μ {enc_cbor:>9.1f}μ {enc_mp:>9.1f}μ")
            print(f"{'':12} {'decode':<8} {dec_sif:>9.1f}μ {dec_json:>9.1f}μ {dec_cbor:>9.1f}μ {dec_mp:>9.1f}μ")
        print()

    print("Notes:")
    print("  SIF decode includes checksum validation (SHA-256) — unavoidable correctness cost.")
    print("  JSON/CBOR/MsgPack/Proto decode only parses structure, no integrity check.")
    print("  Proto wins on raw speed; SPIF adds integrity + schema-free distribution (no .proto needed at decode site).")
    print("  SIF encode overhead vs CBOR = chunk framing + SHA-256 + CBOR custom tags.")
    if not proto_col:
        print("  Protobuf column omitted: pip install protobuf to include")


if __name__ == "__main__":
    run()
