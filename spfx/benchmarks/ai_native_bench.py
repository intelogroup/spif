"""
AI-Native Format Benchmark
===========================
Benchmarks formats across scenarios that matter for AI jobs specifically —
not generic serialization throughput, but the real operational cost of using
each format in production AI pipelines.

Scenarios
─────────
1. AGENT OUTPUT ENCODING
   Encode a realistic LLM response with provenance, confidence, reasoning trace.
   For formats without native support, we bolt on the metadata manually.

2. AGENT-TO-AGENT HANDOFF CHAIN
   Agent A produces output → Agent B reads it and produces a new output linked
   to A's → Agent C does the same. Measures: total bytes for the 3-doc chain,
   encode/decode time per hop, whether provenance chain survives.

3. STREAMING TOKEN ASSEMBLY
   50 tokens arrive one-by-one. Assemble into a final document.
   Measures: overhead per token, total size, whether integrity is checkable
   after assembly.

4. PROVENANCE EXTRACTION
   Given an encoded document, extract: model name, timestamp_ms, confidence_mean.
   Measures: decode time, whether metadata survives or was lost.

5. CONTEXT WINDOW COST
   If you pass a prior AI output back into a model as context, how many tokens
   does the encoding consume? (Estimate: GPT-4 tokenizer ≈ 1 token per 4 chars
   for text, 1 token per 3 chars for JSON/XML.)

6. FEATURE MATRIX
   Qualitative table: what each format natively supports vs needs bolting on.

Run:
    cd /path/to/sif
    python benchmarks/ai_native_bench.py

No API key required — all data is synthetic but representative.
"""

from __future__ import annotations

import gzip
import hashlib
import json
import sys
import time
import zlib
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import cbor2
import msgpack
import yaml
from lxml import etree

from spfx import SPIFDocument, SPIFWriter, SPIFReader, Node, TraceStep, Distribution, Provenance
from spfx.streaming import SPIFStreamWriter, SPIFStreamReader

REPS = 500

# ─────────────────────────────────────────────────────────────────────────────
# Synthetic data representing a real LLM response
# ─────────────────────────────────────────────────────────────────────────────

RESPONSE_TEXT = (
    "Remote work has fundamentally reshaped urban office demand. "
    "JLL (2024) reports average occupancy at 54% in major US cities, "
    "down from 87% pre-pandemic. This structural shift is likely permanent "
    "for knowledge-worker roles, though in-person collaboration remains "
    "critical for onboarding and creative work."
)

THINKING_STEPS = [
    "User is asking about remote work impact on commercial real estate.",
    "I should cite recent data — JLL 2024 occupancy figures are authoritative.",
    "Need to balance: some roles benefit from in-person, others don't.",
    "Conclude with a nuanced position, not a blanket claim.",
]

TOKENS = RESPONSE_TEXT.split()  # ~50 tokens (words as proxy)

INPUT_HASH = hashlib.sha256(b"What is the impact of remote work on office demand?").hexdigest()


def make_spif_doc(context_ref: str = "") -> SPIFDocument:
    trace = [
        TraceStep(
            id=f"t{i}",
            type="inference",
            content=step,
            confidence=Distribution(mean=0.82 + i * 0.02, var=0.04, shape="gaussian",
                                    semantics="epistemic"),
            deps=[f"t{i-1}"] if i > 0 else [],
        )
        for i, step in enumerate(THINKING_STEPS)
    ]
    return SPIFDocument(
        payload=[Node(
            id="response",
            type="text",
            value=RESPONSE_TEXT,
            confidence=Distribution(mean=0.85, var=0.05, shape="gaussian",
                                    semantics="output_stability"),
        )],
        provenance=Provenance(
            source_model="claude-sonnet-4-6",
            model_version="claude-sonnet-4-6",
            temperature=0.7,
            input_hash=INPUT_HASH,
            timestamp_ms=1712000000000,
            context_ref=context_ref,
        ),
        trace=trace,
        trace_method="live",
    )


# ─────────────────────────────────────────────────────────────────────────────
# JSON equivalent — manually adding all the metadata SPIF has natively
# ─────────────────────────────────────────────────────────────────────────────

def make_json_doc(context_ref: str = "") -> dict:
    """
    JSON with manually-bolted-on provenance, confidence, trace, and checksum.
    This is what you'd write to match SPIF's feature set in JSON.
    """
    body = {
        "format": "ai-output-v1",
        "response": RESPONSE_TEXT,
        "provenance": {
            "source_model": "claude-sonnet-4-6",
            "model_version": "claude-sonnet-4-6",
            "temperature": 0.7,
            "input_hash": INPUT_HASH,
            "timestamp_ms": 1712000000000,
            "context_ref": context_ref,
        },
        "confidence": {
            "mean": 0.85,
            "var": 0.05,
            "shape": "gaussian",
            "semantics": "output_stability",
        },
        "trace": [
            {
                "id": f"t{i}",
                "type": "inference",
                "content": step,
                "confidence": {"mean": 0.82 + i * 0.02, "var": 0.04},
                "deps": [f"t{i-1}"] if i > 0 else [],
            }
            for i, step in enumerate(THINKING_STEPS)
        ],
        "trace_method": "live",
    }
    # Manually compute + attach checksum (what SPIF does automatically)
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    body["__checksum__"] = "sha256:" + hashlib.sha256(canonical).hexdigest()
    return body


def make_jsonl_doc(context_ref: str = "") -> str:
    """
    JSONL: one line per logical record (provenance, response, each trace step).
    Closest thing JSONL has to a 'document'.
    """
    lines = [
        json.dumps({"type": "provenance", "source_model": "claude-sonnet-4-6",
                    "timestamp_ms": 1712000000000, "input_hash": INPUT_HASH,
                    "context_ref": context_ref}),
        json.dumps({"type": "response", "value": RESPONSE_TEXT,
                    "confidence_mean": 0.85, "confidence_var": 0.05}),
    ]
    for i, step in enumerate(THINKING_STEPS):
        lines.append(json.dumps({"type": "trace", "id": f"t{i}", "content": step,
                                  "confidence_mean": 0.82 + i * 0.02,
                                  "deps": [f"t{i-1}"] if i > 0 else []}))
    return "\n".join(lines)


def make_xml_doc(context_ref: str = "") -> bytes:
    root = etree.Element("ai-output", version="1", format="ai-output-v1")
    prov = etree.SubElement(root, "provenance")
    etree.SubElement(prov, "source_model").text = "claude-sonnet-4-6"
    etree.SubElement(prov, "timestamp_ms").text = "1712000000000"
    etree.SubElement(prov, "input_hash").text = INPUT_HASH
    etree.SubElement(prov, "context_ref").text = context_ref
    resp = etree.SubElement(root, "response")
    etree.SubElement(resp, "value").text = RESPONSE_TEXT
    conf = etree.SubElement(resp, "confidence")
    etree.SubElement(conf, "mean").text = "0.85"
    etree.SubElement(conf, "var").text = "0.05"
    etree.SubElement(conf, "shape").text = "gaussian"
    tr = etree.SubElement(root, "trace", method="live")
    for i, step in enumerate(THINKING_STEPS):
        s = etree.SubElement(tr, "step", id=f"t{i}", type="inference")
        etree.SubElement(s, "content").text = step
        etree.SubElement(s, "confidence_mean").text = str(0.82 + i * 0.02)
        if i > 0:
            etree.SubElement(s, "dep").text = f"t{i-1}"
    return etree.tostring(root, xml_declaration=True, encoding="UTF-8")


def make_yaml_doc(context_ref: str = "") -> str:
    return yaml.dump({
        "format": "ai-output-v1",
        "provenance": {
            "source_model": "claude-sonnet-4-6",
            "timestamp_ms": 1712000000000,
            "input_hash": INPUT_HASH,
            "context_ref": context_ref,
        },
        "response": RESPONSE_TEXT,
        "confidence": {"mean": 0.85, "var": 0.05, "shape": "gaussian"},
        "trace": [
            {"id": f"t{i}", "type": "inference", "content": step,
             "confidence_mean": round(0.82 + i * 0.02, 4),
             "deps": [f"t{i-1}"] if i > 0 else []}
            for i, step in enumerate(THINKING_STEPS)
        ],
        "trace_method": "live",
    }, default_flow_style=False)


def make_msgpack_doc(context_ref: str = "") -> bytes:
    return msgpack.packb(make_json_doc(context_ref), use_bin_type=True)


def make_cbor_doc(context_ref: str = "") -> bytes:
    return cbor2.dumps(make_json_doc(context_ref))


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def bench(fn, reps: int = REPS) -> float:
    """Mean time per call in microseconds."""
    t0 = time.perf_counter()
    for _ in range(reps):
        fn()
    return (time.perf_counter() - t0) / reps * 1_000_000


def gzip_size(data: bytes) -> int:
    return len(gzip.compress(data, compresslevel=9))


def approx_tokens(data: bytes | str) -> int:
    """
    Rough GPT-4 tokenizer estimate.
    Binary formats (SPIF, MsgPack, CBOR) are base64-encoded before passing
    to a model — that inflates size by ~33%.
    Text formats are passed as-is.
    """
    if isinstance(data, bytes):
        # Binary must be base64 to go into a prompt
        import base64
        as_text = base64.b64encode(data).decode()
        return len(as_text) // 4
    return len(data) // 4


# ─────────────────────────────────────────────────────────────────────────────
# Scenario 1: Single AI output encoding
# ─────────────────────────────────────────────────────────────────────────────

def scenario_single_output():
    writer = SPIFWriter()
    reader = SPIFReader()
    doc = make_spif_doc()

    spif_bytes    = writer.encode(doc)
    json_bytes    = json.dumps(make_json_doc()).encode()
    jsonl_bytes   = make_jsonl_doc().encode()
    xml_bytes     = make_xml_doc()
    yaml_bytes    = make_yaml_doc().encode()
    mp_bytes      = make_msgpack_doc()
    cbor_bytes    = make_cbor_doc()

    rows = [
        ("SPIF",    spif_bytes,  lambda: writer.encode(doc),                          lambda: reader.decode(spif_bytes)),
        ("JSON",    json_bytes,  lambda: json.dumps(make_json_doc()).encode(),         lambda: json.loads(json_bytes)),
        ("JSONL",   jsonl_bytes, lambda: make_jsonl_doc().encode(),                   lambda: [json.loads(l) for l in jsonl_bytes.decode().split("\n")]),
        ("XML",     xml_bytes,   lambda: make_xml_doc(),                              lambda: etree.fromstring(xml_bytes)),
        ("YAML",    yaml_bytes,  lambda: make_yaml_doc().encode(),                    lambda: yaml.safe_load(yaml_bytes)),
        ("MsgPack", mp_bytes,    lambda: make_msgpack_doc(),                          lambda: msgpack.unpackb(mp_bytes, raw=False)),
        ("CBOR",    cbor_bytes,  lambda: make_cbor_doc(),                             lambda: cbor2.loads(cbor_bytes)),
    ]

    print("\n## Scenario 1 — Single AI Output (response + provenance + 4-step trace)\n")
    print(f"{'Format':<10} {'Raw B':>7} {'Gzip B':>7} {'Enc μs':>8} {'Dec μs':>8} {'~Tokens':>8}  Native metadata?")
    print("─" * 82)

    for name, raw, enc_fn, dec_fn in rows:
        enc_us  = bench(enc_fn)
        dec_us  = bench(dec_fn)
        tokens  = approx_tokens(raw)
        gz      = gzip_size(raw)
        native  = "provenance + confidence + trace + checksum" if name == "SPIF" else "response text only"
        print(f"{name:<10} {len(raw):>7} {gz:>7} {enc_us:>7.1f}μ {dec_us:>7.1f}μ {tokens:>8}  {native}")


# ─────────────────────────────────────────────────────────────────────────────
# Scenario 2: Agent-to-agent handoff chain (A → B → C)
# ─────────────────────────────────────────────────────────────────────────────

def scenario_agent_chain():
    writer = SPIFWriter()
    reader = SPIFReader()

    print("\n## Scenario 2 — Agent Handoff Chain (A→B→C, 3 hops)\n")
    print(f"{'Format':<10} {'Total B':>8} {'Enc/hop μs':>11} {'Dec/hop μs':>11}  Chain provenance?")
    print("─" * 72)

    # SPIF: context_ref links documents
    def spif_chain():
        doc_a = make_spif_doc()
        raw_a = writer.encode(doc_a)
        ref_a = reader.decode(raw_a).content_id()

        doc_b = make_spif_doc(context_ref=ref_a)
        raw_b = writer.encode(doc_b)
        ref_b = reader.decode(raw_b).content_id()

        doc_c = make_spif_doc(context_ref=ref_b)
        raw_c = writer.encode(doc_c)
        return raw_a, raw_b, raw_c

    ra, rb, rc = spif_chain()
    spif_total = len(ra) + len(rb) + len(rc)
    spif_enc = bench(lambda: spif_chain()) / 3
    spif_dec = bench(lambda: [reader.decode(r) for r in [ra, rb, rc]]) / 3
    print(f"{'SPIF':<10} {spif_total:>8} {spif_enc:>10.1f}μ {spif_dec:>10.1f}μ  YES — context_ref SHA-256 chain")

    # JSON: manually hash previous doc and embed
    def json_chain():
        doc_a = make_json_doc()
        raw_a = json.dumps(doc_a).encode()
        ref_a = "sha256:" + hashlib.sha256(raw_a).hexdigest()

        doc_b = make_json_doc(context_ref=ref_a)
        raw_b = json.dumps(doc_b).encode()
        ref_b = "sha256:" + hashlib.sha256(raw_b).hexdigest()

        doc_c = make_json_doc(context_ref=ref_b)
        raw_c = json.dumps(doc_c).encode()
        return raw_a, raw_b, raw_c

    ra, rb, rc = json_chain()
    json_total = len(ra) + len(rb) + len(rc)
    json_enc = bench(lambda: json_chain()) / 3
    json_dec = bench(lambda: [json.loads(r) for r in [ra, rb, rc]]) / 3
    print(f"{'JSON':<10} {json_total:>8} {json_enc:>10.1f}μ {json_dec:>10.1f}μ  manual — SHA-256 must be computed by caller")

    # JSONL: no native chain support, just repeat the provenance line
    def jsonl_chain():
        ra = make_jsonl_doc().encode()
        rb = make_jsonl_doc("ref-a").encode()
        rc = make_jsonl_doc("ref-b").encode()
        return ra, rb, rc

    ra, rb, rc = jsonl_chain()
    jsonl_total = len(ra) + len(rb) + len(rc)
    jsonl_enc = bench(lambda: jsonl_chain()) / 3
    jsonl_dec = bench(lambda: [[json.loads(l) for l in r.decode().split("\n")] for r in [ra, rb, rc]]) / 3
    print(f"{'JSONL':<10} {jsonl_total:>8} {jsonl_enc:>10.1f}μ {jsonl_dec:>10.1f}μ  manual — no native chain mechanism")

    # XML: embed prev hash as attribute
    def xml_chain():
        ra = make_xml_doc()
        ref_a = "sha256:" + hashlib.sha256(ra).hexdigest()
        rb = make_xml_doc(context_ref=ref_a)
        ref_b = "sha256:" + hashlib.sha256(rb).hexdigest()
        rc = make_xml_doc(context_ref=ref_b)
        return ra, rb, rc

    ra, rb, rc = xml_chain()
    xml_total = len(ra) + len(rb) + len(rc)
    xml_enc = bench(lambda: xml_chain()) / 3
    xml_dec = bench(lambda: [etree.fromstring(r) for r in [ra, rb, rc]]) / 3
    print(f"{'XML':<10} {xml_total:>8} {xml_enc:>10.1f}μ {xml_dec:>10.1f}μ  manual — no native chain mechanism")

    def yaml_chain():
        ra = make_yaml_doc().encode()
        rb = make_yaml_doc("ref-a").encode()
        rc = make_yaml_doc("ref-b").encode()
        return ra, rb, rc

    ra, rb, rc = yaml_chain()
    yaml_total = len(ra) + len(rb) + len(rc)
    yaml_enc = bench(lambda: yaml_chain()) / 3
    yaml_dec = bench(lambda: [yaml.safe_load(r) for r in [ra, rb, rc]]) / 3
    print(f"{'YAML':<10} {yaml_total:>8} {yaml_enc:>10.1f}μ {yaml_dec:>10.1f}μ  manual — no native chain mechanism")

    def mp_chain():
        ra = make_msgpack_doc()
        ref_a = "sha256:" + hashlib.sha256(ra).hexdigest()
        rb = make_msgpack_doc(context_ref=ref_a)
        ref_b = "sha256:" + hashlib.sha256(rb).hexdigest()
        rc = make_msgpack_doc(context_ref=ref_b)
        return ra, rb, rc

    ra, rb, rc = mp_chain()
    mp_total = len(ra) + len(rb) + len(rc)
    mp_enc = bench(lambda: mp_chain()) / 3
    mp_dec = bench(lambda: [msgpack.unpackb(r, raw=False) for r in [ra, rb, rc]]) / 3
    print(f"{'MsgPack':<10} {mp_total:>8} {mp_enc:>10.1f}μ {mp_dec:>10.1f}μ  manual — must bolt on SHA-256 chain")


# ─────────────────────────────────────────────────────────────────────────────
# Scenario 3: Streaming token assembly
# ─────────────────────────────────────────────────────────────────────────────

def scenario_streaming():
    print("\n## Scenario 3 — Streaming Token Assembly ({} tokens)\n".format(len(TOKENS)))
    print(f"{'Format':<10} {'Total B':>8} {'μs/token':>10} {'Integrity?'}")
    print("─" * 55)

    doc = make_spif_doc()
    writer_obj = SPIFWriter()

    # SPIF streaming: SPIFStreamWriter
    def spif_stream():
        sw = SPIFStreamWriter()
        chunks = []
        prov = doc.provenance
        chunks.append(sw.open(prov))
        for tok in TOKENS:
            chunks.append(sw.partial_text(tok + " ", node_id="response"))
        chunks.append(sw.commit(doc))
        return b"".join(chunks)

    spif_stream_bytes = spif_stream()
    spif_tok_us = bench(spif_stream) / len(TOKENS)
    # Verify: SPIFStreamReader can decode it end-to-end
    stream_reader = SPIFStreamReader()
    final_doc = None
    for event in stream_reader.feed(spif_stream_bytes):
        if event.type == "verified":
            final_doc = event.document
    spif_verified = final_doc is not None
    print(f"{'SPIF':<10} {len(spif_stream_bytes):>8} {spif_tok_us:>9.2f}μ  {'YES — checksum auto-verified' if spif_verified else 'FAIL'}")

    # JSONL streaming: one JSON line per token
    def jsonl_stream():
        lines = []
        for i, tok in enumerate(TOKENS):
            lines.append(json.dumps({"seq": i, "token": tok + " "}))
        lines.append(json.dumps({"done": True, "full_text": RESPONSE_TEXT,
                                  "model": "claude-sonnet-4-6",
                                  "checksum": "sha256:" + hashlib.sha256(RESPONSE_TEXT.encode()).hexdigest()}))
        return "\n".join(lines).encode()

    jsonl_stream_bytes = jsonl_stream()
    jsonl_tok_us = bench(jsonl_stream) / len(TOKENS)
    print(f"{'JSONL':<10} {len(jsonl_stream_bytes):>8} {jsonl_tok_us:>9.2f}μ  manual — caller must verify final checksum line")

    # JSON streaming: simulate OpenAI SSE-style (data: {...}\n\n)
    def json_sse_stream():
        lines = []
        for tok in TOKENS:
            lines.append("data: " + json.dumps({"choices": [{"delta": {"content": tok + " "}}]}))
        lines.append("data: [DONE]")
        return "\n\n".join(lines).encode()

    json_sse_bytes = json_sse_stream()
    json_sse_tok_us = bench(json_sse_stream) / len(TOKENS)
    print(f"{'JSON-SSE':<10} {len(json_sse_bytes):>8} {json_sse_tok_us:>9.2f}μ  NO — no integrity mechanism in SSE")

    # MsgPack streaming: one msgpack frame per token
    def mp_stream():
        frames = []
        for i, tok in enumerate(TOKENS):
            frames.append(msgpack.packb({"seq": i, "token": tok + " "}, use_bin_type=True))
        frames.append(msgpack.packb({"done": True, "full_text": RESPONSE_TEXT}, use_bin_type=True))
        return b"".join(frames)

    mp_stream_bytes = mp_stream()
    mp_tok_us = bench(mp_stream) / len(TOKENS)
    print(f"{'MsgPack':<10} {len(mp_stream_bytes):>8} {mp_tok_us:>9.2f}μ  manual — no framing standard")


# ─────────────────────────────────────────────────────────────────────────────
# Scenario 4: Provenance extraction
# ─────────────────────────────────────────────────────────────────────────────

def scenario_provenance_extraction():
    writer = SPIFWriter()
    reader = SPIFReader()
    doc = make_spif_doc()

    spif_bytes  = writer.encode(doc)
    json_bytes  = json.dumps(make_json_doc()).encode()
    xml_bytes   = make_xml_doc()
    yaml_bytes  = make_yaml_doc().encode()
    mp_bytes    = make_msgpack_doc()

    print("\n## Scenario 4 — Provenance Extraction (model, timestamp, confidence)\n")
    print(f"{'Format':<10} {'Dec μs':>8}  Extracted cleanly?")
    print("─" * 55)

    # SPIF
    def spif_extract():
        d = reader.decode(spif_bytes)
        return d.provenance.source_model, d.provenance.timestamp_ms, d.payload[0].confidence.mean
    t = bench(spif_extract)
    m, ts, c = spif_extract()
    print(f"{'SPIF':<10} {t:>7.1f}μ  YES — typed fields: model={m!r}, ts={ts}, conf={c}")

    # JSON
    def json_extract():
        d = json.loads(json_bytes)
        return d["provenance"]["source_model"], d["provenance"]["timestamp_ms"], d["confidence"]["mean"]
    t = bench(json_extract)
    m, ts, c = json_extract()
    print(f"{'JSON':<10} {t:>7.1f}μ  manual — dict navigation required, no schema enforcement")

    # XML
    def xml_extract():
        root = etree.fromstring(xml_bytes)
        m = root.find("provenance/source_model").text
        ts = int(root.find("provenance/timestamp_ms").text)
        c = float(root.find("response/confidence/mean").text)
        return m, ts, c
    t = bench(xml_extract)
    m, ts, c = xml_extract()
    print(f"{'XML':<10} {t:>7.1f}μ  manual — XPath navigation, all values as strings")

    # YAML
    def yaml_extract():
        d = yaml.safe_load(yaml_bytes)
        return d["provenance"]["source_model"], d["provenance"]["timestamp_ms"], d["confidence"]["mean"]
    t = bench(yaml_extract)
    m, ts, c = yaml_extract()
    print(f"{'YAML':<10} {t:>7.1f}μ  manual — dict navigation, schema lost")

    # MsgPack
    def mp_extract():
        d = msgpack.unpackb(mp_bytes, raw=False)
        return d["provenance"]["source_model"], d["provenance"]["timestamp_ms"], d["confidence"]["mean"]
    t = bench(mp_extract)
    m, ts, c = mp_extract()
    print(f"{'MsgPack':<10} {t:>7.1f}μ  manual — dict navigation, no schema")


# ─────────────────────────────────────────────────────────────────────────────
# Scenario 5: Context window cost
# ─────────────────────────────────────────────────────────────────────────────

def scenario_context_window():
    writer = SPIFWriter()
    doc = make_spif_doc()

    spif_bytes  = writer.encode(doc)
    json_bytes  = json.dumps(make_json_doc()).encode()
    jsonl_bytes = make_jsonl_doc().encode()
    xml_bytes   = make_xml_doc()
    yaml_bytes  = make_yaml_doc().encode()
    mp_bytes    = make_msgpack_doc()
    cbor_bytes  = make_cbor_doc()

    print("\n## Scenario 5 — Context Window Cost (tokens consumed if passed to a model)\n")
    print("  Note: binary formats (SPIF, MsgPack, CBOR) must be base64-encoded to appear")
    print("  in a text prompt, adding ~33% overhead. Text formats pass as-is.\n")
    print(f"{'Format':<10} {'Raw B':>7} {'As-prompt B':>12} {'~Tokens':>8}  Passable as context?")
    print("─" * 72)

    formats = [
        ("SPIF",    spif_bytes,  True,  "base64 required — binary"),
        ("JSON",    json_bytes,  False, "directly pasteable"),
        ("JSONL",   jsonl_bytes, False, "directly pasteable"),
        ("XML",     xml_bytes,   False, "directly pasteable"),
        ("YAML",    yaml_bytes,  False, "directly pasteable, most readable"),
        ("MsgPack", mp_bytes,    True,  "base64 required — binary"),
        ("CBOR",    cbor_bytes,  True,  "base64 required — binary"),
    ]

    import base64
    for name, raw, is_binary, note in formats:
        if is_binary:
            prompt_bytes = base64.b64encode(raw)
        else:
            prompt_bytes = raw
        tokens = len(prompt_bytes) // 4
        print(f"{name:<10} {len(raw):>7} {len(prompt_bytes):>12} {tokens:>8}  {note}")


# ─────────────────────────────────────────────────────────────────────────────
# Scenario 6: Feature matrix
# ─────────────────────────────────────────────────────────────────────────────

def scenario_feature_matrix():
    print("\n## Scenario 6 — Feature Matrix (AI-Native Capabilities)\n")

    features = [
        "Provenance (model, version, temp)",
        "Input hash (reproducibility)",
        "Per-node confidence distribution",
        "Reasoning trace (DAG)",
        "Trace method (live vs post-hoc)",
        "Alternative outputs",
        "Provenance chain (multi-turn)",
        "Built-in integrity (checksum)",
        "Tamper-evident signatures",
        "Streaming with partial delivery",
        "Human-readable",
        "Schema-enforced types",
        "Binary compact",
        "AI-to-AI without extra tooling",
    ]

    # native=✓ manual=~ none=✗
    matrix = {
        #                      SPIF  JSON  JSONL  XML   YAML  MsgPk CBOR
        features[0]:          ["✓",  "~",  "~",   "~",  "~",  "~",  "~"],
        features[1]:          ["✓",  "~",  "~",   "~",  "~",  "~",  "~"],
        features[2]:          ["✓",  "~",  "~",   "~",  "~",  "~",  "~"],
        features[3]:          ["✓",  "~",  "✗",   "~",  "~",  "~",  "~"],
        features[4]:          ["✓",  "~",  "✗",   "~",  "~",  "~",  "~"],
        features[5]:          ["✓",  "~",  "✗",   "~",  "~",  "~",  "~"],
        features[6]:          ["✓",  "~",  "✗",   "~",  "✗",  "~",  "~"],
        features[7]:          ["✓",  "~",  "✗",   "✗",  "✗",  "✗",  "✗"],
        features[8]:          ["✓",  "✗",  "✗",   "✗",  "✗",  "✗",  "✗"],
        features[9]:          ["✓",  "✗",  "~",   "✗",  "✗",  "~",  "✗"],
        features[10]:         ["✗",  "✓",  "✓",   "✓",  "✓",  "✗",  "✗"],
        features[11]:         ["✓",  "✗",  "✗",   "~",  "✗",  "✗",  "✗"],
        features[12]:         ["✓",  "✗",  "✗",   "✗",  "✗",  "✓",  "✓"],
        features[13]:         ["✓",  "~",  "✗",   "✗",  "✗",  "~",  "~"],
    }

    headers = ["Feature", "SPIF", "JSON", "JSONL", "XML", "YAML", "MsgPk", "CBOR"]
    col_w = [36, 6, 6, 7, 5, 6, 7, 6]
    header_line = "".join(h.ljust(w) for h, w in zip(headers, col_w))
    print(header_line)
    print("─" * sum(col_w))
    for feat, vals in matrix.items():
        row = feat.ljust(col_w[0]) + "".join(v.ljust(w) for v, w in zip(vals, col_w[1:]))
        print(row)

    print("\n  ✓ = native support    ~ = possible with manual boilerplate    ✗ = not supported")

    # Score SPIF
    spif_native = sum(1 for v in matrix.values() if v[0] == "✓")
    json_native = sum(1 for v in matrix.values() if v[1] == "✓")
    print(f"\n  SPIF: {spif_native}/{len(features)} features native")
    print(f"  JSON: {json_native}/{len(features)} features native ({len(features)-json_native} require manual implementation)")


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 82)
    print("SPIF vs AI-Native Format Benchmark")
    print("Scenarios: real AI output encoding, agent chains, streaming,")
    print("provenance extraction, context window cost, feature completeness")
    print("=" * 82)

    scenario_single_output()
    scenario_agent_chain()
    scenario_streaming()
    scenario_provenance_extraction()
    scenario_context_window()
    scenario_feature_matrix()

    print("\n" + "=" * 82)
    print("Key: all encode/decode times are μs per operation (500 reps).")
    print("     'manual' = the format can carry the data but requires caller-side code.")
    print("     'native' = the format enforces and validates the field automatically.")
    print("=" * 82)
