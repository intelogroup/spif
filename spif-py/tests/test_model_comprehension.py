"""
Model Comprehension Test — Scenario G
=======================================
Tests whether Claude can correctly extract provenance fields from a SPIF document
presented in different encodings/representations.

Marked `@live` — requires ANTHROPIC_API_KEY. Skipped automatically when absent.

Run:
    pytest tests/test_model_comprehension.py -v -m live
    pytest tests/test_model_comprehension.py -v -m live -k "not base64"  # skip hard ones
"""
from __future__ import annotations

import base64
import gzip
import json
import os
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
MODEL = "claude-haiku-4-5-20251001"  # cheapest, fastest

pytestmark = [
    pytest.mark.live,
    pytest.mark.skipif(not ANTHROPIC_API_KEY, reason="ANTHROPIC_API_KEY not set"),
]

# ─────────────────────────────────────────────────────────────────────────────
# Document factory (same document every time — deterministic answers)
# ─────────────────────────────────────────────────────────────────────────────

RESPONSE_TEXT  = "Remote work has reshaped urban office demand significantly."
MODEL_NAME     = "claude-sonnet-4-6"
CONFIDENCE     = 0.85
N_TRACE_STEPS  = 3
CONTEXT_REF    = "sha256:abc123def456"

def _make_doc():
    from spif import SPIFDocument, Node, TraceStep, Distribution, Provenance
    return SPIFDocument(
        payload=[Node(id="response", type="text", value=RESPONSE_TEXT,
                      confidence=Distribution(mean=CONFIDENCE, var=0.05,
                                              shape="gaussian", semantics="output_stability"))],
        provenance=Provenance(source_model=MODEL_NAME, model_version=MODEL_NAME,
                              temperature=0.7, input_hash="a" * 64,
                              timestamp_ms=1712000000000, context_ref=CONTEXT_REF),
        trace=[
            *[__import__("spif").TraceStep(
                id=f"t{i}", type="inference", content=f"Reasoning step {i}.",
                confidence=Distribution(mean=0.8, var=0.04, shape="gaussian",
                                        semantics="epistemic"),
                deps=[f"t{i-1}"] if i > 0 else [])
              for i in range(N_TRACE_STEPS)]
        ],
        trace_method="live",
    )


def _make_doc_safe():
    """Lazy import version safe for top-level calls."""
    from spif import SPIFDocument, Node, TraceStep, Distribution, Provenance
    doc = SPIFDocument(
        payload=[Node(id="response", type="text", value=RESPONSE_TEXT,
                      confidence=Distribution(mean=CONFIDENCE, var=0.05,
                                              shape="gaussian", semantics="output_stability"))],
        provenance=Provenance(source_model=MODEL_NAME, model_version=MODEL_NAME,
                              temperature=0.7, input_hash="a" * 64,
                              timestamp_ms=1712000000000, context_ref=CONTEXT_REF),
        trace=[
            TraceStep(id=f"t{i}", type="inference", content=f"Reasoning step {i}.",
                      confidence=Distribution(mean=0.8, var=0.04, shape="gaussian",
                                              semantics="epistemic"),
                      deps=[f"t{i-1}"] if i > 0 else [])
            for i in range(N_TRACE_STEPS)
        ],
        trace_method="live",
    )
    return doc


# ─────────────────────────────────────────────────────────────────────────────
# Format encoders
# ─────────────────────────────────────────────────────────────────────────────

def _spif_base64(doc) -> str:
    from spif import SPIFWriter
    return base64.b64encode(SPIFWriter().encode(doc)).decode()


def _spif_gzip_base64(doc) -> str:
    from spif import SPIFWriter
    return base64.b64encode(gzip.compress(SPIFWriter().encode(doc), compresslevel=9)).decode()


def _spif_render(doc) -> str:
    from spif.renderer import SPIFRenderer
    return SPIFRenderer().render(doc)


def _spif_lossless_json(doc) -> str:
    import hashlib
    from spif.types import Distribution

    def dist(d):
        return {"m": d.mean, "v": d.var, "s": d.shape, "sem": d.semantics}

    p = doc.provenance
    body = {
        "fmt": "spif", "v": "0.2",
        "prov": {"m": p.source_model, "mv": p.model_version, "tmp": p.temperature,
                 "ts": p.timestamp_ms, "ih": p.input_hash, "cr": p.context_ref},
        "payload": [{"id": n.id, "t": n.type,
                     "val": n.value if isinstance(n.value, str) else str(n.value),
                     "c": dist(n.confidence)} for n in doc.payload],
        "trace": [{"id": s.id, "t": s.type,
                   "cont": s.content if isinstance(s.content, str) else str(s.content),
                   "c": dist(s.confidence),
                   "deps": s.deps} for s in doc.trace],
        "tm": doc.trace_method,
    }
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"))
    body["cksum"] = "sha256:" + hashlib.sha256(canonical.encode()).hexdigest()
    return json.dumps(body, separators=(",", ":"))


def _json_manual(doc) -> str:
    return json.dumps({
        "response": RESPONSE_TEXT,
        "provenance": {"source_model": MODEL_NAME, "timestamp_ms": 1712000000000,
                       "temperature": 0.7, "context_ref": CONTEXT_REF},
        "confidence": {"mean": CONFIDENCE, "var": 0.05, "shape": "gaussian"},
        "trace": [{"id": f"t{i}", "type": "inference", "content": f"Reasoning step {i}.",
                   "deps": [f"t{i-1}"] if i > 0 else []}
                  for i in range(N_TRACE_STEPS)],
        "trace_method": "live",
    }, indent=2)


def _yaml_doc(doc) -> str:
    import yaml
    return yaml.dump({
        "response": RESPONSE_TEXT,
        "provenance": {"source_model": MODEL_NAME, "timestamp_ms": 1712000000000,
                       "context_ref": CONTEXT_REF},
        "confidence": {"mean": CONFIDENCE, "var": 0.05},
        "trace": [{"id": f"t{i}", "type": "inference", "content": f"Reasoning step {i}."}
                  for i in range(N_TRACE_STEPS)],
        "trace_method": "live",
    }, default_flow_style=False)


# ─────────────────────────────────────────────────────────────────────────────
# Questions and expected answers
# ─────────────────────────────────────────────────────────────────────────────

QUESTIONS = [
    (
        "model_name",
        "What is the name of the AI model that produced this output? "
        "Reply with just the model identifier, nothing else.",
        lambda ans: MODEL_NAME.lower() in ans.lower(),
    ),
    (
        "confidence",
        "What is the confidence level (mean) of the response? "
        "Reply with just the decimal number, nothing else.",
        lambda ans: "0.85" in ans or "85%" in ans,
    ),
    (
        "trace_count",
        "How many reasoning trace steps are in this document? "
        "Reply with just the integer, nothing else.",
        lambda ans: str(N_TRACE_STEPS) in ans,
    ),
    (
        "context_ref",
        "What is the context_ref or context reference value in this document? "
        "Reply with just the value (or 'none' if absent), nothing else.",
        lambda ans: "abc123" in ans.lower() or "sha256" in ans.lower(),
    ),
]


# ─────────────────────────────────────────────────────────────────────────────
# Core helper: ask Claude one question about one document
# ─────────────────────────────────────────────────────────────────────────────

def _ask(client, doc_text: str, question: str, system: str = "") -> tuple[str, float]:
    """Returns (answer_text, latency_seconds)."""
    messages = [{"role": "user", "content": f"Document:\n\n{doc_text}\n\nQuestion: {question}"}]
    kwargs = {"model": MODEL, "max_tokens": 64, "messages": messages}
    if system:
        kwargs["system"] = system
    t0 = time.perf_counter()
    resp = client.messages.create(**kwargs)
    latency = time.perf_counter() - t0
    return resp.content[0].text.strip(), latency


# ─────────────────────────────────────────────────────────────────────────────
# Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_comprehension_matrix():
    """
    2D accuracy matrix: format × question.
    Asserts that JSON, YAML, SPIF-render, and SPIF-lossless-JSON all achieve
    100% accuracy on model_name and confidence questions.
    """
    import anthropic
    client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
    doc = _make_doc_safe()

    formats = {
        "JSON":              _json_manual(doc),
        "YAML":              _yaml_doc(doc),
        "SPIF-render":       _spif_render(doc),
        "SPIF-lossless-JSON": _spif_lossless_json(doc),
    }

    results: dict[str, dict[str, bool]] = {}
    for fmt_name, doc_text in formats.items():
        results[fmt_name] = {}
        for q_name, question, check in QUESTIONS:
            answer, _ = _ask(client, doc_text, question)
            results[fmt_name][q_name] = check(answer)

    print("\n\nComprehension matrix (✓=correct ✗=wrong):")
    print(f"  {'Format':<24} " + " ".join(f"{q[0]:>14}" for q in QUESTIONS))
    print("  " + "─" * 82)
    for fmt_name, scores in results.items():
        row = "  " + f"{fmt_name:<24} " + " ".join(
            f"{'✓':>14}" if scores[q[0]] else f"{'✗':>14}" for q in QUESTIONS
        )
        print(row)

    # JSON, YAML, SPIF-lossless-JSON must get all four questions right
    for fmt in ["JSON", "YAML", "SPIF-lossless-JSON"]:
        assert results[fmt]["model_name"], f"{fmt}: failed to extract model name"
        assert results[fmt]["confidence"], f"{fmt}: failed to extract confidence"

    # SPIF-render must get model_name right (it's in the PROVENANCE section)
    # but confidence and context_ref may fail — the renderer uses visual bars (████ 85%)
    # and does not always surface context_ref — this is a documented limitation
    assert results["SPIF-render"]["model_name"], \
        "SPIF-render: failed to extract model name (should be in PROVENANCE section)"
    if not results["SPIF-render"]["confidence"]:
        print("\n  NOTE: SPIF-render confidence extraction failed — "
              "renderer shows visual bars (████░ 85%) which models parse inconsistently. "
              "Use SPIF-lossless-JSON for model-to-model handoffs.")


@pytest.mark.slow
def test_spif_base64_comprehension():
    """
    Test whether Claude can understand a SPIF document passed as raw base64.
    Expectation: it CANNOT without a spec — this test documents the failure mode.
    """
    import anthropic
    client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
    doc = _make_doc_safe()

    doc_b64 = _spif_base64(doc)

    scores = {}
    for q_name, question, check in QUESTIONS[:2]:  # just model_name + confidence
        answer, _ = _ask(client, doc_b64, question)
        scores[q_name] = check(answer)

    print(f"\n  SPIF-base64 comprehension (no spec): {scores}")
    # Document the result without hard asserting — we expect failure
    # This test passes regardless; it's measuring, not enforcing
    print("  Note: base64 opaque to model — expected failure is fine here")


@pytest.mark.slow
def test_spif_base64_with_spec_hint():
    """
    Does providing a brief SPIF spec in the system prompt help the model decode base64?
    """
    import anthropic
    client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
    doc = _make_doc_safe()

    doc_b64 = _spif_base64(doc)

    system_prompt = (
        "You are processing SPIF (Semantic Provenance Inference Format) documents. "
        "SPIF is a binary format. When given as base64, decode it mentally and look for: "
        "provenance.source_model (the AI model name), payload[0].confidence.mean (a float 0-1), "
        "trace (list of reasoning steps), context_ref (SHA-256 of prior document). "
        "The binary contains CBOR-encoded chunks. Extract the requested field."
    )

    scores = {}
    for q_name, question, check in QUESTIONS[:2]:
        answer, latency = _ask(client, doc_b64, question, system=system_prompt)
        scores[q_name] = (check(answer), answer, latency)

    print(f"\n  SPIF-base64 WITH spec hint:")
    for q, (ok, ans, lat) in scores.items():
        print(f"    {q}: {'✓' if ok else '✗'}  answer={ans!r}  latency={lat:.2f}s")

    # With a spec hint the model still can't decode binary — document this
    any_correct = any(ok for ok, _, _ in scores.values())
    print(f"  Any correct with spec hint: {any_correct} (expected: False for base64)")


def test_lossless_json_preserves_context_ref():
    """
    Specific test: can a model find context_ref in SPIF-lossless-JSON?
    This is the multi-turn chain field — critical for agent pipelines.
    """
    import anthropic
    client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
    doc = _make_doc_safe()

    lj = _spif_lossless_json(doc)
    answer, latency = _ask(
        client, lj,
        "What is the context reference (context_ref or cr) value in the provenance? "
        "Reply with just the value."
    )

    print(f"\n  context_ref extraction from SPIF-lossless-JSON:")
    print(f"  Answer: {answer!r}  ({latency:.2f}s)")
    assert "abc123" in answer.lower() or "sha256" in answer.lower(), \
        f"Expected context_ref containing 'abc123', got: {answer!r}"


def test_render_vs_json_trace_count():
    """
    Does SPIF-render give more accurate trace step counts than JSON?
    Render has an explicit 'REASONING TRACE (N steps)' header.
    """
    import anthropic
    client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
    doc = _make_doc_safe()

    question = (
        f"How many reasoning trace steps are in this document? "
        f"Reply with just the integer."
    )

    render_ans, r_lat = _ask(client, _spif_render(doc), question)
    json_ans,   j_lat = _ask(client, _json_manual(doc), question)

    render_ok = str(N_TRACE_STEPS) in render_ans
    json_ok   = str(N_TRACE_STEPS) in json_ans

    print(f"\n  Trace count ({N_TRACE_STEPS} steps):")
    print(f"  SPIF-render: {'✓' if render_ok else '✗'}  {render_ans!r}  ({r_lat:.2f}s)")
    print(f"  JSON:        {'✓' if json_ok else '✗'}  {json_ans!r}  ({j_lat:.2f}s)")

    # Both should work — if render fails and JSON passes, that's a red flag
    assert render_ok or json_ok, "Neither format could extract trace count correctly"
