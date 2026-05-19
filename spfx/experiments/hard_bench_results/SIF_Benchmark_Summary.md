# SIF Hard Benchmark - Executive Summary

## Overview
Compares SIF against JSON, JSON-minimal, CBOR, MsgPack, and BSON across nine synthetic document categories.

## Test Configuration
- **Test Categories**: Minimal, Medium, Complex Trace, Full, Extreme Dist, Unicode Stress, Large Embeddings, Max Payload, Adversarial
- **Documents per Category**: 10 (Quick mode)
- **Total Test Documents**: 90
- **Benchmark Date**: 2026-04-08

---

## Methodology Notes

**Two JSON baselines are included:**

- `JSON` (`json_full`) encodes all SPIF fields in flat JSON — confidence mean/var/shape, refs, trace steps, provenance. This is the equivalent-data comparison: JSON carrying the same information as SIF. SIF is competitive with `json_full` on size for most categories.
- `JSON-minimal` encodes text payload only (id, type, value, model), representing what a developer would write without SPIF. This is the realistic baseline for applications that don't need typed confidence or trace. SIF is 3–15x slower and 2–6x larger than `json_minimal` for typical documents.

**Semantic fidelity** is measured as the fraction of SPIF-specific typed fields (Distribution objects, NodeRef DAG) that survive a roundtrip. SIF scores 1.0 because it was designed for these types. Alternatives score 0.80–0.90 because they use flat encodings — this does not imply they are inferior for general use, only that they cannot natively round-trip SPIF's typed schema without a separate schema layer.

**`json_minimal` fidelity** would score ~0.50 — it loses confidence, trace, refs, and provenance entirely. It is included for size/speed context, not fidelity comparison.

---

## Key Findings

### 1. Semantic Fidelity
SIF achieves perfect fidelity (1.0) for its native types. Alternatives lose typed Distribution objects:

| Format | Fidelity | Primary loss |
|--------|----------|--------------|
| SIF | 1.0 | None |
| JSON / CBOR / MsgPack / BSON | 0.80–0.90 | Distribution → 3 flat fields |
| JSON-minimal | ~0.50 | Confidence, trace, refs, provenance dropped |

### 2. Size Efficiency

| Category | SIF | JSON | JSON-minimal | CBOR | MsgPack | BSON |
|----------|-----|------|--------------|------|---------|------|
| Minimal | 255 | 193 | 107 | 160 | 160 | 200 |
| Medium | 1,310 | 1,255 | 623 | 1,112 | 1,112 | 1,318 |
| Complex Trace | 2,150 | 1,757 | 157 | 1,575 | 1,593 | 1,910 |
| Full | 5,920 | 6,313 | 1,034 | 4,823 | 4,836 | 5,883 |
| Max Payload | 179,854 | 200,658 | 101,782 | 170,768 | 170,768 | 203,665 |

SIF is larger than CBOR/MsgPack but competitive with JSON-full and BSON. For `complex_trace` documents (where most value is in the trace), JSON-minimal is 14x smaller — the trace overhead is the cost of the feature.

### 3. Performance (μs roundtrip)

| Category | SIF | JSON | JSON-minimal | CBOR | MsgPack | BSON |
|----------|-----|------|--------------|------|---------|------|
| Minimal | 15.2 | 4.3 | 3.0 | 6.4 | 1.7 | 1.9 |
| Medium | 40.4 | 14.1 | 6.5 | 21.7 | 6.6 | 7.8 |
| Complex Trace | 65.0 | 18.6 | 3.1 | 30.6 | 9.2 | 10.8 |
| Full | 145.0 | 83.1 | 9.9 | 82.2 | 25.2 | 32.3 |
| Max Payload | 4,663.7 | 2,275.1 | 901.2 | 4,167.7 | 1,606.6 | 1,920.4 |

SIF is 2–3x slower than JSON-full and 5–21x slower than JSON-minimal. MsgPack is fastest. For throughput-sensitive pipelines where confidence/trace are not consumed, JSON-minimal or MsgPack are better choices.

### 4. Integrity & Security

Most formats detect the tested 1-byte flip via parse errors. Notable exception:

- **MsgPack and BSON fail to detect tamper on `large_embeddings`** — a 1-byte flip in a large float array produces a valid but silently wrong document.
- SIF, JSON, CBOR detect corruption on every category tested.
- SIF additionally provides SHA-256 checksums and optional ed25519 signatures for tamper evidence (not just parse-error detection).

### 5. SIF-Specific Strengths

- Native typed `Distribution` objects (mean, var, shape, semantics) — not flat fields
- First-class `NodeRef` DAG with cycle detection on decode
- SHA-256 checksum (accidental corruption) + ed25519 signatures (intentional tampering)
- Content-addressed stable `content_id()` for audit chains
- Streaming protocol (SSPIF) with resume tokens

---

## When to Use SIF

**Use SIF when:** you need typed confidence distributions, reasoning trace provenance, multi-signature audit chains, or streaming with resumption.

**Use JSON-full when:** you need human readability and schema flexibility, and can reconstruct types from flat fields at the application layer.

**Use JSON-minimal / MsgPack when:** you only need text payload and model identity, throughput matters, and downstream consumers don't use confidence or trace.

---

*Generated from SIF Hard Benchmark — 2026-04-08*
*Location: /Users/kalinovdameus/Developer/brainex/spif/experiments/hard_bench_results/*
