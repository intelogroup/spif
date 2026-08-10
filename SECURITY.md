# Security

SPIF is a binary format: CBOR payload + ed25519 signatures + a DAG (trace
steps and payload nodes with dependency edges). That puts it in three
overlapping threat models — parser, crypto, and provenance/DAG — plus
resource-exhaustion and supply-chain concerns on top. This document lists
the attack classes we test against and what currently passes, with real
numbers, not estimates.

## Reporting a vulnerability

Open a private security advisory on this repository, or email the
maintainer directly. Do not open a public issue for undisclosed
vulnerabilities.

## 1. Parser attacks

Vectors: zlib bombs, chunk-length overflow, corrupted magic bytes, unknown
chunk types, malformed/indefinite-length CBOR, duplicate map keys, integer
overflow.

- AFL++: 1.057B+ executions against `SPIFReader::new()` (unsigned-tolerant
  path), 0 crashes.
- libFuzzer: 4.6M executions against the same path, 0 crashes; 5.4M
  executions against `SPIFReader::strict()` (signature-required path), 0
  crashes.
- 15,664/15,664 single-bit tamper mutations against a signed fixture
  rejected cleanly (0 silent accepts, 0 panics). 1,957/1,957 truncation
  points rejected cleanly (0 panics).

**Status: tested, currently passing.**

## 2. Crypto attacks

Vectors: malleable signatures, truncated signatures, bit-flipped payloads
that still pass verification, invalid/undersized keys.

- ed25519: 5/5 RFC 8032 test vectors, 150/150 Project Wycheproof vectors.
- ~55,000 verifies/sec (see `docs/BENCHMARKS.md`).
- Signature verification (`SPIFReader::verify_signatures_internal`,
  `src/reader.rs`) rejects any non-ed25519 algorithm, any signer key that
  doesn't decode to 32 bytes, and any signature that fails
  `VerifyingKey::verify`.

**Status: tested against RFC 8032 and Wycheproof vectors, currently
passing.**

## 3. Provenance / DAG attacks

Vectors: cycle injection into the trace or payload DAG, dangling
dependency references, duplicate step/node IDs.

`SPIFReader::read()` (`src/reader.rs`) runs `validate_payload_dag()` and
`validate_trace_dag()` (Kahn's-algorithm cycle detection) *before*
signature enforcement. `verify_signature()` calls `read()` internally, so a
cyclic or dangling-reference DAG is rejected before signature checking
runs at all — a cyclic document cannot be waved through by an otherwise
valid signature.

Covered by `tests/audit.rs::test_cyclic_trace_rejected`,
`test_cyclic_payload_rejected`, `test_dangling_dep_rejected`,
`test_duplicate_trace_step_id_rejected`.

**Status: tested, currently passing.** This has not been benchmarked
against an external threat-model test suite (e.g. C2PA's) — that's future
work, not a claim made here.

## 4. Supply chain / binding attacks

Vectors: a `.spif` file detached from the artifact it claims to describe,
replayed/stale provenance, dependency vulnerabilities in the crate itself.

- `cargo audit`: 0 outstanding advisories as of this release (2 HIGH
  RustSec advisories, RUSTSEC-2026-0194/0195, fixed via `quick-xml`
  0.36→0.41).
- 2 Dependabot alerts (1 moderate, 1 low) are open and unrelated to the
  above; tracked for the next release, not fixed yet — see
  `docs/BENCHMARKS.md`.
- The web verifier (`verify/`, wasm-based) gives a decoded JSON dump for
  tooling that wants to cross-check a `.spif` against external provenance
  metadata; it does not itself perform cross-artifact binding checks. There
  is no native viewer/desktop binary.

**Status: dependency-level auditing only. No cross-artifact binding
mechanism exists yet — not claimed here.**

The EU-readiness matrix (`spif/tests/test_eu_readiness.py`) keeps this boundary
explicit: SPIF signatures and content hashes are not C2PA hard binding or
trust, and a detached sidecar is not an Article 50 content mark. Deployers
remain responsible for transport preservation, replay state, tenant isolation,
and applicable privacy controls.

## 5. Resource exhaustion / DoS

Vectors: very large DAGs, deeply nested structures, large compressed
payloads.

Tested with synthetic DAGs up to 50,000 nodes; scaling measured, not
independently re-verified in this document — see `docs/BENCHMARKS.md` for the
raw numbers before repeating them elsewhere.

## What's not done yet

- OpenSSF Scorecard: currently low (no branch protection, no pinned
  Actions, no token-permission hardening). Target for v1.0, not rc2.
- OSS-Fuzz: submission scaffold (`project.yaml`, `Dockerfile`, `build.sh`)
  builds locally but has not been submitted upstream to
  `google/oss-fuzz`. Target for v1.0.
- No independent third-party audit of the Rust/x86 build has taken place.
- No bug bounty program exists yet.

Numbers in this file are pulled from `docs/BENCHMARKS.md` and from tests that
were run and re-verified while writing this document, not from memory or
estimate.
