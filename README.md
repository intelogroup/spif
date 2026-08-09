# SPIF: Semantic Provenance Inference Format

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Format Specification](https://img.shields.io/badge/Spec-v0.2--Active-success)](spif/SPEC.md)
[![Rust Tests](https://github.com/intelogroup/spif/actions/workflows/spif-rust-test.yml/badge.svg)](https://github.com/intelogroup/spif/actions/workflows/spif-rust-test.yml)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/intelogroup/spif/badge)](https://scorecard.dev/viewer/?uri=github.com/intelogroup/spif)
[![CodeQL](https://github.com/intelogroup/spif/actions/workflows/codeql.yml/badge.svg)](https://github.com/intelogroup/spif/actions/workflows/codeql.yml)

**SPIF** (Semantic Provenance Inference Format) is an open-standard binary serialization format designed for structured, cryptographically signed, and tamper-evident AI outputs. SPIF captures the full lineage of AI inference—including prompts, responses, reasoning traces, uncertainty distributions, tool calls, and multiple signatures—ensuring high auditability and trust in agentic workflows.

## Table of Contents

- [Key Features](#key-features)
- [Monorepo Project Layout](#monorepo-project-layout)
- [Programmatic Specification-Compliant Samples](#programmatic-specification-compliant-samples)
- [Getting Started](#getting-started)
- [Cryptographic Assurance & Triage](#cryptographic-assurance--triage)
- [Contributing](#contributing)
- [License](#license)

---

## Key Features

- **Tamper-Evident Multi-Signatures**: Dual and multi-signature co-signing supporting sequential client-to-proxy signatures with automatic device-key compromise recovery.
- **High-Performance Core Optimizations**:
  - $O(N)$ fast-path DAG validation short-circuits bypassing topological sorting for minimal/medium documents.
  - Thread-safe LRU cryptographic key cache (`maxsize=256`) making repetitive DER key reconstruction instantaneous.
  - Configurable zstandard compression levels supporting up to **80%+ speedups in serialization**.
- **Denial-of-Service / Memory Exhaustion Protection**: Early stream-offset validation preventing pre-allocation buffer out-of-memory exploits (CVE-2026-34665 style) on truncated or malicious payloads.
- **Rich Metadata & Lineage**: Full support for `task_info` (status, total execution duration, tool counts, error counts) and `provenance` retries.
- **Cross-Language Fidelity**: Complete feature parity and validated interoperability between Python, TypeScript/Node.js, and Rust.
- **Web Verifier**: In-browser, wasm-based `.spif` verification — nothing uploaded. See [`/verify`](verify/).

---

## Monorepo Project Layout

This repository is structured as a monorepo, containing all components of the SPIF ecosystem:

| Path | Component | Language / Stack | Description |
| :--- | :--- | :--- | :--- |
| [`/spif`](spif/) | **Core Python & CLI** | Python 3.9+ | Main specification (`SPEC.md`), reference compiler, CLI generator, and LLM integrations. |
| [`/spif-rust`](spif-rust/) | **Rust Engine & CLI** | Rust (2021) | Ultra-fast native core decoder, multi-signer validator, and high-throughput batch signature verifier. |
| [`/verify`](verify/) | **Web Verifier** | Rust/wasm | Static, in-browser `.spif` verifier — no upload, no GUI viewer, ghost artifact stays binary-only. Live at [intelogroup.github.io/spif](https://intelogroup.github.io/spif/). |

---

## Programmatic Specification-Compliant Samples

The workspace root includes verified specification-compliant SPIF sample binaries demonstrating bidirectional interoperability (generated programmatically via [`generate_root_samples.py`](generate_root_samples.py)):

- [`sample_valid.spif`](sample_valid.spif): A valid, dual cryptographically signed, complete document with full `task_info` and `provenance` metadata.
- [`sample_tampered.spif`](sample_tampered.spif): Structural CBOR content has been altered while maintaining signature values to demonstrate cryptographic tamper-detection.
- [`sample_corrupted.spif`](sample_corrupted.spif): Bit flipped in the checksum chunk, triggering early-stage checksum failure.

### Programmatic Verification

**Using Python CLI (`spif`):**
```bash
# Verify the valid sample
$ python3 -m spif.cli validate sample_valid.spif && python3 -m spif.cli verify sample_valid.spif
OK  sample_valid.spif
VALID  sample_valid.spif  (signer: DoZuYeLW80Gu8Vr9mAOHVosMPYHe3rT7S50fuK+D)

# Verify the tampered sample (Fails Cryptographically)
$ python3 -m spif.cli verify sample_tampered.spif
INVALID  signature verification failed for sample_tampered.spif

# Verify the corrupted sample (Fails Checksum)
$ python3 -m spif.cli validate sample_corrupted.spif
FAIL  sample_corrupted.spif: Checksum mismatch
```

**Using the web verifier (no install, wasm, nothing uploaded):**

https://intelogroup.github.io/spif/ — drop a `.spif` file, get signature status and full decoded JSON in-browser. Source in [`/verify`](verify/). There is no standalone native viewer/desktop app — the web verifier is the only GUI-based inspection tool.

---

## Getting Started

### 1. Python & CLI (`spif`)
Generate cryptographically signed SPIF payloads via Python or integrated CLI:
```bash
cd spif
pip install -e ".[dev]"
spif --help
```

### 2. Rust Engine (`spif-rust`)
Build the ultra-fast Rust encoder/decoder library:
```bash
cd spif-rust
cargo build --release
cargo test
```

---

## Cryptographic Assurance & Triage

SPIF implements eager signature verification under **Strict Mode**. Any modification to payload segments or invalid checksums will instantly raise a signature validation error, protecting agent-to-agent and server-to-client pipelines from man-in-the-middle forging.

*For security audits and detailed architectural considerations, see [CRYPTO_AUDIT.md](spif/CRYPTO_AUDIT.md) and [SPEC.md](spif/SPEC.md).*

---

## Contributing

Contributions are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md) for dev setup, coding standards, and the PR process across the Python, Rust, and wasm components. Security issues should follow [SECURITY.md](SECURITY.md) instead of a public issue.

---

## License

This monorepo is licensed under **Apache-2.0** — see [LICENSE](LICENSE).

