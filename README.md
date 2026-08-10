<div align="center">

# SPIF

### Semantic Provenance Inference Format

An open binary format for carrying **signed, tamper-evident provenance** with AI outputs.

SPIF makes an AI result auditable from the first input to the final response—across models,
tools, agents, and organizational boundaries.

<p>
  <a href="docs/SPEC.md">Read the specification</a> ·
  <a href="https://intelogroup.github.io/spif/">Verify a file in your browser</a> ·
  <a href="spif/README.md">Use the Python package</a>
</p>

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Spec: v0.2](https://img.shields.io/badge/spec-v0.2--active-success.svg)](docs/SPEC.md)
[![Rust tests](https://github.com/intelogroup/spif/actions/workflows/spif-rust-test.yml/badge.svg)](https://github.com/intelogroup/spif/actions/workflows/spif-rust-test.yml)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/intelogroup/spif/badge)](https://scorecard.dev/viewer/?uri=github.com/intelogroup/spif)
[![CodeQL](https://github.com/intelogroup/spif/actions/workflows/codeql.yml/badge.svg)](https://github.com/intelogroup/spif/actions/workflows/codeql.yml)

</div>

## The problem

An AI response is rarely just text. It may depend on a prompt, model version, tool calls,
retrieval results, retries, human approvals, and other agents. Once that context is separated
from the response, it becomes difficult to answer simple questions:

> What produced this output? Was it changed? Can I prove it?

SPIF packages the answer into a portable `.spif` artifact. It records the lineage, protects the
artifact with checksums and signatures, and can be verified without uploading the file anywhere.

## What SPIF carries

| Layer | Includes |
| --- | --- |
| **Identity** | Model, provider, agent, task, timestamps, and execution metadata |
| **Lineage** | Prompts, responses, tool calls, retries, handoffs, and linked context |
| **Signal** | Uncertainty distributions, status, errors, and audit-relevant events |
| **Assurance** | Checksums, Ed25519 signatures, multi-signature workflows, and strict validation |

## EU AI Act integration boundaries

SPIF provides signed, tamper-evident provenance for AI outputs. It can support
a deployer’s Article 50 implementation by carrying provenance alongside the
output, but it is not an AI-system provider, deployer, or standalone compliance
solution.

The deployer remains responsible for the user-facing disclosure, visible label,
machine-readable marking, content binding, and preservation of those signals
through the output’s lifecycle. SPIF does not generate or validate those
signals. See the [EU AI Act integration documentation](docs/README.md)
for the integration model and limitations.

| Requirement area | SPIF provides | Deployer or provider provides |
|---|---|---|---|
| Article 50 | Signed per-output identity, timestamp, input hash, and chain | Content-carried marking, visible disclosure, detection, and lifecycle preservation |
| C2PA workflows | Signed provenance and content-hash evidence | C2PA manifest, hard binding, credential trust, and lifecycle handling |
| Privacy and security | Hash-based input reference, signatures, bounded parsing, and trace integrity | Lawful processing, retention, access control, replay protection, and tenant isolation |
| GPAI evidence | Per-output model and generation metadata | Model documentation, training-data summary, copyright policy, and systemic-risk controls |

---

## Why teams use it

- **Portable:** one format across Python, Rust, and WebAssembly.
- **Auditable:** preserve the chain of inputs, transformations, and outputs across agentic workflows.
- **Tamper-evident:** detect modified payloads, broken checksums, and invalid signatures early.
- **Local-first:** the browser verifier runs entirely in WebAssembly; files are not uploaded.
- **Bounded:** strict parsing and early offset validation help defend against malformed or hostile input.
- **Practical:** stream, sign, validate, decode, and export from a CLI or library.

## Try it in under a minute

The repository includes valid, tampered, and corrupted fixtures so the trust model is easy to
see in practice:

```bash
# Validate structure and verify signatures
PYTHONPATH=spif python3 -m spif.cli validate examples/fixtures/sample_valid.spif
PYTHONPATH=spif python3 -m spif.cli verify examples/fixtures/sample_valid.spif

# A changed payload is rejected
PYTHONPATH=spif python3 -m spif.cli verify examples/fixtures/sample_tampered.spif
```

Expected results include `OK`, `VALID`, and `INVALID signature verification failed`.

### Install the Python CLI

```bash
cd spif
pip install -e ".[dev]"
spif --help
```

### Build the Rust engine

```bash
cd spif-rust
cargo build --release
cargo test
```

### Verify in the browser

Open the [SPIF Web Verifier](https://intelogroup.github.io/spif/), drop in a `.spif` file, and
inspect its signature status and decoded JSON locally in your browser. The verifier is the
project's GUI inspection tool; there is no standalone desktop viewer or upload API.

## Repository layout

| Path | Role |
| --- | --- |
| [`spif/`](spif/) | Python reference implementation, CLI, streaming support, and provider adapters |
| [`spif-rust/`](spif-rust/) | Native Rust engine, CLI, sidecar, and cross-language validation |
| [`verify/`](verify/) | Static WebAssembly verifier for `.spif` files |
| [`examples/`](examples/) | Programmatically generated, specification-compliant fixtures |
| [`docs/`](docs/) | Wire specification, security audit, benchmarks, and integration guidance |

## Learn more

- [Specification](docs/SPEC.md) — wire format, chunks, validation, and compatibility
- [Cryptographic audit](docs/CRYPTO_AUDIT.md) — security model and design considerations
- [Benchmarks](docs/BENCHMARKS.md) — reproducibility metadata and performance comparisons
- [Python implementation](spif/README.md) · [Rust implementation](spif-rust/README.md)
- [Contributing](CONTRIBUTING.md) · [Security policy](SECURITY.md)

## License

SPIF is licensed under [Apache-2.0](LICENSE).
