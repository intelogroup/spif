<div align="center">

<img src="assets/spif-logo.svg" alt="SPIF — signed provenance for AI outputs" width="760" />

### Record where an AI output came from. Prove what influenced it. Detect when it changes.

SPIF is an open binary format for carrying signed, tamper-evident provenance across models,
tools, agents, and organizational boundaries.

<p>
  <a href="https://intelogroup.github.io/spif/">Try the browser verifier</a> ·
  <a href="spif/README.md">Install the Python package</a> ·
  <a href="docs/SPEC.md">Read the specification</a>
</p>

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Spec: v0.2](https://img.shields.io/badge/spec-v0.2--active-success.svg)](docs/SPEC.md)
[![Rust tests](https://github.com/intelogroup/spif/actions/workflows/spif-rust-test.yml/badge.svg)](https://github.com/intelogroup/spif/actions/workflows/spif-rust-test.yml)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/intelogroup/spif/badge)](https://scorecard.dev/viewer/?uri=github.com/intelogroup/spif)
[![CodeQL](https://github.com/intelogroup/spif/actions/workflows/codeql.yml/badge.svg)](https://github.com/intelogroup/spif/actions/workflows/codeql.yml)

</div>

<br />

<div align="center">
  <img src="assets/provenance-flow.svg" alt="Prompt flows through a model, tools, and an agent into a signed SPIF output" width="100%" />
</div>

## Why SPIF?

AI responses rarely come from a single step. They may depend on a prompt, model snapshot,
retrieval result, tool call, retry, human approval, or another agent. Once that context is
separated from the response, it becomes difficult to answer:

> What produced this output? Was it changed? Can I prove it?

SPIF packages the answer into a portable `.spif` artifact that can be checked locally without
uploading the file anywhere.

## Trace · Seal · Verify

|  | Capability | What it gives you |
| --- | --- | --- |
| **01** | **Trace** | Prompts, responses, model metadata, tool calls, retries, handoffs, and linked context |
| **02** | **Seal** | Checksums, Ed25519 signatures, multi-signature workflows, and strict validation |
| **03** | **Verify** | Offline inspection from Python, Rust, WebAssembly, or the browser |

## Try it in under a minute

The repository includes valid, tampered, and corrupted fixtures so the trust model is easy to
see in practice:

```bash
# Validate structure and verify signatures
PYTHONPATH=spif python3 -m spif.cli validate examples/fixtures/sample_valid.spif
PYTHONPATH=spif python3 -m spif.cli verify examples/fixtures/sample_valid.spif
# OK
# VALID

# A changed payload is rejected
PYTHONPATH=spif python3 -m spif.cli verify examples/fixtures/sample_tampered.spif
# INVALID signature verification failed
```

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

### The proof is visible

The same verifier catches a valid artifact and a modified payload locally:

<table>
  <tr>
    <td align="center"><strong>Valid artifact</strong></td>
    <td align="center"><strong>Tampered artifact</strong></td>
  </tr>
  <tr>
    <td><img src="assets/verifier-valid.png" alt="SPIF verifier showing signed and signature verified" width="100%" /></td>
    <td><img src="assets/verifier-tampered.png" alt="SPIF verifier showing signed and signature invalid" width="100%" /></td>
  </tr>
</table>

## What travels inside a SPIF artifact?

```text
IDENTITY  →  LINEAGE  →  SIGNAL  →  ASSURANCE
 model       prompts     uncertainty  checksums
 provider    tools       status       signatures
 timestamp   retries     errors       validation
```

SPIF uses a self-describing, chunked binary container. A reader can parse and verify a document
without an external schema:

```text
magic → version → header → provenance → payload → signature → checksum
```

## Choose your path

| You want to... | Start here |
| --- | --- |
| Verify a `.spif` file | [Browser verifier](https://intelogroup.github.io/spif/) |
| Add provenance to a Python app | [Python implementation](spif/README.md) |
| Build an interoperable reader or writer | [Wire specification](docs/SPEC.md) |
| Review the threat model | [Cryptographic audit](docs/CRYPTO_AUDIT.md) |
| Compare serialization performance | [Benchmarks](docs/BENCHMARKS.md) |
| Integrate provenance into a deployer workflow | [EU AI Act integration](docs/README.md) |

## Implementations

| Path | Role |
| --- | --- |
| [`spif/`](spif/) | Python reference implementation, CLI, streaming support, and provider adapters |
| [`spif-rust/`](spif-rust/) | Native Rust engine, CLI, sidecar, and cross-language validation |
| [`verify/`](verify/) | Static WebAssembly verifier for `.spif` files |
| [`examples/`](examples/) | Programmatically generated, specification-compliant fixtures |
| [`docs/`](docs/) | Wire specification, security audit, benchmarks, and integration guidance |

## Compliance integration

SPIF provides signed, tamper-evident provenance for AI outputs. It can support a deployer's
Article 50 implementation by carrying provenance alongside the output, but it is not an
AI-system provider, deployer, or standalone compliance solution.

See the [EU AI Act integration documentation](docs/README.md) for the integration model and
limitations.

## Contributing

Read [CONTRIBUTING.md](CONTRIBUTING.md) to propose changes, improve implementations, or add
interoperability work. Security issues should follow the process in [SECURITY.md](SECURITY.md).

## License

SPIF is licensed under [Apache-2.0](LICENSE).
