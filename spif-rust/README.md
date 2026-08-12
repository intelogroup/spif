<div align="center">

<img src="../assets/spif-mark.svg#gh-light-mode-only" alt="SPIF provenance mark" width="112" />
<img src="../assets/spif-mark-dark.svg#gh-dark-mode-only" alt="SPIF provenance mark" width="112" />

# SPIF Rust

### Native parsing, signing, streaming, and verification.

[Back to the project overview](../README.md) · [Read the specification](../docs/SPEC.md) · [Python implementation](../spif-py/README.md)

</div>

<br />

The Rust implementation of SPIF provides a native engine for reading, writing, streaming, and
verifying signed `.spif` artifacts.

| Capability | Status |
| --- | --- |
| Read and write core SPIF documents | Supported |
| zlib-compressed payload chunks via `flags2` | Supported |
| Byte-accurate Ed25519 signature verification | Supported |
| Streaming reader and writer | Supported |
| Cross-language conformance fixtures | Supported |

## Quickstart

Useful commands:

```bash
cargo test --quiet
cargo fmt --check
```

## What this crate powers

```text
.spif artifact → Rust reader → checksum + signature verification → trusted payload
```

The crate also exposes a WebAssembly verification module in `wasm.rs`, built with
`wasm-pack build --target web`. It is a library artifact, not a hosted web page or verification
API.
