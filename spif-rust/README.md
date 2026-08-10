<div align="center">

<img src="../assets/spif-mark.svg" alt="SPIF provenance mark" width="112" />

# SPIF Rust

### Native parsing, signing, streaming, and verification.

[Back to the project overview](../README.md) · [Read the specification](../docs/SPEC.md) · [Python implementation](../spif/README.md)

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

The crate also provides the engine behind the WebAssembly verifier. Files stay in the browser;
they are not uploaded to a server.

## Web verifier

`.spif` files can be verified in-browser with [Ghost Verifier](https://intelogroup.github.io/spif/)
(local-only, no upload, WASM-only) — source in [`../verify`](../verify),
built from this crate's `wasm` module via `wasm-pack build --target web`.
