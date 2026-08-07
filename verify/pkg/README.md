# spif-rust

Rust implementation of the Semantic Provenance Inference Format.

Current v0.2 coverage:
- read and write core SPIF documents
- zlib-compressed payload-bearing chunks via `flags2`
- byte-accurate ed25519 signature verification against the raw signing body
- streaming reader and writer
- conformance checks against Python-generated compatibility fixtures

Useful commands:

```bash
cargo test --quiet
cargo fmt --check
```
