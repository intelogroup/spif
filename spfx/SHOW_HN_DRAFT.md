Show HN: SPIF — a binary format for AI outputs with provenance, uncertainty, trace, and signatures

What it is
- SPIF is a CBOR-based container for AI outputs. It stores payload, per-node uncertainty distributions, reasoning traces, provenance (model, temp, input hash), alternatives, deltas, and optional ed25519 signatures. Streaming is a first-class variant.

Why
- Auditability and interoperability for agent/LLM outputs: one file you can sign, stream, replay, export to OTel/PROV, or hand to another model.

What’s new
- Lossless MsgPack export/import (`to_msgpack`/`from_msgpack`, `spif export --msgpack`).
- Live-tested Anthropic/OpenAI adapters (stream + complete, signing, export).
- Acceptance workflow test: streaming → signed artifact → OTel/PROV export → tamper detection.

Quick start
- `pip install spif` (and `npm install spif-js` if you want TS)
- `spif export demo.spfx --lossless-json` or `--msgpack`
- `python - <<'PY'\nfrom spif import SPIFReader, to_msgpack, from_msgpack\ndoc = SPIFReader().read(\"demo.spfx\")\nblob = to_msgpack(doc)\nrestored = from_msgpack(blob)\nPY`

Demos
- Streaming examples in `examples/`
- Signed/streaming fixtures in `compat/`

Caveats
- Alpha/spec-reference; wire contract stable at v0.2.
- Checksum is not tamper-proof—use signatures for integrity.
- OTel/PROV exports are lossy (signatures/embeddings/alternatives are dropped).

Links
- GitHub repo: <add>
- Spec: `SPEC.md`
- Examples: `examples/`
