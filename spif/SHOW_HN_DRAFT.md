Show HN: SPIF — a binary format for AI outputs with provenance, uncertainty, trace, and signatures

What it is
- SPIF is a CBOR-based container for AI outputs. It stores payload, per-node uncertainty distributions, reasoning traces, provenance (model, temp, input hash), alternatives, deltas, and optional ed25519 signatures. Streaming is a first-class variant.

Why
- Auditability and interoperability for agent/LLM outputs: one file you can sign, stream, replay, export to OTel/PROV, or hand to another model.

What’s new
- Lossless MsgPack export/import (`to_msgpack`/`from_msgpack`, `spfx export --msgpack`).
- Live-tested Anthropic/OpenAI adapters (stream + complete, signing, export).
- Acceptance workflow test: streaming → signed artifact → OTel/PROV export → tamper detection.

Quick start
- `pip install spfx` (and `npm install spfx-js` if you want TS)
- `spfx export demo.spfx --lossless-json` or `--msgpack`
- `python - <<'PY'
from spfx import SPIFReader, to_msgpack, from_msgpack
doc = SPIFReader().read("demo.spfx")
blob = to_msgpack(doc)
restored = from_msgpack(blob)
PY`

Streaming quick start
- `python - <<'PY'
from spfx import SPIFDocument, Node
from spfx.streaming import SPIFStreamWriter, SPIFStreamReader

sw = SPIFStreamWriter()
buf  = sw.open()
buf += sw.partial_text("Hello ", seq=0)
buf += sw.partial_text("world!", seq=1)
buf += sw.commit(SPIFDocument(payload=[Node(id="n1", type="text", value="Hello world!")]))

for event in SPIFStreamReader().feed(buf):
    print(type(event).__name__, event)
PY`

Demos
- Streaming examples in `examples/`
- Signed/streaming fixtures in `compat/`

Caveats
- Alpha/spec-reference; wire contract stable at v0.2.
- Checksum is not tamper-proof—use signatures for integrity.
- OTel/PROV exports are lossy (signatures/embeddings/alternatives are dropped).

Links
- GitHub repo: https://github.com/intelogroup/spif
- Spec: `SPEC.md`
- Examples: `examples/`
