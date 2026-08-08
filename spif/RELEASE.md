# SPIF v0.2.0 (proposed)

## Highlights
- Lossless MsgPack export/import: `to_msgpack` / `from_msgpack` and `spif export --msgpack`.
- Real-provider acceptance: Anthropic + OpenAI (stream + complete, signing, export).
- Acceptance workflow test: streaming → signed artifact → OTel/PROV export → tamper detection.
- Wire format unchanged (v0.2); compat fixtures remain valid.

## Install
- Python: `pip install spif`
- TypeScript: `npm install spif-js` (if publishing npm for this cut)

## Quickstart
```bash
spif export demo.spfx --lossless-json > demo.json
spif export demo.spfx --msgpack -o demo.msgpack
python - <<'PY'
from spif import SPIFReader, to_msgpack, from_msgpack
doc = SPIFReader().read("demo.spfx")
blob = to_msgpack(doc)
restored = from_msgpack(blob)
assert restored.payload[0].id == doc.payload[0].id
PY
```

## Security note
- Checksum detects corruption only.
- Tamper evidence requires signatures; use `SPIFReader.strict()` or `SPIFReader.verify_signature`.
- OTel/PROV exports drop signatures/embeddings/alternatives by design.

## Tested providers
- Anthropic: haiku/sonnet (stream + complete)
- OpenAI: gpt-4o-mini (stream + complete)
- Gemini: planned (key pending)

## What’s new since last cut
- MsgPack exporter/importer and CLI flag.
- Live acceptance suite for Anthropic/OpenAI.
- MsgPack and CLI export tests.
- Acceptance test that exercises stream → sign → export → tamper detect.

## Caveats
- Package still marked alpha/spec-reference; wire contract is stable at v0.2.
- OTel/PROV exports are lossy.

