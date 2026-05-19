# SPIF — Product Roadmap

## EU AI Act Compliance Stack

- [ ] **1. SPIF output provenance** (done) — tamper-evident logging of every AI output with model, timestamp, input hash, signature
- [ ] **2. Model card / training data registry** — link SPIF documents back to the model version and training data that produced them
- [ ] **3. Risk classification tooling** — tag SPIF documents with EU AI Act risk tier (minimal / limited / high / unacceptable) at write time
- [ ] **4. Human review workflow** — tooling to route high-risk SPIF outputs to a human reviewer before they act on the decision; log the review outcome in the chain
- [ ] **5. Audit dashboard** — read `.spfx` archives and present regulators with a verifiable timeline of every AI decision: model, timestamp, input hash, signature; the part that turns SPIF from a library into a compliance product

## Framework Integrations

- [ ] npm / Node.js reader package (done — `packages/spif-js`)
- [ ] LangChain adapter example (done — `examples/langchain_adapter.py`)
- [ ] LlamaIndex adapter example (done — `examples/llamaindex_adapter.py`)
- [ ] LangChain adapter — publish as standalone pip package
- [ ] LlamaIndex adapter — publish as standalone pip package
- [ ] Gemini adapter (in progress — `spif/adapters/gemini_adapter.py`)

## Publishing

- [ ] Publish Python package to PyPI: `twine upload dist/spif-1.0.0-py3-none-any.whl`
- [ ] Publish JS package to npm: `cd packages/spif-js && npm publish`
