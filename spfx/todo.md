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

## Enterprise Readiness — Making Top AI Companies Try SPIF

### 1. Zero-Friction First Experience
- [ ] **Publish to PyPI** — `pip install spif` works out of the box (pure Python wheel, no build-from-source)
- [ ] **Publish to npm** — `npm install spif` works (WASM build for Node/browser/Deno/Bun)
- [ ] **`spif` CLI works instantly** — `spif sign "hello" > out.spif && spif verify out.spif` with no setup
- [ ] **Maturin fallback** — Python Rust extension auto-detects and falls back gracefully if no compiler available

### 2. One-Line Integration into Their Stack
- [ ] **`spif-langchain` pip package** — `SpifCallback` wraps any LLM chain in one import
- [ ] **`spif-llamaindex` pip package** — same for LlamaIndex
- [ ] **`spif-fastapi` middleware** — auto-sign every API response
- [ ] **`spif-django` middleware** — auto-sign all outgoing responses
- [ ] **`spif-grpc` interceptor** — auto-sign every gRPC response
- [ ] **`spif-opentelemetry`** — auto-traces sign/verify spans

### 3. Rich Type Hints & IDE Support
- [ ] **Full type annotations** on every public function (no `-> Any`)
- [ ] **`py.typed` marker** in the Python package
- [ ] **`mypy --strict` passes** with zero errors in CI
- [ ] **`cargo doc --open`** is useful — `#[doc]` on every public Rust function
- [ ] **VS Code/PyCharm hover docs** — docstrings on every public symbol

### 4. Async Everywhere
- [ ] **`sign_async()` / `verify_async()`** — asyncio wrappers for server usage
- [ ] **Async streaming** — `async for chunk in sign_stream(payload)` for large payloads
- [ ] **Thread-safe signers** — callable from multiple coroutines without locks
- [ ] **Async context managers** — `async with SpifSigner(key=...) as signer`

### 5. Rich Error Messages
- [ ] **Error class hierarchy** — separate exception for every failure mode (`SignatureMismatchError`, `ReplayAttackError`, `ExpiredTimestampError`, …)
- [ ] **Byte-offset error messages** — "Signature mismatch at byte offset 247-347 (ed25519, key_id=ab:cd:ef:12)"
- [ ] **Suggested fixes** in error text — "Payload was modified after signing, or wrong public key was used"
- [ ] **All errors exported at package root** — `from spif import VerificationError`

### 6. Deterministic, Reproducible Output
- [ ] **Canonical CBOR** — same input + same key → same binary every time
- [ ] **Cross-arch test** — `assert sign(b"x") == sign(b"x")` passes on x86, ARM, macOS, Linux
- [ ] **No random nonce** — ed25519 is deterministic by spec; verify no nonce leaks in any code path
- [ ] **Float encoding forced** to single representation

### 7. Minimal Dependency Tree
- [ ] **Python: only `cbor2` + (maybe) `cryptography`** — no `requests`, `pydantic`, `click`, `numpy`
- [ ] **Rust: only `ciborium` + `ed25519-dalek`** — zero other transitive deps
- [ ] **`spif-minimal` package** — even fewer deps (just CBOR, calls user's own signer)
- [ ] **Document every dep** in README with rationale
- [ ] **`pipdeptree` + `cargo tree`** run in CI to catch dependency creep

### 8. Backward-Compatibility Test Suite
- [ ] **`test_vectors/` archive** — signed SPIF files from every release, stored in repo
- [ ] **CI runs current code against all historical vectors** — never break existing SPIFs
- [ ] **`BREAKING_CHANGES.md`** — documents every intentional incompatibility with migration guide
- [ ] **Version in envelope** — decoder gives clear error: "File from SPIF v0.8, decoder is v1.5 — run pip install --upgrade spif"

### 9. FFI Bindings for Every Language
- [ ] **C ABI `cdylib`** — single Rust lib exposing `spif_sign()`, `spif_verify()`, `spif_free()`
- [ ] **JavaScript/TypeScript** — `wasm-pack` build from the C ABI
- [ ] **Go bindings** — `cgo` wrapper around the C ABI
- [ ] **Java/JNI bindings** — JNI wrapper around the C ABI
- [ ] **All bindings tested in CI** with the same test vectors

### 10. Benchmarks in the Repo
- [ ] **`BENCHMARKS.md`** — live numbers updated from CI
- [ ] **Multi-arch benches** — AMD EPYC, Apple Silicon, Raspberry Pi, Cloudflare Worker
- [ ] **Cover real sizes** — 100B, 1KB, 10KB, 1MB, 100MB
- [ ] **Cover all ops** — decode, sign, verify, streaming, bulk batch
- [ ] **`cargo bench` + `pytest-benchmark`** harness in the repo
