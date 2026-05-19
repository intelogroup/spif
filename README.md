# SPIF: Semantic Provenance Inference Format

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Format Specification](https://img.shields.io/badge/Spec-Active-success)](spfx/SPEC.md)

**SPIF** (Semantic Provenance Inference Format) is an open-standard binary serialization format designed for structured, cryptographically signed, and tamper-evident AI outputs. SPIF captures the full lineage of AI inference—including prompts, responses, reasoning traces, uncertainty distributions, tool calls, and multiple signatures—ensuring high auditability and trust in agentic workflows.

---

## Key Features

- **Tamper Evident**: Eager cryptographic validation of document segments using Ed25519 signatures (supporting single and multi-party signing).
- **Rich Metadata & Lineage**: Encodes model metadata, prompt structures, intermediate reasoning, tool execution histories, and raw or token-level uncertainty metrics.
- **High-Performance Parsing**: Compact binary layout utilizing CBOR (Concise Binary Object Representation) with highly optimized decoders.
- **Cross-Language Fidelity**: Complete feature parity and validated interoperability between Python, TypeScript/Node.js, and Rust.
- **Visual Analytics**: Interactive, desktop-grade visualizer for audit trails and probability distributions.

---

## Monorepo Project Layout

This repository is structured as a monorepo, containing all components of the SPIF ecosystem:

| Path | Component | Language / Stack | Description |
| :--- | :--- | :--- | :--- |
| [`/spfx`](spfx/) | **Core Python & CLI** | Python 3.9+ | Main specification (`SPEC.md`), reference compiler, CLI generator, and LLM integrations (OpenAI, Anthropic, Gemini). |
| [`/spfx/packages/spfx-js`](spfx/packages/spfx-js/) | **JS/TS Client Library** | TypeScript | High-performance isomorphic client library for Node.js, Web, and Edge runtimes. |
| [`/spif-rust`](spif-rust/) | **Rust Engine & CLI** | Rust (2021) | Ultra-fast native core decoder, multi-signer validator, and high-throughput batch signature verifier. |
| [`/spif-desktop`](spif-desktop/) | **SPIF Desktop Viewer** | Tauri, TS, React | A beautiful cross-platform desktop visualizer for inspecting reasoning traces, signatures, and distribution charts. |

---

## Getting Started

### 1. Python & CLI (`spfx`)
Generate cryptographically signed SPIF payloads via Python or integrated CLI:
```bash
cd spfx
pip install -e ".[dev]"
spfx --help
```

### 2. TypeScript / Node.js (`spfx-js`)
Decode and audit SPIF payloads in JavaScript environments:
```bash
cd spfx/packages/spfx-js
npm install
npm run build
npm test
```

### 3. Rust Engine (`spif-rust`)
Build the ultra-fast Rust encoder/decoder or CLI tool:
```bash
cd spif-rust
cargo build --release
cargo test
```

### 4. Desktop Visualizer (`spif-desktop`)
Launch the interactive desktop inspection interface:
```bash
cd spif-desktop
npm install
npm run dev
```

---

## Cryptographic Assurance & Triage

SPIF implements eager signature verification under **Strict Mode**. Any modification to payload segments or invalid checksums will instantly raise a signature validation error, protecting agent-to-agent and server-to-client pipelines from man-in-the-middle forging.

*For security audits and detailed architectural considerations, see [CRYPTO_AUDIT.md](spfx/CRYPTO_AUDIT.md) and [SPEC.md](spfx/SPEC.md).*

---

## License

This project is licensed under the **MIT License**. See the [LICENSE](LICENSE) file for details.
