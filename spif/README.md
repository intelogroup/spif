# SPIF — Semantic Provenance Inference Format

**Cryptographically signed, tamper-evident provenance for AI outputs.**

SPIF is a binary wire format that wraps any LLM response with a SHA-256 checksum and an ed25519 signature — baked into the format itself, not bolted on. Every document carries: who produced it, which model, at what timestamp, in what chain of prior calls. Any byte changed after signing is detected on decode.

```
pip install spif
```

---

## The Problem

AI outputs flow through pipelines — model to application to database to downstream model — as plain JSON strings. There is no standard way to prove:

- Which model produced a specific response
- That the response was not modified in transit or at rest
- That a chain of AI calls traces back to a known origin

SPIF solves this at the wire format level.

---

## Quickstart

### Wrap an Anthropic response

```python
from anthropic import Anthropic
from spif.adapters.anthropic_adapter import AnthropicSPIFAdapter
from spif.writer import SPIFWriter

client = Anthropic()
adapter = AnthropicSPIFAdapter(client, model="claude-sonnet-4-6")

doc = adapter.complete("Summarize the EU AI Act in one paragraph.")

# Write to disk — tamper-evident binary
SPIFWriter().write(doc, "response.spif")
```

### Wrap an OpenAI response

```python
from openai import OpenAI
from spif.adapters.openai_adapter import OpenAISPIFAdapter
from spif.writer import SPIFWriter

client = OpenAI()
adapter = OpenAISPIFAdapter(client, model="gpt-4o")

doc = adapter.complete("Summarize the EU AI Act in one paragraph.")
SPIFWriter().write(doc, "response.spif")
```

### Sign the output

```python
from pathlib import Path
from spif.crypto import derive_key_from_mnemonic, sign_document

# Always supply a non-empty passphrase for production-grade keys.
# Leaving passphrase empty ("") works but triggers a UserWarning about PBKDF2 precomputation risk.
key = derive_key_from_mnemonic("your twelve word mnemonic phrase here", passphrase="strong-passphrase")
signed_bytes = sign_document(doc, key, signer_id="https://yourorg.com/keys/signing-key-1")
Path("signed.spif").write_bytes(signed_bytes)
```

Or use a PEM private key:

```python
from pathlib import Path
from spif.crypto import load_pem_private_key, sign_document

key = load_pem_private_key("private_key.pem")
signed_bytes = sign_document(doc, key, signer_id="https://yourorg.com/keys/v1")
Path("signed.spif").write_bytes(signed_bytes)
```

### Verify

```python
from spif.reader import SPIFReader

# Always verifies checksum on decode
doc = SPIFReader().decode(open("signed.spif", "rb").read())

# Strict: reject unsigned documents
doc = SPIFReader(require_signature=True).decode(data)

# Verify against a known signer
doc = SPIFReader().decode(data, verify_signer="https://yourorg.com/keys/v1")

# Time-bounded verification: reject replay attacks if document is older than allowed age limit
reader = SPIFReader(require_signature=True, max_signature_age_seconds=60)
doc = reader.decode(data)

# You can also pass max_signature_age_seconds directly to verify_signature
is_valid = reader.verify_signature(data, max_signature_age_seconds=60)

print(doc.provenance.source_model)    # "claude-sonnet-4-6" (or server-resolved dynamic snapshot, e.g. "gpt-4o-2024-05-13")
print(doc.provenance.timestamp_ms)    # Unix epoch ms
print(doc.provenance.input_hash)      # SHA-256 of the prompt
print(doc.provenance.context_ref)     # content_id of prior doc in chain
```

### CLI

```bash
spif validate response.spif          # checksum + signature check
spif inspect response.spif           # show provenance, model, timestamp
spif verify response.spif --signer https://yourorg.com/keys/v1
spif sign response.spif --key "twelve word mnemonic" --signer-id https://yourorg.com/keys/v1
```

---

## Audit Chains

`context_ref` links documents into a verifiable call chain. When Agent B calls a model using Agent A's output as context, the resulting SPIF document references A's `content_id`. An auditor can reconstruct the full decision chain.

```python
from spif.types import content_id

# Agent A produces a document
doc_a = adapter_a.complete("What are the risks?")
ref = content_id(doc_a)  # stable SHA-256 content address

# Agent B continues the chain
adapter_b = AnthropicSPIFAdapter(client, model="claude-sonnet-4-6", context_ref=ref)
doc_b = adapter_b.complete("Given the risks, recommend an action.")

# doc_b.provenance.context_ref == ref
# The chain is auditable end to end
```

---

## Wire Format

SPIF is a chunked binary container (similar structure to PNG):

```
\x89SPIF\r\n\x1a\n   — 9-byte magic
0x02                  — version byte (frozen)
flags                 — compression, streaming flags
HEADER chunk          — model, timestamp, flags
PROVENANCE chunk      — source_model, input_hash, context_ref, attempt, task_id
PAYLOAD chunk         — CBOR-encoded output nodes
[SIGNATURE chunk]     — ed25519 signature over all preceding bytes
CHECKSUM chunk        — SHA-256 of everything before it
```

The format is self-describing: a SPIF reader needs no external schema to parse and verify a document. The checksum covers the signature, so removing the signature chunk is also detected.

**Tamper detection is absolute**: every byte flip in a signed document raises `SPIFChecksumError` or `SPIFSignatureError` on decode. There are no silent corruptions.

---

## Install

```bash
# Full install
pip install spif

# Verification only (minimal dependencies)
pip install spif[verify]

# With Anthropic adapter
pip install spif[anthropic]

# With OpenAI adapter
pip install spif[openai]
```

---

## Language Support

| Language | Package | Status |
|----------|---------|--------|
| Python | `pip install spif` | Production — writer + reader + adapters |
| TypeScript/Deno | `compat/sif_reader.ts` | Reader only |
| Node.js / npm | coming soon | — |

---

## Why Not JSON + HMAC?

You can bolt an HMAC onto any JSON response. SPIF is different in three ways:

1. **Format-level, not application-level.** The checksum and signature are part of the binary framing — not a field in your JSON that someone can delete or forget to check.
2. **Self-describing.** Any SPIF reader, in any language, can verify the document without knowing your application schema.
3. **Content-addressed chains.** `content_id` is a stable hash of the document content, making multi-turn audit chains reconstructable without a central registry.

---

## Specification

Full wire format specification: [`docs/SPEC.md`](../docs/SPEC.md)

Cryptographic implementation audit: [`docs/CRYPTO_AUDIT.md`](../docs/CRYPTO_AUDIT.md)

---

## License

Apache-2.0
