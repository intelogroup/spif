# SPIF v1.0.0 — Semantic Provenance Inference Format

**Release Date**: April 5, 2026  
**Wire Format**: v0.2 (locked, no breaking changes planned)  
**Stability**: Production-ready

---

## Overview

SPIF v1.0 marks the first production release of the Semantic Provenance Inference Format. The wire format (v0.2) is **frozen**. All implementations that claim v1.0 compliance MUST:

1. Support reading all v0.1 and v0.2 documents
2. Write documents using wire format v0.2
3. Enforce the cryptographic guarantees documented in `CRYPTO_AUDIT.md`
4. Pass the interoperability test suite

---

## What's New in v1.0

### Stabilization
- Format specification locked and audited
- Cryptographic implementation security-reviewed
- Cross-implementation compatibility fixtures published
- Real-world acceptance test suite covering:
  - Streaming → signing → export → tamper detection
  - Multi-provider acceptance (Anthropic, OpenAI, Gemini)
  - Context chaining and delta documents

### New in the Package
- **CRYPTO_AUDIT.md**: Complete security review of ed25519, PBKDF2, and checksum layers
- **Acceptance tests** for all major LLM providers
- **MsgPack export**: Lossless serialization via `spif export --msgpack`
- **Revocation support**: Key rotation and signer revocation checking
- **Tool calling support**: NODE_TOOL_CALL and NODE_TOOL_RESULT types

### Backward Compatibility
- v0.1 documents are read with deprecation warnings
- No v0.1 documents are written (migrate by re-encoding)
- Wire format unchanged from v0.2

---

## Breaking Changes from Previous Releases

None. Existing v0.2 documents will remain valid indefinitely.

---

## Production Readiness Checklist

| Requirement | Status | Evidence |
|---|---|---|
| Specification frozen | ✅ | SPEC.md marked v1.0, wire format v0.2 locked |
| Security audit completed | ✅ | CRYPTO_AUDIT.md approved |
| Test coverage: security | ✅ | 62 dedicated security/crypto tests |
| Test coverage: roundtrip | ✅ | 472 tests pass (all non-live) |
| Real-world acceptance | ✅ | test_real_world_acceptance.py scenarios |
| Multi-implementation | ✅ | TypeScript/Deno reader available |
| Documentation complete | ✅ | README.md, SPEC.md, CLI help |
| Package maturity | ✅ | Python 3.9–3.12 tested |

---

## Known Limitations

1. **OTel/PROV exports are lossy**: Signatures, embeddings, and alternatives are not represented in OpenTelemetry or W3C PROV formats (by design — these formats lack the required structure)

2. **Revocation is out-of-band**: Signer revocation lists are not stored in SPIF documents. Verifiers must fetch and validate revocation status from a separate source (e.g., a URL or file)

3. **Timestamp validation (Opt-In)**: SPIF natively supports replay protection and time-bounded signature validation. Callers can enable this by passing `max_signature_age_seconds` to `SPIFReader` or `verify_signature()`, which compares the system clock against `timestamp_ms` to reject expired documents. This is disabled by default to maintain backward compatibility with offline devices with clock drift.

4. **No perfect forward secrecy**: Old signing keys compromise old signatures. Use key rotation (`rotate_key()`) to document transitions

---

## Guidance for Users

### For Producers (Creating SPIF Documents)

```python
from spif import SPIFWriter, SPIFDocument, Node, Distribution, Provenance

# Basic document with provenance
doc = SPIFDocument(
    payload=[
        Node(
            id="response",
            type="text",
            value="Your answer here.",
            confidence=Distribution(mean=0.9, semantics="epistemic"),
        )
    ],
    provenance=Provenance(
        source_model="claude-sonnet-4-6",
        temperature=0.2,
        timestamp_ms=int(time.time() * 1000),
    ),
)

# Encode to bytes
encoded = SPIFWriter().encode(doc)

# Sign for tamper-evidence (recommended)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import base64
private_key = Ed25519PrivateKey.from_private_bytes(...)
signer_id = base64.b64encode(private_key.public_key()...).decode()
# See test_signature.py for two-pass signing pattern
```

### For Consumers (Reading SPIF Documents)

```python
from spif import SPIFReader

# Read with signature enforcement
reader = SPIFReader.strict()  # Rejects unsigned documents
doc = reader.read("artifact.spfx")

# Verify signature
is_valid = reader.verify_signature(open("artifact.spfx", "rb").read())
if not is_valid:
    raise ValueError("Signature verification failed")

# Access content
for node in doc.payload:
    print(f"{node.id}: {node.value} (confidence: {node.confidence.mean})")
```

### For Infrastructure (Audit & Observability)

```python
from spif.exporters.otel import to_otel_span
from spif.exporters.prov import to_prov

doc = SPIFReader().read("artifact.spfx")

# Export to OpenTelemetry
span = to_otel_span(doc)
# Push to observability backend

# Export to W3C PROV
prov = to_prov(doc)
# Store in provenance archive
```

---

## Migration Guide (for v0.2 Users)

Your existing v0.2 documents will continue to work. No action required.

If you want to upgrade to v1.0 features:
- Locking your key derivation to PBKDF2 100k iterations is fine; Argon2 upgrade is optional
- New `semantics` field in Distribution: add to your documents for better uncertainty semantics
- New TOOL_CALL and TOOL_RESULT node types: adopt for agent workflows

---

## Future Direction (v1.1 and Beyond)

Items deferred to future releases (not blocking v1.0):

- **Argon2 key derivation** (GPU-resistant): Implementation available, pending adoption decision
- **STREAM_RESUME robustness**: Current implementation works; future enhancements to multi-fragment recovery
- **Ed448 support**: Lower priority; ed25519 is suitable for next 10+ years

---

## Testing & Deployment

### Run the Test Suite
```bash
# All tests except live provider tests (requires API keys)
pytest tests/ -m "not live" -v

# With coverage
pytest tests/ -m "not live" --cov=spif --cov-report=term-missing
```

### Run Real-World Acceptance Tests (Optional)
```bash
export ANTHROPIC_API_KEY="sk-ant-..."
export OPENAI_API_KEY="sk-..."
pytest tests/test_live_provider_acceptance.py -v -m live
```

### Security Review
Read `CRYPTO_AUDIT.md` for the complete cryptographic assessment.

---

## Support & Issues

For bug reports, feature requests, and security issues:
- GitHub Issues: [anthropics/spif](https://github.com/anthropics/spif/issues)
- Security disclosure: [security@anthropic.com](mailto:security@anthropic.com)

---

## License

MIT — See LICENSE file.

---

## Acknowledgments

SPIF v1.0 builds on:
- RFC 8949 (CBOR) for deterministic serialization
- RFC 8032 (Ed25519) for cryptographic signing
- NIST guidance on key derivation and salt management
- W3C PROV and OpenTelemetry for interoperability exports

---

**Status**: ✅ Production-ready. Wire format locked. Ready for integration.
