# SPIF Documentation

- [Wire format specification](SPEC.md) — the external interface: chunk layout, encoding, signing. Start here if you're implementing a reader/writer.
- [Crypto audit](CRYPTO_AUDIT.md) — key derivation, signature scheme, threat coverage.
- [Security policy](../SECURITY.md) — how to report a vulnerability.
- [IETF draft](../draft-ietf-spif-00.md) — standards-track draft of the format.
- [Benchmarks](BENCHMARKS.md) — serialization and provenance/attestation comparisons.
- [EU AI Act integration boundaries](#eu-ai-act-integration-boundaries) — measured support and explicit gaps for deployers, C2PA, and GPAI evidence workflows.

## EU AI Act integration boundaries

SPIF is an infrastructure/provenance component, not an AI-system provider or
deployer. SPIF alone is not EU AI Act compliant.

| Requirement area | SPIF evidence | Integrator responsibility | Not provided by SPIF |
|---|---|---|---|
| Article 50 | Signed output identity, timestamp, input hash, and chain | Content-carried machine mark, visible label, disclosure, detection, and transport preservation | Standalone Article 50 compliance |
| C2PA | SPIF integrity and content-hash evidence | C2PA manifest, hard binding, credential trust, and lifecycle handling | C2PA conformance or trust-list membership |
| Privacy/security | Hash-based input reference, signatures, bounded parsing, trace integrity | Retention, access control, replay state, tenant isolation, and lawful processing | A complete privacy program |
| GPAI evidence | Per-output model and generation metadata | Technical model documentation, training-data summary, copyright policy, and systemic-risk controls | GPAI provider obligations |

The executable matrix is [`spif/tests/test_eu_readiness.py`](../spif/tests/test_eu_readiness.py).
A detached `.spif` sidecar is provenance evidence, not a content-carried
machine-readable mark; deployers must preserve required marking and labelling
through export. SPIF signatures do not establish C2PA hard binding or trust.
- Component READMEs: [`spif/`](../spif/README.md) (Python), [`spif-rust/`](../spif-rust/README.md) (Rust).

See [CONTRIBUTING.md](../CONTRIBUTING.md) for how to propose changes.
