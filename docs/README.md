# SPIF Documentation

- [Wire format specification](SPEC.md) — the external interface: chunk layout, encoding, signing. Start here if you're implementing a reader/writer.
- [Security policy](../SECURITY.md) — how to report a vulnerability, key derivation, signature scheme, threat coverage.
- [IETF draft](../draft-ietf-spif-00.md) — standards-track draft of the format.
- [Benchmarks](BENCHMARKS.md) — serialization and provenance/attestation comparisons.
- [EU AI Act integration](#eu-ai-act-integration) — how to use SPIF as a provenance component in a deployer workflow.
- [Clinical governance application profile](../spif-py/README.md#clinical-governance-application-profile) — a synthetic, prototype-scoped cross-system evidence-chain walkthrough.

## EU AI Act integration

### Purpose

SPIF is a provenance component for AI pipelines. It records signed output
identity, timestamps, input references, model metadata, and provenance chains.
This information can help a deployer preserve evidence about how an output was
created.

SPIF is not an AI-system provider or deployer, and SPIF alone is not EU AI Act
compliant. The organization deploying the AI system remains responsible for
determining which obligations apply and implementing the corresponding user
experience, content marking, governance, and operational controls.

### Article 50 integration model

A deployer can return the generated content together with:

- a visible disclosure appropriate to the user interaction or content type;
- a machine-readable mark embedded or otherwise carried with the content; and
- signed SPIF bytes containing provenance evidence for the output.

The reference Python envelope is implemented by
[`spif-py/spif/eu_ai_act.py`](../spif-py/spif/eu_ai_act.py):

```python
from spif import build_deployer_output

response = build_deployer_output(
    content="Generated answer",
    visible_label="AI-generated",
    machine_readable_mark="deployer-mark-v1",
    spif_bytes=signed_spif_bytes,
)

payload = response.to_transport()
```

`to_transport()` returns JSON-safe fields. The deployer chooses and validates
the marking scheme, visible wording, rendering behavior, and transport path.
SPIF does not decide whether those choices satisfy a particular legal
obligation.

### C2PA and media workflows

SPIF is not a C2PA manifest and does not establish C2PA trust. A deployer that
uses C2PA may carry an externally generated manifest in the response envelope:

```python
response = build_deployer_output(
    content="Generated image reference",
    visible_label="AI-generated",
    machine_readable_mark="deployer-mark-v1",
    spif_bytes=signed_spif_bytes,
    c2pa_manifest=manifest_bytes,
)
```

The manifest remains the responsibility of the C2PA implementation, including
asset binding, certificate trust, timestamps, validation, and lifecycle
handling.

### Responsibilities and limitations

| Area | SPIF provides | Deployer or model provider provides |
|---|---|---|
| Article 50 | Signed per-output identity, timestamp, input hash, and chain | Content marking, visible disclosure, detection, and preservation through export |
| C2PA | Signed provenance and content-hash evidence | C2PA manifest, hard binding, credential trust, and lifecycle handling |
| Privacy and security | Input minimisation by hashing, signatures, bounded parsing, and trace integrity | Lawful processing, retention, access control, replay protection, and tenant isolation |
| GPAI evidence | Per-output model and generation metadata | Model documentation, training-data summary, copyright policy, and systemic-risk controls |

A detached `.spif` sidecar is provenance evidence. It is not, by itself, a
content-carried machine-readable mark. The integration tests in
[`spif-py/tests/test_eu_readiness.py`](../spif-py/tests/test_eu_readiness.py) and
[`spif-py/tests/test_eu_ai_act_profile.py`](../spif-py/tests/test_eu_ai_act_profile.py)
verify the envelope and integrity behaviors described here; they are not a
legal certification or a C2PA conformance test.
- Component READMEs: [`spif-py/`](../spif-py/README.md) (Python), [`spif-rust/`](../spif-rust/README.md) (Rust).

See [CONTRIBUTING.md](../CONTRIBUTING.md) for how to propose changes.
