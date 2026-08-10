# EU Readiness Test Matrix Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Test SPIF as an infrastructure/provenance component that can support a deployer’s EU AI Act Article 50 workflow, while explicitly proving the limits of SPIF, GPAI documentation, and C2PA interoperability.

**Architecture:** Add a focused readiness test module under the existing Python test suite, with deterministic fixtures for content, provenance, signatures, and transport failures. Keep legal-scope assertions separate from wire-format assertions: the harness must be able to pass while recording that a detached `.spif` sidecar is not itself an Article 50 machine-readable mark. Publish only measured capabilities and gaps.

**Tech Stack:** Python 3.11, pytest, Hypothesis where useful, existing SPIF reader/writer/streaming APIs, `c2pa-python` 0.37.5 for explicitly bounded interoperability checks, local Ed25519 test keys, and existing OSS-Fuzz targets.

## Global Constraints

- Primary role: SPIF is an infrastructure/provenance component, not an AI-system provider or deployer.
- Never claim that SPIF alone is EU AI Act compliant; claim only that an integration supports a deployer’s evidence and marking workflow.
- Article 50 tests must distinguish machine-readable marking, visible labelling, detection, and provenance evidence.
- GPAI tests must distinguish per-output evidence from model documentation, training-data summaries, copyright policy, and systemic-risk safety obligations.
- C2PA tests must distinguish SPIF integrity/signatures from C2PA claims, hard bindings, certificate trust, and revocation.
- No network is required for deterministic tests; live C2PA/provider tests are opt-in and must not be presented as local conformance.
- Do not serialize raw prompts by default; test that provenance contains an input hash rather than prompt plaintext.
- Generated outputs remain local and gitignored.

## Source baseline

- EU AI Act Article 50 guidance and Code of Practice: <https://digital-strategy.ec.europa.eu/en/policies/code-practice-ai-generated-content>
- EU GPAI Code of Practice: <https://digital-strategy.ec.europa.eu/en/policies/contents-code-gpai>
- C2PA Content Credentials Specification 2.4: <https://spec.c2pa.org/specifications/specifications/2.4/specs/ContentCredentials.html>
- Repository wire contract: `docs/SPEC.md`
- Existing security limits: `SECURITY.md`

### Task 1: Establish the readiness fixture and result vocabulary

**Files:**
- Create: `spif/tests/test_eu_readiness.py`
- Modify: `spif/tests/conftest.py` only if a shared deterministic fixture is required

**Interfaces:**
- Create `ReadinessCase` data with `content`, `spif_bytes`, `role`, `transport`, and expected evidence fields.
- Create assertions named `assert_spif_integrity`, `assert_no_prompt_plaintext`, and `assert_chain_continuity`.
- Every test must state whether it proves a wire-format property, an integration-support property, or a gap.

- [ ] **Step 1: Write fixture tests** for a text output, a signed output, a chained output, and a tool-call output.
- [ ] **Step 2: Run** `spif/.venv-test/bin/python -m pytest -q spif/tests/test_eu_readiness.py`; confirm the new assertions expose missing fixtures before implementation.
- [ ] **Step 3: Implement deterministic fixture builders** using `SPIFDocument`, `Provenance`, `Node`, `SPIFWriter`, and the repository’s two-pass signing helper pattern.
- [ ] **Step 4: Verify** unsigned decode, strict signed decode, content ID stability, and chain references.
- [ ] **Step 5: Commit** `test: add EU readiness fixture vocabulary`.

### Task 2: Article 50 integration-support tests

**Files:**
- Modify: `spif/tests/test_eu_readiness.py`
- Modify: `README.md` and `docs/README.md` only after tests establish exact wording

**Interfaces:**
- Add `evaluate_article50_support(content, marker, visible_label, spif_bytes, transport)` returning explicit booleans for `machine_mark`, `visible_label`, `detectable_after_transport`, and `provenance_evidence`.

- [ ] **Step 1: Add the four scenarios:** chatbot interaction disclosure, machine-readable generated-text mark, deepfake/media label, and human-review/editorial-control exception.
- [ ] **Step 2: Add the negative control** proving that a detached `.spif` sidecar stripped during export does not satisfy `machine_mark` or `detectable_after_transport`.
- [ ] **Step 3: Add the positive integration fixture** where a deployer supplies a content-carried marker and SPIF supplies signed provenance evidence; assert that each responsibility is independently visible.
- [ ] **Step 4: Test export paths** that strip sidecars, preserve embedded markers, re-encode text, and transform binary media; record which evidence survives.
- [ ] **Step 5: Update public wording** to say SPIF supports deployer workflows and does not itself implement Article 50 marking or labelling.
- [ ] **Step 6: Run** `spif/.venv-test/bin/python -m pytest -q spif/tests/test_eu_readiness.py -k article50`.
- [ ] **Step 7: Commit** `test: cover Article 50 integration boundaries`.

### Task 3: C2PA interoperability and binding tests

**Files:**
- Modify: `spif/tests/test_eu_readiness.py`
- Modify: `spif/tests/test_c2pa_watermark_edge.py` only for reusable existing helpers

**Interfaces:**
- Add `C2PAInteropResult` with `hard_binding_valid`, `spif_signature_valid`, `trust_valid`, `survives_reencode`, and `manifest_removed` fields.

- [ ] **Step 1: Add a deterministic content-binding fixture** with a content hash shared by SPIF provenance and a C2PA-style assertion.
- [ ] **Step 2: Test hard-binding changes:** one-byte content mutation, line-ending changes, Unicode normalization, image re-encoding, and metadata stripping.
- [ ] **Step 3: Test manifest lifecycle:** manifest preserved, manifest removed, manifest redacted, and a new claim appended; distinguish SPIF failure from C2PA failure.
- [ ] **Step 4: Test trust boundaries:** self-signed credential rejection remains an expected limitation; CA-chain/trust-anchor validation is marked live-only unless a stable fixture exists.
- [ ] **Step 5: Assert no false equivalence:** passing SPIF signature verification must not set `trust_valid` or imply a valid C2PA manifest.
- [ ] **Step 6: Run** `spif/.venv-test/bin/python -m pytest -q spif/tests/test_eu_readiness.py spif/tests/test_c2pa_watermark_edge.py`.
- [ ] **Step 7: Commit** `test: define SPIF and C2PA binding boundaries`.

### Task 4: Privacy and hostile-input security tests

**Files:**
- Modify: `spif/tests/test_eu_readiness.py`
- Modify: `spif/tests/test_hardening.py` only when a regression belongs in the general security suite

**Interfaces:**
- Add `assert_prompt_minimized`, `assert_replay_rejected`, and `assert_resource_bound` helpers with bounded input sizes.

- [ ] **Step 1: Test prompt minimization** with email addresses, names, identifiers, and secrets; verify raw prompt text is absent from encoded provenance unless explicitly placed in payload by the caller.
- [ ] **Step 2: Test replay controls** using stale timestamps, duplicate content IDs, signer rotation, revocation, and context-chain substitution.
- [ ] **Step 3: Test malformed inputs** including truncated headers, invalid CBOR, duplicate IDs, dangling references, cyclic trace/payload DAGs, unknown chunks, oversized declared lengths, and compressed-bomb limits.
- [ ] **Step 4: Test multi-tenant separation** with signer IDs, context references, and payloads from two tenants; verify no cross-chain acceptance.
- [ ] **Step 5: Run Python and Rust fuzz targets** locally for bounded smoke iterations; keep long campaigns in OSS-Fuzz rather than CI.
- [ ] **Step 6: Run** `spif/.venv-test/bin/python -m pytest -q spif/tests/test_eu_readiness.py -k 'privacy or security or hostile'` and the focused Rust security tests.
- [ ] **Step 7: Commit** `test: cover privacy and hostile provenance inputs`.

### Task 5: Real-world resilience tests

**Files:**
- Modify: `spif/tests/test_eu_readiness.py`
- Reuse: `spif/tests/test_streaming.py`, `spif/tests/test_live_provider_acceptance.py`, and adapter unit-test fakes

**Interfaces:**
- Add `run_resilience_case(adapter, failure_mode)` returning `stream_state`, `final_document`, `retry_count`, `context_ref`, and `verification_state`.

- [ ] **Step 1: Test stream interruption** before header completion, after partial text, before checksum, and after checksum; assert incomplete streams never become verified documents.
- [ ] **Step 2: Test retry behavior** for provider errors, empty responses, tool errors, and duplicate provider response IDs; verify attempt metadata and chain identity.
- [ ] **Step 3: Test clock skew** for local timestamps, max signature age, future timestamps, and offline verification.
- [ ] **Step 4: Test provider substitution** by changing the returned model ID and confirming provenance reflects the actual response model rather than the requested model.
- [ ] **Step 5: Run** deterministic fake-provider tests first, then opt-in live tests for Claude Opus 5 and GPT-5.6.
- [ ] **Step 6: Commit** `test: cover provider and streaming resilience`.

### Task 6: GPAI boundary matrix and release documentation

**Files:**
- Modify: `docs/README.md`
- Modify: `README.md`
- Modify: `SECURITY.md`
- Modify: `docs/BENCHMARKS.md` only for measured test results

**Interfaces:**
- Add a concise capability table with columns `Requirement area`, `SPIF evidence`, `Integrator responsibility`, `Not provided by SPIF`, and `Test reference`.

- [ ] **Step 1: Document supported evidence:** per-output model identity, timestamp, input hash, tool-call trace, signed chain, integrity verification, and offline verification.
- [ ] **Step 2: Document explicit non-coverage:** training-data summary, copyright policy, model technical documentation, systemic-risk safety framework, public transparency label, C2PA trust-list membership, and cross-artifact binding by default.
- [ ] **Step 3: Link each statement to an implemented test or existing specification section.**
- [ ] **Step 4: Add a release gate** that rejects language such as “SPIF is EU AI Act compliant” and permits only “SPIF supports deployer evidence workflows.”
- [ ] **Step 5: Run** link checks, the complete non-live suite, and the live provider smoke test.
- [ ] **Step 6: Commit** `docs: state EU AI Act and GPAI integration boundaries`.

### Task 7: Final release-gate verification

**Files:**
- No production files unless a preceding test exposes a defect.

- [ ] **Step 1: Run** `spif/.venv-test/bin/python -m pytest -q spif/tests -m 'not live'` with local socket permissions for sidecar tests.
- [ ] **Step 2: Run** focused Claude 5 and GPT-5.6 completion/streaming wrappers and decode every generated SPIF document locally.
- [ ] **Step 3: Run** bounded fuzz smoke tests and record corpus/iteration counts without committing generated outputs.
- [ ] **Step 4: Confirm** C2PA self-signed rejection is classified as an expected limitation, not a passing interoperability result.
- [ ] **Step 5: Confirm** all public claims use the infrastructure-component role and list integrator responsibilities.
- [ ] **Step 6: Review OSS-Fuzz PR status, CodeRabbit comments, and CI status before merging any code PR.
- [ ] **Step 7: Commit** `test: finalize EU readiness release gate`.
