# Clinical Governance Evidence Vertical Slice Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a synthetic cross-system clinical-governance workflow showing signed SPIF evidence from AI recommendation through human review, action, and outcome, including revoked and unknown signer failures.

**Architecture:** Keep the SPIF wire format unchanged. Add a Python application-profile module that encodes six typed governance events as structured SPIF nodes, signs each event as an independent document with its actor key, and verifies the resulting chain using the existing `SPIFKeyStore` plus explicit trust-policy checks. Add one executable example and focused tests; no production service, PHI, dashboard, or regulatory-certification claim.

**Tech Stack:** Python 3, existing `spif-py` dataclasses/writer/reader/crypto/keystore, Ed25519 from `cryptography`, pytest.

**Spec:** Approved design in the conversation; no separate design document is created because project instructions prohibit summary Markdown files.

## Global Constraints

- Do not change the SPIF wire-format version, chunk registry, or core serialization schema.
- Encode `Decision`, `Evidence`, `PolicyEvaluation`, `Review`, `Action`, and `Outcome` as application-profile structured node values.
- Use one Ed25519 signer per actor/event; never use one platform key for the whole chain.
- Keep patient data synthetic and minimum-necessary.
- Unknown and revoked signers must be demonstrated as verification failures.
- Qventus remains an unconfirmed cold-outreach target; the example must be host/adaptor neutral.
- Do not add dashboards, network services, production EHR integrations, or broad compliance claims.

---

### Task 1: Define the clinical-governance application profile

**Files:**
- Create: `spif-py/spif/governance.py`
- Modify: `spif-py/spif/__init__.py`
- Test: `spif-py/tests/test_governance_profile.py`

**Interfaces:**
- `EVENT_TYPES: tuple[str, ...]` containing the six event names in workflow order.
- `EVENT_ROLE_BY_TYPE: dict[str, str]` mapping `Decision` to `model_provider`, `Evidence` to `evidence_service`, `PolicyEvaluation` to `policy_engine`, `Review` to `human_reviewer`, `Action` to `action_service`, and `Outcome` to `outcome_source`.
- `GovernanceEvent` dataclass with `event_type`, `event_id`, `timestamp_ms`, `actor`, `payload`, `parent_ids`, `policy_id`, and `credential_ref` fields.
- `GovernanceEvent.to_node() -> Node` and `GovernanceEvent.from_node(node: Node) -> GovernanceEvent`.
- `build_event_document(event: GovernanceEvent, *, nonce: str = "") -> SPIFDocument`.
- `event_from_document(doc: SPIFDocument) -> GovernanceEvent`.

- [ ] **Step 1: Write failing tests for event vocabulary and round-trip encoding**

Test that all six event types are accepted, event fields survive `GovernanceEvent -> Node -> GovernanceEvent`, unsupported event types fail with `ValueError`, and `build_event_document()` creates a valid document containing one structured node and provenance with the event actor and nonce.

- [ ] **Step 2: Run the focused tests and verify they fail**

Run: `cd spif-py && PYTHONPATH=. pytest tests/test_governance_profile.py -q`

Expected: collection or import failures because `spif.governance` does not exist.

- [ ] **Step 3: Implement the minimal profile module**

Use an existing node type such as `NODE_CONCEPT` or `NODE_MULTIMODAL` with a dictionary value containing:

```python
{
    "profile": "spif-clinical-governance-v0",
    "event_type": "Review",
    "event_id": "review-001",
    "timestamp_ms": 0,
    "actor": "hospital/reviewer/alice",
    "payload": {"decision": "approve", "override_flag": False},
    "parent_ids": ["decision-001", "policy-001"],
    "policy_id": "bed-placement-v1",
    "credential_ref": "credential://hospital/alice/clinical-ops",
}
```

Validate non-empty IDs, non-negative timestamps, non-empty actor/event type, and list-shaped parent IDs. Preserve RMF fields as application-profile payload keys without adding SPIF core fields.

- [ ] **Step 4: Run the focused tests and verify they pass**

Run: `cd spif-py && PYTHONPATH=. pytest tests/test_governance_profile.py -q`

Expected: all profile tests pass.

- [ ] **Step 5: Export the public profile API**

Add the profile symbols to `spif-py/spif/__init__.py` and test importing them from `spif`.

- [ ] **Step 6: Commit**

```bash
git add spif-py/spif/governance.py spif-py/spif/__init__.py spif-py/tests/test_governance_profile.py
git commit -m "feat: add clinical governance SPIF application profile"
```

### Task 2: Add per-actor signing and trust-chain verification

**Files:**
- Modify: `spif-py/spif/governance.py`
- Test: `spif-py/tests/test_governance_chain.py`

**Interfaces:**
- `sign_event(event: GovernanceEvent, private_key, signer_id: str, *, nonce: str = "") -> bytes`.
- `TrustDecision` dataclass with `event_id`, `signer_id`, `event_type`, `valid`, `reason`.
- `verify_event(data: bytes, keystore: SPIFKeyStore, *, expected_signer: str | None = None) -> TrustDecision`.
- `verify_chain(events: list[bytes], keystore: SPIFKeyStore) -> list[TrustDecision]`.

- [ ] **Step 1: Write failing tests for independent actor signatures**

Create generated keys for provider, evidence service, policy engine, reviewer, action service, and outcome source. Assert each signed event verifies with its registered public key and that the event signer is preserved after decoding.

- [ ] **Step 2: Add failing tests for unknown and revoked signers**

Assert `verify_event()` returns `valid=False` with stable reasons such as `unknown_signer` and `revoked_signer`. Assert `verify_chain()` reports the failing event and does not silently treat the chain as valid.

- [ ] **Step 3: Add failing tests for parent and expected-signer mismatches**

Assert a missing parent, wrong expected signer, tampered event bytes, and event-type/signer-role mismatch are rejected. Register each demo signer for the exact role from `EVENT_ROLE_BY_TYPE` with `SPIFKeyStore.authorize_role()` and require that authorization during verification; do not invent a second role database.

- [ ] **Step 4: Run focused tests and verify they fail**

Run: `cd spif-py && PYTHONPATH=. pytest tests/test_governance_chain.py -q`

Expected: missing signing and verification functions or failing assertions.

- [ ] **Step 5: Implement signing with the existing two-pass primitive**

Use `spif.crypto.sign_document()` and `SPIFWriter`; do not pass a signing key into `SPIFWriter`. Bind the signer ID, event type, and parent IDs into the signed structured node. Register public keys in the existing keystore and consult its revocation state before accepting a signer.

- [ ] **Step 6: Implement chain verification**

Decode each raw artifact with strict signature requirements, verify the signature through the keystore, reject unknown/revoked keys, validate event payloads, and ensure every declared parent ID was already present in the supplied chain. Return structured results rather than raising for expected trust failures; reserve exceptions for malformed SPIF bytes.

- [ ] **Step 7: Run focused tests and verify they pass**

Run: `cd spif-py && PYTHONPATH=. pytest tests/test_governance_chain.py -q`

Expected: all happy-path, tamper, unknown-signer, revoked-signer, and chain-link tests pass.

- [ ] **Step 8: Commit**

```bash
git add spif-py/spif/governance.py spif-py/tests/test_governance_chain.py
git commit -m "feat: verify signed clinical governance chains"
```

### Task 3: Build the cross-system synthetic workflow demonstration

**Files:**
- Create: `spif-py/examples/clinical_governance_chain.py`
- Test: `spif-py/tests/test_clinical_governance_demo.py`

**Interfaces:**
- `build_synthetic_chain() -> tuple[list[bytes], SPIFKeyStore]`.
- `summarize_chain(results: list[TrustDecision]) -> dict[str, object]`.
- `main() -> int`.

- [ ] **Step 1: Write failing end-to-end tests**

Assert the demo creates six artifacts in this order: `Decision`, `Evidence`, `PolicyEvaluation`, `Review`, `Action`, `Outcome`; each actor is distinct; the review contains both an approval path and an override-capable field; and the complete chain verifies.

- [ ] **Step 2: Add failing tests for cross-system boundaries**

Assert the payload identifies separate systems such as `qventus-sim`, `hospital-ehr-sim`, `policy-engine-sim`, and `bed-management-sim`, and that the final summary can reconstruct recommendation, evidence, policy, reviewer, action, and outcome.

- [ ] **Step 3: Add failing tests for live trust failures**

Remove one signer from the trust registry and assert the summary identifies `unknown_signer`. Revoke the reviewer key after creating the chain and assert the summary identifies `revoked_signer` for the review event.

- [ ] **Step 4: Run the end-to-end tests and verify they fail**

Run: `cd spif-py && PYTHONPATH=. pytest tests/test_clinical_governance_demo.py -q`

Expected: missing example module/functions.

- [ ] **Step 5: Implement the synthetic workflow**

Generate six ephemeral Ed25519 keys, register only the trusted public keys, create the event documents using synthetic patient/case identifiers, sign each event with its actor key, and verify the chain. Include CLI output that clearly shows the six events, signer IDs, verification state, and explicit revoked/unknown failure demonstrations.

- [ ] **Step 6: Run the end-to-end tests and example**

Run:

```bash
cd spif-py
PYTHONPATH=. pytest tests/test_clinical_governance_demo.py -q
PYTHONPATH=. python examples/clinical_governance_chain.py
```

Expected: the complete chain verifies, followed by visible failures for an unknown signer and a revoked reviewer.

- [ ] **Step 7: Commit**

```bash
git add spif-py/examples/clinical_governance_chain.py spif-py/tests/test_clinical_governance_demo.py
git commit -m "demo: add cross-system clinical governance evidence chain"
```

### Task 4: Run regression verification and prepare outreach artifact

**Files:**
- Modify: `spif-py/README.md` (brief application-profile example and explicit non-goals)
- Modify: `docs/README.md` (link to the clinical governance profile example)
- Test: existing `spif-py/tests/`

- [ ] **Step 1: Run the focused profile and chain tests together**

Run: `cd spif-py && PYTHONPATH=. pytest tests/test_governance_profile.py tests/test_governance_chain.py tests/test_clinical_governance_demo.py -q`

Expected: all new tests pass.

- [ ] **Step 2: Run the full Python test suite**

Run: `cd spif-py && PYTHONPATH=. pytest -q`

Expected: no regressions in existing signing, reader, writer, replay, adapter, or compatibility tests.

- [ ] **Step 3: Document the profile boundary**

State that RMF fields are currently application-profile payload fields, not core SPIF wire fields; the example is synthetic; the trust registry is a local prototype; and production credential issuance, EHR integration, retention, and compliance determinations remain external responsibilities.

- [ ] **Step 4: Verify the outreach demo from a clean command**

Run the example from the documented command and capture the exact five-minute walkthrough: recommendation, cross-system evidence, policy evaluation, reviewer approval/override, action, outcome, successful verification, unknown signer rejection, and revoked signer rejection.

- [ ] **Step 5: Commit**

```bash
git add spif-py/README.md docs/README.md
git commit -m "docs: explain clinical governance application profile"
```
