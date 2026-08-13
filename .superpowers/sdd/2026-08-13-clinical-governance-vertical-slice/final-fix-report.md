# Final Fix Report: Clinical Governance Vertical Slice

## Scope

Resolved every required final-review finding without changing the SPIF wire
format, schema version, chunk registry, services, dashboards, production
integrations, or the synthetic/no-PHI nature of the walkthrough.

## Changes

### Trust verification

- `verify_event()` now resolves the signer from the signature chunk and, for a
  known non-revoked signer, verifies the raw Ed25519 signature before it uses
  event actor, signer binding, role, or provenance claims for policy decisions.
- Unknown and revoked signature signers retain their stable trust failures
  (`unknown_signer` and `revoked_signer`) because no trusted key is available
  for signature verification.
- Signed profile documents now require provenance. Its `source_model` must
  equal `event.actor` and its `timestamp_ms` must equal `event.timestamp_ms`.
  Stable failures are `missing_provenance`, `provenance_actor_mismatch`, and
  `provenance_timestamp_mismatch`.
- Removed the previously ignored `now_ms` arguments from `verify_event()` and
  `verify_chain()`. No governance caller used them.

### Chain and summary semantics

- `verify_chain()` keeps a mapping of previously verified event IDs, rejects a
  second verified event with `duplicate_event_id`, and does not overwrite the
  original verified parent entry.
- `summarize_chain()` now exposes `trust_valid` and `complete`. `complete` is
  true only when exactly one valid result exists for each required governance
  event type. `valid` is the conjunction of these two properties.

### API and demo neutrality

- Exported `TrustDecision`, `sign_event`, `verify_event`, and `verify_chain`
  from the top-level `spif` API.
- Replaced the `qventus-sim` demo identifier with
  `recommendation-platform-sim` in the example, tests, and CLI output.

## Regression coverage

- Added signed negative provenance tests for missing provenance, actor
  mismatch, and timestamp mismatch.
- Added exact `invalid_signature` assertions for tampered signed payload,
  actor, event type, and role claims.
- Added a duplicate-ID/parent-substitution chain test that confirms the
  original parent remains the only indexed verified event.
- Added summary tests for a trust-valid truncated workflow and duplicate valid
  workflow stages.
- Added a top-level API test that signs and verifies an event through `spif`.

## Verification

The initial test-first run failed as expected because `TrustDecision` was not
yet exported from `spif`:

```text
ImportError: cannot import name 'TrustDecision' from 'spif'
```

After implementation:

```text
PYTHONPATH=. .venv/bin/pytest \
  tests/test_governance_profile.py \
  tests/test_governance_chain.py \
  tests/test_clinical_governance_demo.py -q
25 passed in 0.15s

PYTHONPATH=. .venv/bin/python examples/clinical_governance_chain.py
exit 0; six verified events plus unknown_signer and revoked_signer demonstrations

PYTHONPATH=. .venv/bin/pytest -q
687 passed, 21 skipped, 30 warnings in 10.95s

PYTHONPATH=. .venv/bin/python -m compileall -q spif examples tests
exit 0

git diff --check
exit 0
```

The 30 warnings are the existing empty-passphrase mnemonic warnings in
compatibility, keystore, and sidecar tests; this change neither adds nor
suppresses them.

## Self-review

- Confirmed signature verification occurs before authenticated governance
  claims are interpreted for known, non-revoked signers.
- Confirmed duplicate IDs are rejected before the chain parent index changes.
- Confirmed workflow completeness is separate from trust validity.
- Confirmed no `qventus-sim` references remain in `spif-py`.
- Confirmed no governance `now_ms` parameter or caller remains; the only
  remaining `now_ms` variable is unrelated experimental report metadata.
- Confirmed the diff is limited to governance verification, public exports,
  synthetic demo semantics, focused tests, and this required report.
