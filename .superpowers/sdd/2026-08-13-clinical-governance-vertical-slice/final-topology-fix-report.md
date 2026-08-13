# Final Topology Fix Report: Clinical Governance Vertical Slice

## Changes

- `verify_event()` verifies a registered signer's raw signature before it
  reports revocation. A tampered artifact that claims a revoked registered
  signer returns `invalid_signature`; a valid artifact returns
  `revoked_signer`; an unregistered signer remains `unknown_signer`.
- `SPIFKeyStore.verify()` now performs the cryptographic check before raising
  the new `SPIFRevokedSignerError`, so callers can make that distinction.
- `verify_chain()` now enforces exactly one `Decision` root with no parents,
  requires parents for every other type, rejects repeated parent IDs, requires
  verified parents, and requires every parent event type to precede its child.
  Stable topology failures are `invalid_root`, `duplicate_parent`,
  `missing_parent`, and `parent_order`.
- `summarize_chain()` reports `complete` only for trust-valid results with
  exactly one valid result per required event type.
- The approved plan no longer advertises `now_ms` parameters.

## Regression coverage

- Added the exact revoked-and-tampered signer regression.
- Added root, second-root, parent-uniqueness, parent-order, disconnected
  six-event, and reverse-order six-event chain regressions.
- Added a summary regression where all event types are represented but an
  `invalid_root` result prevents completion and validity.

## Verification

The new focused regressions first failed against the pre-fix behavior: 8
failures covering signer ordering, topology enforcement, and summary
completeness. After implementation:

```text
./.venv/bin/python -m pytest -q tests/test_governance_chain.py tests/test_clinical_governance_demo.py
25 passed in 0.17s

./.venv/bin/python -m pytest tests/ -q --ignore=tests/test_fuzz.py --ignore=tests/test_mcp_tools.py --ignore=tests/test_gemini_adapter.py
637 passed, 21 skipped, 30 warnings in 9.09s

./.venv/bin/python examples/clinical_governance_chain.py
exit 0; six verified events plus unknown_signer and revoked_signer demonstrations

./.venv/bin/python -m compileall -q spif examples tests
exit 0

git diff --check
exit 0
```

The 30 warnings are existing empty-passphrase mnemonic warnings from
compatibility, keystore, and sidecar tests; this change does not add them.
