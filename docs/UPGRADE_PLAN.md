# SPIF v1.3 "World-Ready" Upgrade Plan

**Branch:** `tmp/world-ready-v13` · **Date:** 2026-10-29 · **Status:** planned, implementation in progress

v1.0 shipped the wire format; the v1.2 addendum sketched the trust layer
(revocation, post-quantum signatures, cross-document references) as
*informational*. v1.3 turns the trust layer into decided, implemented,
conformance-tested behavior: a revocation model with a distinct REVOKED
trust status, an optional timestamp anchor, an offline cross-document
resolution policy, and a public conformance kit any implementation can run.
No wire-format version bump: every addition is a new chunk type in the
reserved range or a new verification behavior, and degrades gracefully on
older readers (unknown chunks are skipped per §3.1).

Baseline at plan time (verified 2026-10-29): Python core suite
**671 passed / 21 skipped / 0 failed** (excluding
`tests/test_gemini_adapter.py` — missing optional `google` extra — and
`tests/test_rust_sidecar.py` — missing compiled Rust binary; both fail
environmentally, not in the sign/verify core).

---

## Settled design decisions (implement as written; do not redesign)

### D1 — Revocation model

- Signer-issued, **signed** revocation statements. A statement binds:
  `artifact_digest`, the revoking signer's public key, `issued_ms`
  (issued-at), and a `reason` code (`compromised` | `retracted` |
  `superseded` | `other`).
- `artifact_digest` = SHA-256 hex of the artifact's **signing body** (all
  bytes before the first SIGNATURE/MULTISIG chunk; for unsigned artifacts,
  all bytes before CHECKSUM). This is the only digest that stays stable
  when post-signature chunks (revocation, timestamp) are attached, and it
  is exactly the byte range the artifact's signature covers.
- Only a key that signed (or co-signed) the artifact can revoke it. A
  statement whose key is not one of the artifact's signers, or whose
  signature does not verify, is a **forged revocation**: it is ignored for
  trust purposes, counted, and flagged in the verification report. The
  artifact keeps its own status.
- The verifier reports a distinct trust status: an artifact whose
  signature is cryptographically valid but which carries (embedded chunk)
  or matches (supplied revocation list) a valid revocation reports
  **REVOKED** — never VALID, and never conflated with INVALID (bad
  signature).
- Distribution is out-of-band: revocations travel in a revocation-list
  file the verifier is given, and/or embedded in the artifact's
  REVOCATION chunk. Verification stays fully offline.

### D2 — Timestamp model

- Optional **TIMESTAMP anchor chunk**: an opaque timestamp token plus an
  authority identifier.
- Absence of a token never invalidates an artifact.
- When a token is present and the verifier is configured with the TSA's
  pinned key, the token is checked and the report marks the timestamp
  **verified**. When present but no TSA key is configured, the report
  marks it **unverified** — not a failure.
- The token is a TSA countersignature (ed25519) over
  `(artifact_digest, time_ms)`, so the whole model is testable with a
  locally generated TSA test key. No network RFC 3161 client in this
  rung.

### D3 — Cross-document policy

- Verification **never** performs network access.
- Cross-document NodeRefs (`spif:sha256:<content_id>#<node_id>`, §8.1)
  resolve only from a caller-supplied local bundle of artifacts provided
  alongside the artifact under verification.
- An unresolvable reference yields an explicit **UNRESOLVED** status for
  that reference in the verification report — never a silent pass, never
  a hard failure of the artifact's own signature.

### D4 — Conformance

- A `vectors/` directory at repo root: numbered cases (artifact bytes or
  a builder recipe, plus expected verify outcome including trust
  status), covering at minimum: valid (py-produced), valid
  (rust-produced, if buildable), tampered, unsigned, revoked,
  revoked-with-forged-revocation, timestamped (verified and
  unverified-authority variants), cross-doc resolved, cross-doc
  unresolved.
- A runner script any implementation can execute that prints per-case
  PASS/FAIL against the expected outcomes.

---

## Deviations discovered at plan time (recorded, not hidden)

1. **Chunk ID collision — REVOCATION is 0x0B, not 0x0A.** The spec's
   registry (§3.1) and §6.12 reserve `0x0A` for REVOCATION, but the
   shipped Python implementation has used `0x0A` for the **ROLES** chunk
   since v1.1 (`spif/format.py: CHUNK_ROLES = 0x0A`), the reader enforces
   ROLES placement relative to the auth chunks, and governance tests
   exercise it. Reassigning 0x0A would corrupt every ROLES-bearing
   document and break the baseline suite. v1.3 therefore assigns
   **REVOCATION = 0x0B** and **TIMESTAMP = 0x0C** — both inside the
   spec's reserved `0x0B`–`0x0F` range — and the v1.3 spec text corrects
   the registry (0x0A documented as ROLES, as implemented). The D1 model
   is implemented exactly as decided; only the byte moved.
2. **Cross-doc refs currently fail to parse at all.** The Python
   reader's payload-DAG validator raises `SPIFFormatError` on a
   `spif:`-prefixed ref (dangling local reference), contradicting §8.1's
   "treat as opaque" rule. Rung 4 includes fixing the validator to treat
   cross-document refs as external.
3. **No Rust toolchain in the build sandbox** (`cargo`/`rustc` absent).
   Rungs 2–4 are implemented fully in Python; Rust parity is a recorded
   gap (see per-rung status), and the conformance kit's
   cross-implementation case is its one unexecuted case here. Nothing
   about Rust support is claimed that was not run.

---

## Rungs

### Rung 1 — Version story
- Consolidate the v1.2 addendum + D1/D2/D3 into `docs/SPEC.md` as the
  v1.3 addendum, following the v1.2 style (marked sections, §11
  negotiation row, Appendix B entry): registry correction (0x0A ROLES,
  0x0B REVOCATION, 0x0C TIMESTAMP), §6.12 revised to the signed-statement
  model, new §6.13 TIMESTAMP, new §7.7 revocation verification, new
  §7.8 timestamp anchoring, §8.1 extended with bundle resolution.
- README badge: `spec v0.2` → `spec v1.3`.
- Package versions aligned to **1.3.0**: `spif-py/pyproject.toml`,
  `spif-rust/Cargo.toml` (+ matching `Cargo.lock` entry, hand-synced
  since cargo is unavailable).
- CHANGELOG: new `[1.3.0]` section.

### Rung 2 — Revocation (Python)
- `spif/format.py`: `CHUNK_REVOCATION = 0x0B`.
- `spif/types.py`: `RevocationStatement` dataclass (CBOR dict +
  JSON dict forms).
- New `spif/trust.py`: statement creation/signing, statement
  verification, `artifact_digest()`, embedded-chunk attach/extract
  helpers, revocation-list file save/load, `verify_artifact()` →
  `VerificationReport` with `trust_status ∈ {VALID, INVALID, REVOKED,
  UNSIGNED, UNVERIFIABLE}`, `forged_revocations` count.
- Reader: parse REVOCATION chunk into `SPIFDocument.revocations`.
  Writer: emit it (after MULTISIG, before CHECKSUM; never compressed).
- Tests: valid revocation → REVOKED; forged revocation (wrong key / bad
  signature) → artifact keeps VALID, forgery flagged; revocation for a
  different artifact → no effect; unsigned artifact → UNSIGNED, never
  REVOKED-as-valid.
- Rust: **gap** (no toolchain) — recorded here and in the final report.

### Rung 3 — Timestamp anchor (Python)
- `CHUNK_TIMESTAMP = 0x0C`; `TimestampAnchor` dataclass; TSA
  countersignature create/verify in `spif/trust.py`; attach/extract
  helpers; reader parses into `SPIFDocument.timestamp_anchor`; writer
  emits it after REVOCATION.
- `verify_artifact(..., tsa_keys={authority: pubkey_b64})` →
  `timestamp_status ∈ {verified, unverified, absent}`; absent/unverified
  never changes `trust_status`.
- Tests: verified with pinned test-TSA key; unverified without a
  configured key; absent; token over a different digest → unverified
  (reported, not a failure).
- Rust: **gap** (same as rung 2).

### Rung 4 — Cross-document bundle resolution (Python)
- Fix `_validate_payload_dag` to treat `spif:`-prefixed refs as
  external (excluded from the local graph and the dangling-ref check).
- `verify_artifact(..., bundle=[artifact_bytes, ...])`: each cross-doc
  ref resolves iff the bundle contains an artifact whose `content_id()`
  matches and which contains the named node. Report lists every ref
  with status `local` | `resolved` | `unresolved`. No network, ever.
- Tests: resolved from bundle; unresolved with empty/absent bundle;
  bundle artifact with wrong content_id → unresolved; local refs
  unaffected.
- Rust: **gap** (same as rung 2).

### Rung 5 — Conformance kit
- `vectors/`: `manifest.json` (numbered cases + expected outcomes),
  deterministic builder `build_vectors.py` (fixed-seed ed25519 test
  keys — ed25519 signatures are deterministic, so artifacts are
  reproducible), generated artifacts + aux files (revocation list, TSA
  public key), and `run_conformance.py`, a runner that executes every
  case against spif-py and prints per-case PASS/FAIL.
- Cases: 01 valid (py), 02 valid (rust-produced / cross-implementation —
  **BLOCKED here, no Rust toolchain; the kit's one unexecuted case**),
  03 tampered, 04 unsigned, 05 revoked (list-supplied), 06 revoked
  (embedded), 07 forged revocation, 08 timestamp verified, 09 timestamp
  unverified authority, 10 cross-doc resolved, 11 cross-doc unresolved.
- A pytest wrapper (`spif-py/tests/test_v13_conformance.py`) runs the
  same manifest so CI sees the kit too.

### Rung 6 — PQ signatures: check only
- Finding (verified at plan time): the v1.2 hybrid `ml-dsa-65` path is
  **spec-only**. Evidence: no `ml-dsa`/`ml_dsa`/`dilithium` code in
  `spif-py/spif/` or `spif-rust/src/` (the reader rejects non-ed25519
  algorithms as unsupported), and no PQ dependency in
  `spif-py/pyproject.toml` or `spif-rust/Cargo.toml`.
- Per the upgrade scope: do **not** implement PQ in v1.3. Recorded as
  the next rung (v1.4 candidate) — one-line reason: PQ support needs a
  vetted ML-DSA implementation choice (pure-Python vs binding) and its
  own conformance vectors; bolting it onto the trust-layer release
  would ship the highest-risk cryptography with the least review.

---

## Test gates (all must actually run)

- Existing Python core suite: ≥ baseline (671 passed, 0 failed in core
  scope) after every rung.
- New per-rung suites under `spif-py/tests/test_v13_*.py`.
- Conformance runner: every executable case PASS; case 02 reported
  BLOCKED with the toolchain reason.
- Rust: `cargo test` not run — toolchain absent (recorded, not faked).

## Out of scope

Pushing, GitHub releases, version tags, network timestamp clients
(RFC 3161), PQ implementation, changes to the v1.0 wire contract.

---

## Rung 6 finding (recorded 2026-10-29, check-only as scoped)

The v1.2 hybrid `ml-dsa-65` path is **spec-only** in both implementations:

- `grep -rn "ml-dsa|ml_dsa|MlDsa|dilithium" spif-py/spif/*.py spif-rust/src/*.rs`
  → **0 hits**.
- No PQ dependency (`oqs`, `dilithium`, `pqcrypto`, `liboqs`) in
  `spif-py/pyproject.toml` or `spif-rust/Cargo.toml` → **0 hits**.
- `spif-py/spif/reader.py:813` hard-gates verification: any non-`ed25519`
  algorithm raises "only ed25519 is supported".
- `docs/SPEC.md` mentions `ml-dsa-65` 7 times — specification text only.

No conformance case was added (there is nothing to execute), and per the
upgrade scope PQ was **not** implemented in v1.3. It stands as the next
rung (v1.4 candidate): it needs a vetted ML-DSA implementation choice
(pure-Python vs binding) and its own conformance vectors; bolting it onto
the trust-layer release would ship the highest-risk cryptography with the
least review.

## Implementation status (as built on this branch)

| Rung | Status |
|------|--------|
| 0 Plan | done — this document |
| 1 Version story | done — SPEC v1.3 addendum, badge, versions 1.3.0, CHANGELOG |
| 2 Revocation (py) | done — chunk 0x0B, `spif/trust.py`, REVOKED status; **Rust: gap (no toolchain)** |
| 3 Timestamp (py) | done — chunk 0x0C, countersignature verify; **Rust: gap** |
| 4 Cross-doc (py) | done — bundle resolution, UNRESOLVED, reader DAG fix; **Rust: gap** |
| 5 Conformance kit | done — 10 PASS / 0 FAIL / 1 BLOCKED (case 02, Rust cross-implementation) |
| 6 PQ check | done — spec-only, recorded above; not implemented |

**Post-plan update (2026-10-29):** the per-rung "Rust: gap (no toolchain)" entries above
are the historical record of the upgrade run. Rust parity was completed afterwards:
the Rust engine implements the full v1.3 trust layer (revocation, timestamp, bundle
resolution), aligned with the Python hardening (statement cap, candidate dedupe), and
the conformance kit now passes 11 PASS / 0 FAIL / 0 BLOCKED.

**v1.4 rung (2026-10-29, branch `tmp/v14-pq-rung`):** the PQ check of rung 6 became
the v1.4 rung. SPEC §7.9 addendum (encoding decided in-spec: both public keys embedded
in `signer`, +5,925 B/artifact measured; gate modes classical / require_pq with PQ-only
entries "invisible, not invalid"; hybrid key management and hybrid-signed revocation;
PQ-only signing registered but not implemented). Python: `spif.pq_hybrid` promoted from
the Phase D prototype to a supported module, integrated with the reader gate, the
trust layer, the keystore, and `spif verify --require-pq`; `pqcrypto` is an optional
extra. Conformance kit grows to 15 cases (12–15 promoted from the spike; 15/15 PASS).
Rust: hybrid *verify* parity landed via RustCrypto `ml-dsa` 0.1.1 behind the default-on
`pq` feature (cargo 102 passed / 2 ignored); Rust hybrid *signing* is a recorded gap —
the crate cannot import the FIPS 204 expanded secret keys SPIF keystores hold.
Performance re-checked on the integrated path: no regression vs the spike
(sign 15.20 ms, strict verify 0.55 ms; medians of 50). Versions aligned to 1.4.0.
Built and committed locally only — merge/release are a separate decision, as v1.3 was.
