# Changelog

All notable changes to SPIF are documented here. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [1.4.3] - 2026-11-21

A hardening release. No wire-format or spec change — the spec remains
v1.4, and artifacts written by 1.4.2 verify identically. This release
closes the last open adversarial-loop card, SPIF-REPLAY-EVICTION-001,
left open by 1.4.2 pending a semantics ruling.

### Fixed
- **ReplayGuard eviction is now observable** (#119,
  SPIF-REPLAY-EVICTION-001): the guard's FIFO cap silently weakened
  replay protection — once the seen set turned over, an evicted
  (signer, nonce) pair read as fresh and a replayed document was
  accepted with no signal to the consumer. Ruling (Jim, 2026-11-21):
  keep the FIFO eviction and add an observable counter. Eviction
  behavior is unchanged; every eviction now increments the public
  read-only `ReplayGuard.evictions` counter, and the module documents
  that replay protection is best-effort past the cap so consumers can
  alert on the counter. The pinned FIFO eviction test now asserts the
  counter as well, and a new permanent suite
  (tests/test_replay_eviction.py) covers the counter contract. The
  guard is Python-only — the Rust crate has no ReplayGuard — so there
  is no Rust change in this release beyond the version bump.

## [1.4.2] - 2026-11-20

A hardening release. No wire-format or spec change — the spec remains
v1.4, and artifacts written by 1.4.1 verify identically. Every change
comes from the adversarial-loop fix rounds merged since 1.4.1
(PRs #115–#117).

### Fixed
- **Round-3 validation, 6 cards** (#117): non-finite numbers are
  rejected in Distribution, SEMANTIC and PROVENANCE fields
  (SPIF-NONFINITE-NUMERIC-001); negative values are rejected for the
  SPEC uint64 fields across TASK, PROVENANCE, REVOCATION and
  TIMESTAMP chunks (SPIF-NEGATIVE-INT-001); normalized ALTS weights
  must lie in [0,1] per weight in both readers and writers
  (SPIF-ALTS-NEGATIVE-WEIGHT-001); SEMANTIC covariance must be
  dim x dim for dim = len(embedding), including dim 0
  (SPIF-SEMANTIC-COVARIANCE-SHAPE-001); DELTA changes entries must be
  dicts (SPIF-DELTA-CHANGES-SHAPE-001); and a payload reference is
  cross-document only when its id is not a local node id, so cycles
  through local `spif:`-prefixed nodes are rejected by the payload
  DAG validator (SPIF-PAYLOAD-CROSSDOC-CYCLE-001). The Python fixes
  carry 102 new permanent regression tests; the Rust mirror passed
  CI (`cargo test --release`) on the PR.
- **Fix-all round** (#115): ReplayGuard and keystore input discipline
  — keystore-wide id-type and entry-shape validation.
- **ALTS non-finite weights** (#116): ALTS weights must be finite in
  both readers and writers (SPIF-ALTS-NONFINITE-WEIGHT-001), with
  permanent regressions in both legs.

### Open
- SPIF-REPLAY-EVICTION-001 remains open, pending a semantics ruling
  (fail-closed vs bounded growth vs observable counter). It is
  deliberately untouched by this release.

## [1.4.1] - 2026-11-15

A hardening release. No wire-format or spec change — the spec remains
v1.4, and artifacts written by 1.4.0 verify identically. Every change
comes from the adversarial-loop fix rounds merged since 1.4.0
(PRs #108–#113).

### Fixed
- **CLI fails closed on bad inputs and outputs** (#108, #109):
  revocation files that are missing or wrong-shaped are rejected
  instead of failing open, and unreadable input files or unwritable
  output paths produce clean errors instead of crashes.
  `SPIFReader.read()` now raises `SPIFError` for unreadable paths.
- **Stream discipline** (#110): the Python stream reader decodes
  chunks at the document reader's strict CBOR bar, runs a sequence
  state machine that refuses replayed or misplaced chunks, and binds
  emitted partial text to the final payload before emitting
  `verified`.
- **Trust extractors decode strictly** (#111):
  `extract_revocations` and `extract_timestamp` decode through the
  strict path — ambiguous CBOR (duplicate keys, trailing bytes) and
  duplicate chunks yield no extracted values instead of silently
  resolved ones.
- **Rust stream-reader parity** (#112): the Rust stream reader gained
  strict typed partial parsing, per-node strictly increasing sequence
  numbers, and partial/payload binding at CHECKSUM — `Verified` fires
  only when the emitted partials reconcile with the decoded payload,
  matching the Python reader.

### Changed
- **ReplayGuard consumes nonces per signer** (#112): replay identity
  is every attested signer's `(signer, nonce)` pair, so a stripped
  subset of a seen multisig envelope is rejected as a replay in both
  presentation orders. This is a semantic decision, recorded as such:
  a nonce is spent per signer, in any set composition — re-presenting
  a signer's spent nonce inside a different signer set is a replay,
  not a fresh presentation. The signerset semantics are pinned by a
  permanent test (#113).

## [1.4.0] - 2026-10-29

The post-quantum release. Spec v1.4 (docs/SPEC.md §7.9) adds hybrid
`ed25519+ml-dsa-65` signatures on top of the v1.3 trust layer, built on
the Phase D spike's ADOPT-WITH-CONDITIONS verdict; all six spike
conditions are discharged here. No wire-format version bump; classical
artifacts and verifiers are unaffected.

### Added
- **Hybrid PQ signing and verification** (SPEC §7.9): algorithm
  `ed25519+ml-dsa-65`, signature = ed25519 (64 B) ‖ ML-DSA-65 (3,309 B)
  over the unchanged signing body.
- **Signer-encoding decision (§7.9.1)**: both public keys are embedded
  in the `signer` field — base64(ed25519 32 B ‖ ML-DSA-65 1,952 B) —
  preserving self-contained offline verification. Measured cost:
  **+5,925 bytes per hybrid artifact** vs ed25519 (reproduced by
  `benchmarks/pq_hybrid_bench.py`). The key-lookup alternative was
  rejected because it costs the offline property; named signer ids
  remain legal via verifier-provisioned `known_keys`.
- **Reader gate modes (§7.9.2)**: classical (default — a hybrid entry
  verifies on its ed25519 component; a PQ-only entry is *invisible,
  not invalid*: UNVERIFIABLE, never VALID, never INVALID) and
  `require_pq` (both components must verify; upgradable per call in
  `spif verify --require-pq`). A wrong-length hybrid signature is
  INVALID in both modes. `require_pq` without an ML-DSA backend
  reports UNVERIFIABLE — it never silently degrades to classical.
- **Key management (§7.9.3)**: one signer identity over both key
  components; whole-identity revocation; rotation records MUST carry
  dual-component proofs from old and new keypairs (verified by
  `verify_hybrid_rotation`). ML-DSA secret keys are stored as the
  4,032-byte FIPS 204 encoding; v1.4 defines no mnemonic derivation
  for them. Keystore stores hybrid public entries (`.hyb` files) with
  strict both-component verification.
- **Hybrid revocation (§7.9.4)**: revocation statements are signed
  with the signer's own algorithm — a hybrid signer MUST sign
  hybridly; an ed25519-only statement from a hybrid signer is a
  forgery (counted, applies nothing). `create_revocation_hybrid` in
  the Python trust layer.
- **Optional backend**: `pqcrypto` is an optional dependency
  (`pip install "spif[pq]"`). Importing `spif` without it works
  classically and reports the PQ backend unavailable — never crashes.
  `dilithium-py` is a dev-only independent cross-check; interop is
  tested in both directions through the integrated path.
- **Conformance kit grows to 15 cases**: hybrid cases 12–15 promoted
  from the spike (`vectors/build_pq_vectors.py`, `pq_hybrid` runner
  adapter executing through the trust layer in require_pq mode;
  BLOCKED, never FAIL, without the backend). Runner: 15 passed,
  0 failed, 0 blocked.
- **Rust verify parity**: `spif-rust` verifies hybrid artifacts and
  hybrid revocation statements with the same gate semantics, using
  RustCrypto `ml-dsa` 0.1.1 behind the default-on `pq` cargo feature
  (a `--no-default-features` build degrades exactly like Python
  without the backend). Proof: `spif-rust/tests/pq_hybrid.rs` runs
  conformance artifacts 12–15 and Python-produced revocation fixtures
  through the Rust implementation. Cargo suite: 102 passed,
  0 failed, 2 ignored (was 95/2).
- **Performance** (medians of 50, `benchmarks/pq_hybrid_results.md`):
  hybrid sign 15.20 ms, strict verify 0.55 ms (reader gate) /
  0.64 ms (trust layer), classical-gate verify of a hybrid artifact
  0.23 ms — no regression vs the spike prototype (14.73 / 0.53 ms).

### Not implemented (recorded gaps)
- **PQ-only signing** (`ml-dsa-65` alone) stays spec-only in v1.4:
  the algorithm is registered and verifiers handle it under the gate;
  no writer ships (§7.9.5).
- **Rust hybrid signing**: `ml-dsa` 0.1.1 derives signing keys from a
  32-byte seed and exposes no import for the FIPS 204 expanded
  secret-key encoding (4,032 B) that SPIF hybrid keystores hold
  (`ExpandedSigningKey::from_seed` is the only constructor path), so
  the crate cannot consume existing SPIF hybrid keys. Rust verifies;
  Python signs. Revisit when the crate gains expanded-key import.

## [1.3.0] - 2026-10-29

The "world-ready" trust-layer release. Spec v1.3 (docs/SPEC.md §6.12–§6.13, §7.7–§7.8,
§8.1); plan in docs/UPGRADE_PLAN.md. No wire-format version bump.

### Added
- **Signed revocation statements** (REVOCATION chunk `0x0B`): a signer can retract a
  specific artifact with an ed25519-signed, digest-bound statement (reason codes:
  compromised / retracted / superseded / other). `spif.trust.verify_artifact()` reports a
  distinct **REVOKED** trust status — never VALID, never conflated with INVALID. Forged
  statements (non-signer key or bad signature) are ignored for trust and flagged in the
  report. Statements distribute out-of-band via revocation-list files and/or the embedded
  chunk; verification stays offline.
- **Timestamp anchor** (TIMESTAMP chunk `0x0C`): optional TSA ed25519 countersignature
  over (artifact digest, time). Reported as verified / unverified / absent; absence never
  invalidates an artifact.
- **Cross-document resolution policy**: `spif:` NodeRefs resolve only from a
  caller-supplied local bundle — never the network — with explicit per-reference
  resolved / unresolved reporting.
- **Conformance kit** (`vectors/`): numbered deterministic vectors, a builder, and a
  runner any implementation can execute.

### Changed
- **Chunk registry corrected**: `0x0A` is ROLES, as the implementations have shipped
  since v1.1. Earlier spec drafts reserved `0x0A` for an unsigned key-revocation record
  design that was never implemented; v1.3 supersedes it (see SPEC §3.1 registry note).
- Cross-document (`spif:`) NodeRefs no longer fail payload-DAG validation as dangling
  local references; they are treated as external, per SPEC §8.1.
- Specification clarifications: SPEC §7.7 now states explicitly that a revocation
  statement's `issued_ms` is informational and MUST NOT gate applicability; SPEC §8.1
  pins bundle resolution as content-identity only (a trust-aware resolution mode is
  out of scope for v1.3).
- Implementation package versions aligned to 1.3.0 (Python and Rust).

### Notes
- Post-quantum / hybrid signatures (SPEC §7.5) remain **spec-only** in both
  implementations; implementing ML-DSA-65 is the next rung (docs/UPGRADE_PLAN.md, rung 6).
- Both implementations carry the full v1.3 trust layer: the Rust engine implements
  revocation, timestamp anchoring, and bundle resolution at parity with Python, and
  the conformance kit passes 11 PASS / 0 FAIL / 0 BLOCKED, including the
  cross-implementation case.
- Test fix: the conformance-kit pytest wrapper no longer asserts the Rust
  cross-implementation case is BLOCKED (that was true only before the Rust trust
  layer landed); it now requires a genuine PASS when the Rust binary is available,
  or an explicit BLOCKED with the toolchain reason.

## [Unreleased]

### Fixed
- `SPIFKeyStore.verify()` now rejects non-ed25519-labeled signatures, matching `SPIFReader.strict()` — closed an asymmetric-trust gap where a mislabeled signature could pass keystore verification while failing strict reader verification.
- `rotate_key()` now requires a counter-signature from the new key (`new_key_proof`); added `verify_rotation()` to check both signatures against a tamper-bound payload. Closes a gap where a rotation record could name an attacker-controlled successor with no proof of consent.
- `nan` alternative weights are now rejected explicitly (writer and reader) instead of silently bypassing the `normalized=True` sum check (`abs(total - 1.0) > 0.01` is always `False` for `nan`).
- `SPIFStreamReader` now enforces per-`node_id` `seq` monotonicity on `PARTIAL_TEXT` chunks, rejecting out-of-order or duplicate sequence numbers.
- `SPIFReader.decode()` now rejects non-bytes-like input with a clean `SPIFMagicError` instead of leaking an unhandled `AttributeError`.
- Payload node count is now capped (`MAX_PAYLOAD_NODES = 20_000`) on decode.
- Oversized chunk payloads (> 4 GiB) now raise `SPIFFormatError` on encode instead of a raw `struct.error`.

## [v1.0]

- First stable release. Signed, published artifacts: Python sdist/wheel and the `spif-sidecar` Rust binary, each with a cosign keyless signature (`.sig`/`.pem`).
- Docs rewritten for implementer/adopter audience: removed internal dev-log docs (`CLAUDE.md`, `todo.md`, `open_core_split.md`, `SHOW_HN_DRAFT.md`, `RELEASE.md`, `RELEASE_v1.0.md`, `ROADMAP.md`, `benmarks.md`, `THREAT_MODEL.md`) and `CDDL.md` (schema had drifted from the actual wire format); accuracy-fixed `docs/SPEC.md` and `docs/CRYPTO_AUDIT.md`.
- Added `CONTRIBUTING.md`, `.github/dependabot.yml`, and a signed-release GitHub Actions workflow (`release.yml`).
- CI hardening: least-privilege `permissions:` blocks on all workflows, pinned GitHub Actions and pip dependencies, removed a `curl | sh` installer.
- `spif-rust/Cargo.lock` is now tracked (was gitignored, which broke `cargo build --locked` in release CI).

## [v1.0-rc2]

- Second release candidate. See `docs/SPEC.md` for the current wire format and `docs/CRYPTO_AUDIT.md` for the security posture at this tag.

## [v1.0-rc1]

- First release candidate.

[Unreleased]: https://github.com/intelogroup/spif/compare/v1.0...HEAD
[v1.0]: https://github.com/intelogroup/spif/releases/tag/v1.0
[v1.0-rc2]: https://github.com/intelogroup/spif/compare/v1.0-rc1...v1.0-rc2
[v1.0-rc1]: https://github.com/intelogroup/spif/releases/tag/v1.0-rc1
