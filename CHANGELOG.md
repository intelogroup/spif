# Changelog

All notable changes to SPIF are documented here. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

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
