# Changelog

All notable changes to SPIF are documented here. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

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
