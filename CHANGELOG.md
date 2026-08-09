# Changelog

All notable changes to SPIF are documented here. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

## [v1.0]

- First stable release. Signed, published artifacts: Python sdist/wheel and the `spif-sidecar` Rust binary, each with a cosign keyless signature (`.sig`/`.pem`).
- Docs rewritten for implementer/adopter audience: removed internal dev-log docs (`CLAUDE.md`, `todo.md`, `open_core_split.md`, `SHOW_HN_DRAFT.md`, `RELEASE.md`, `RELEASE_v1.0.md`, `ROADMAP.md`, `benmarks.md`, `THREAT_MODEL.md`) and `CDDL.md` (schema had drifted from the actual wire format); accuracy-fixed `SPEC.md` and `spif/CRYPTO_AUDIT.md`.
- Added `CONTRIBUTING.md`, `.github/dependabot.yml`, and a signed-release GitHub Actions workflow (`release.yml`).
- CI hardening: least-privilege `permissions:` blocks on all workflows, pinned GitHub Actions and pip dependencies, removed a `curl | sh` installer.
- `spif-rust/Cargo.lock` is now tracked (was gitignored, which broke `cargo build --locked` in release CI).

## [v1.0-rc2]

- Second release candidate. See `spif/SPEC.md` for the current wire format and `spif/CRYPTO_AUDIT.md` for the security posture at this tag.

## [v1.0-rc1]

- First release candidate.

[Unreleased]: https://github.com/intelogroup/spif/compare/v1.0...HEAD
[v1.0]: https://github.com/intelogroup/spif/releases/tag/v1.0
[v1.0-rc2]: https://github.com/intelogroup/spif/compare/v1.0-rc1...v1.0-rc2
[v1.0-rc1]: https://github.com/intelogroup/spif/releases/tag/v1.0-rc1
