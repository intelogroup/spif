# Contributing to SPIF

Thanks for taking the time to contribute. This repo is a monorepo with three components — pick the one relevant to your change.

## Repo layout

| Path | Component | Stack |
| :--- | :--- | :--- |
| [`/spif-py`](spif-py/) | Core Python & CLI | Python 3.9+ |
| [`/spif-rust`](spif-rust/) | Rust engine & CLI | Rust (2021) |
| [`/verify`](verify/) | Generated WASM package and sample artifact | Rust/WASM |

## Dev setup

**Python (`spif-py`):**
```bash
cd spif-py
pip install -e ".[dev]"
pytest
```

**Rust (`spif-rust`):**
```bash
cd spif-rust
cargo build --release
cargo test
```

## Making a change

1. Fork and branch off `main`.
2. Keep changes scoped to one component per PR where possible — cross-cutting spec changes (`docs/SPEC.md`) should be discussed in an issue first, since Python, Rust, and wasm all need to stay in sync.
3. Add or update tests for any behavior change. `cargo test` / `pytest` must pass locally before opening a PR.
4. Don't commit generated output (`spif-py/graphify-out/`, `spif-py/results/*.txt`, build artifacts) — these are gitignored.
5. Open a PR against `main`. CI (Rust tests, CodeQL) must pass before merge.

## Requirements for an acceptable PR

- Tests pass locally (`cargo test` / `pytest`) and in CI — a PR without passing checks won't be merged.
- New behavior gets a test; bug fixes get a regression test where practical.
- No unrelated changes bundled in — one logical change per PR.
- No generated/build output committed (see point 4 above).
- Commit messages describe the *why*, not just the *what*.

## Reporting security issues

Do not open a public issue for a security vulnerability — follow the process in [SECURITY.md](SECURITY.md).

## Format spec changes

The wire format is defined in [`docs/SPEC.md`](docs/SPEC.md). Any change there requires updating the Python and Rust implementations in the same PR (or a tracked follow-up) to keep cross-language fidelity — see the interoperability samples described in the [README](README.md).
