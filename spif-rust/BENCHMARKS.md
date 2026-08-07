# SPIF Rust — v1.0-rc1 Benchmark Results

Honest state as of this release. Numbers below were actually run, not estimated.

## PASS

- **Crypto conformance**: 5/5 RFC 8032 ed25519 test vectors, 150/150 Wycheproof ed25519 vectors, ~54,980 verify/sec.
- **Tamper detection** (bit-flip + truncation sweep against a signed fixture, `SPIFReader::strict()`): 15,664/15,664 single-bit mutations rejected (0 silent accepts, 0 panics); 1,957/1,957 truncation points rejected cleanly (0 panics).
- **Fuzzing**: AFL++ 866M+ executions against `SPIFReader::new()` (unsigned-tolerant path), 0 crashes. libFuzzer: 4.6M executions against the same path, 0 crashes; 5.4M executions against `SPIFReader::strict()` (signature-required path), 0 crashes.
- **cargo audit**: 0 outstanding advisories (2 HIGH-severity RustSec advisories fixed via dependency upgrade during this release cycle).
- **cargo test**: 25 passed, 0 failed, 2 ignored.

## WEAK — known gaps, not blockers for rc1

- **OpenSSF Scorecard**: 1.5/10 aggregate. No branch protection, no pinned dependencies, no token-permission hardening yet. Targeted for v1.0.
- **OSS-Fuzz**: submission scaffold (`project.yaml`/`Dockerfile`/`build.sh`) built and verified to compile locally, but not yet submitted upstream to `google/oss-fuzz`. Targeted for v1.0.

## Not verified

- Rust/x86 build has not been independently verified by a third party — didn't fake this, saying so plainly.

## Methodology notes

- Fuzz targets and tamper-detection tooling live in `fuzz/`, `fuzz-libfuzzer/`, and `src/bin/{crypto_conformance,tamper_detect}.rs`.
- "0 crashes" means no non-self-inflicted crash artifacts after standalone reproduction; any AFL `sig:09` entries encountered during development were verified as artifacts of manual process intervention, not target bugs, before being discarded.
