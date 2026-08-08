# Benchmarks: v1.0-rc1

This document provides the performance benchmarks of SPIF, reflecting real-world usage and rigorous testing to validate system integrity and performance. Highlights include:

1. **Adversarial Testing**: 4 structural attack classes × 100 mutated docs × 3 seeds = 1,200 mutations, 0% silent failures.
2. **Provenance Reorder**: DAG cycle validation is directly integrated, rejecting cyclic traces.
3. **Tamper Comparison**: Comprehensive data documented for wire overhead.
4. **Performance Honesty**: Clean performance metrics with noted spikes under load.
5. **DAG DoS Resistance**: Validated scaling under load with no stack overflow.
6. **Cross-Language Fidelity**: Deterministic checks pass across various languages.
7. **Agent Chain Integrity**: Robust CHECKSUM layer protects against tampering.
8. **Repo Hygiene**: 548 passed, 25 skipped (full suite, verified 2026-08-06).

This version is foundational for the security architecture and operational robustness of SPIF.