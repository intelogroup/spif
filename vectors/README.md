# SPIF Conformance Vectors

Normative test vectors for the SPIF trust layer (v1.3: SPEC §6.12, §6.13,
§7.7, §7.8, §8.1 — signed revocation statements and the REVOKED trust
status, TSA timestamp anchors, offline cross-document resolution) and
for v1.4 hybrid post-quantum signing (SPEC §7.9, cases 12–15).

## Running

```bash
python build_vectors.py     # regenerate artifacts + manifest for cases 01-11 (deterministic)
python build_pq_vectors.py  # regenerate artifacts + manifest for cases 12-15 (needs the 'pq' extra)
python run_conformance.py   # execute all cases against spif-py
```

The runner prints one line per case — PASS, FAIL (with the mismatched
fields), or BLOCKED (with the reason) — and exits non-zero iff any case
FAILs. Other implementations can execute the same `manifest.json` by
replacing the adapter function in `run_conformance.py`.

## Cases

| #  | Case                          | Expected outcome                                             |
|----|-------------------------------|--------------------------------------------------------------|
| 01 | valid_py                      | VALID                                                        |
| 02 | cross_implementation_rust     | VALID in the Rust reader and vice versa — **BLOCKED** without a Rust toolchain |
| 03 | tampered                      | INVALID (checksum repaired, signature cannot be)             |
| 04 | unsigned                      | UNSIGNED — never VALID                                       |
| 05 | revoked_list                  | REVOKED via an out-of-band revocation-list file              |
| 06 | revoked_embedded              | REVOKED via the embedded REVOCATION chunk                    |
| 07 | forged_revocation             | VALID, with `forged_revocations == 1` flagged                |
| 08 | timestamp_verified            | VALID, timestamp `verified` (pinned TSA key supplied)        |
| 09 | timestamp_unverified_authority| VALID, timestamp `unverified` (no TSA key configured)        |
| 10 | crossdoc_resolved             | VALID, reference `resolved` from the local bundle            |
| 11 | crossdoc_unresolved           | VALID, reference `unresolved` (no bundle)                    |
| 12 | hybrid_valid                  | VALID under strict hybrid verification (both components) — v1.4, adapter `pq_hybrid` |
| 13 | hybrid_tampered_ml_dsa        | INVALID (ML-DSA-65 component flipped, checksum repaired)     |
| 14 | hybrid_tampered_ed25519       | INVALID (ed25519 component flipped, checksum repaired)       |
| 15 | hybrid_ed25519_only_relabelled| INVALID (ed25519-only signature relabelled as hybrid)        |

Cases 12–15 are the **v1.4 hybrid PQ** cases (SPEC §7.9, hybrid
`ed25519+ml-dsa-65`), built by `build_pq_vectors.py` and executed by the
`pq_hybrid` adapter in the runner (spif.trust in the require_pq gate
mode). Without the `pqcrypto` backend they report BLOCKED, never FAIL.
Unlike cases 01–11, the hybrid artifacts are **not byte-identical
across builds**: FIPS 204 hedged signing is randomized and the ML-DSA
test keypair is generated fresh per build. The expected *outcomes* are
deterministic, and outcomes are all the runner asserts.

## Determinism & test keys

`build_vectors.py` derives every key from a fixed, published seed string
and uses fixed timestamps; ed25519 signatures are deterministic, so the
generated files are byte-identical across runs. **The keys are TEST-ONLY
and public by design — never sign a real artifact with them.**
