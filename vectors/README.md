# SPIF v1.3 Conformance Vectors

Normative test vectors for the SPIF v1.3 trust layer (SPEC §6.12, §6.13,
§7.7, §7.8, §8.1): signed revocation statements and the REVOKED trust
status, TSA timestamp anchors, and offline cross-document resolution.

## Running

```bash
python build_vectors.py     # regenerate artifacts + manifest (deterministic)
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

## Determinism & test keys

`build_vectors.py` derives every key from a fixed, published seed string
and uses fixed timestamps; ed25519 signatures are deterministic, so the
generated files are byte-identical across runs. **The keys are TEST-ONLY
and public by design — never sign a real artifact with them.**
