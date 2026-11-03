# SPIF Conformance Vectors

Normative test vectors for the SPIF trust layer (v1.3: SPEC §6.12, §6.13,
§7.7, §7.8, §8.1 — signed revocation statements and the REVOKED trust
status, TSA timestamp anchors, offline cross-document resolution) and
for v1.4 hybrid post-quantum signing (SPEC §7.9, cases 12–15), and
the negative corpus (cases 16–23): documents that must NOT verify as
plain VALID, each pinning one rejection rule (SPEC §4.1 canonical /
ambiguity rules and the §7.9.2 gate table).

## Running

```bash
python build_vectors.py          # regenerate artifacts + manifest for cases 01-11 (deterministic)
python build_pq_vectors.py       # regenerate artifacts + manifest for cases 12-15 (needs the 'pq' extra)
python build_negative_vectors.py # regenerate artifacts + manifest for cases 16-23 (case 23 needs the 'pq' extra at build time)
python run_conformance.py        # execute all cases against spif-py
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
| 16 | neg_duplicate_signer_key      | INVALID (duplicate `signer` key, victim last — decoder-dependent attribution) |
| 17 | neg_duplicate_signature_key   | INVALID (duplicate `signature` key, garbage first)           |
| 18 | neg_indefinite_signature_map  | INVALID (indefinite-length SIGNATURE map in a signed document) |
| 19 | neg_longform_signature_header | INVALID (non-minimal 0xB8 map header in a signed document)   |
| 20 | neg_trailing_bytes_after_checksum | INVALID (bytes after the terminal CHECKSUM chunk, §12.4) |
| 21 | neg_duplicate_key_provenance  | INVALID (duplicate key in a non-signature chunk)             |
| 22 | neg_hybrid_malformed_length_classical | INVALID (case 15's artifact under the classical gate — §7.9.2: malformed in BOTH modes) |
| 23 | neg_pq_only_classical_unverifiable | UNVERIFIABLE (genuine ML-DSA-65-only signature, classical reader — invisible, not invalid) |

Cases 16–23 are the **negative corpus**, built by
`build_negative_vectors.py` and seeded from the adversarial loop's
preserved probes (SPIF-NONCANONICAL-ACCEPT-001). Cases 16–21 mutate
case 01's signed artifact — the SIGNATURE chunk lies outside the
signing body and the CHECKSUM is recomputable, so anyone holding a
valid envelope can produce them. Case 23's artifact shares the PQ
cases' determinism caveat (fresh ML-DSA keypair per build; the
expected outcome is deterministic), but the case itself executes
through the classical adapter and needs no backend at run time.

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
