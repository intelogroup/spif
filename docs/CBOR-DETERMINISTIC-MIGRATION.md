# Canonical CBOR migration: length-first → IETF deterministic (wire 0x03)

Decision (Jim, 2026-11-07): SPIF's canonical CBOR form converges to the
IETF deterministic serialization defined by draft-ietf-cbor-serialization
(bytewise lexicographic map-key order, RFC 8949 §4.2.1), replacing the
legacy length-then-lexicographic order (RFC 8949 §4.2.3). Rationale and
the recorded divergences live in SPEC §4.1. This note is the migration
plan; it ships as the breaking wire change SPEC §2.2 reserves a major
release for.

## Rules

1. **New wire version `0x03`.** Writers emit `0x03` (file header byte and
   the HEADER chunk `version` field). Readers support {0x01, 0x02, 0x03};
   unknown versions still raise `SPIFVersionError`. Old readers reject
   0x03 documents — that rejection is the gate that makes the migration
   explicit instead of silent.
2. **Canonical rule is per-version.** The reader takes the canonical rule
   from the document's own version byte:
   - 0x01 / 0x02 (legacy): writers sorted length-then-lexicographic;
     readers enforce the pre-existing form subset (definite lengths,
     shortest-form arguments, no duplicate keys) on signed documents and
     do not check key order — exactly today's behavior, so every existing
     document verifies as before.
   - 0x03 (deterministic): writers sort map keys by the bytewise
     lexicographic order of their encodings; readers enforce the full
     deterministic form on signed documents — the legacy subset **plus**
     key order, shortest-form floats (single NaN form), and minimal
     bignums (no leading zeros; a value representable as major type 0/1
     must not use tag 2/3). This is serialization checking in the draft's
     Appendix G sense.
3. **Unsigned documents keep today's leniency** at every version
   (encoding variability accepted; duplicate keys still always rejected).
4. **`content_id` is versioned with the document.** It is SHA-256 over
   the canonical CBOR of {payload, trace, provenance} encoded under the
   document version's canonical rule, and the SPEC states the rule per
   version. Signatures are unaffected by construction: they verify over
   transmitted bytes.
5. **Release naming.** SPEC §2.2 ties a breaking wire change to a major
   release, so wire 0x03 ships as the SPIF v2.0 format release. The
   mismatch (release 2.0, wire 0x03) is deliberate; do not "fix" it.

## Scope as built

The switch covers **every canonical encoding the format defines**, not
only chunk payloads: writer chunks (signed and unsigned — the unsigned
fast path is retired, since it promised no key order), `content_id`,
revocation and timestamp statement signing bytes and payloads, and
key-rotation payloads. One encoder (`cbor_deterministic`) serves all of
them in Python; the Rust side mirrors it. Statement *verification*
always uses the current rule: statements are verified in the present,
and the format is pre-adoption, so no legacy statement corpus exists to
protect. Reader *chunk-form enforcement* is the only version-scoped
surface, which is what keeps every existing document verifiable.

## Implementation surface

- **Python writer** (`spif-py/spif/writer.py`): `cbor2.dumps(...,
  canonical=True)` sorts length-first and has no bytewise option, so
  0x03 encoding uses a dedicated deterministic encoder: structural
  recursion over SPIF's value set (maps, arrays, text, bytes, ints,
  floats, bool, None, tags 1000–1002), map keys sorted by their encoded
  bytes, scalar leaves delegated to cbor2 so float reduction matches
  today's canonical output byte-for-byte at 0x02.
- **Python reader** (`spif-py/spif/reader.py`): `SUPPORTED_VERSIONS`
  gains 0x03; `_scan_cbor` gains, for 0x03 signed documents only, the
  key-order check (per map frame, compare each key's encoded span
  bytewise against the previous key's) and the float/bignum minimality
  checks. Legacy path untouched.
- **Rust writer/reader** (`spif-rust/src/`): mirror both changes —
  bytewise key sorting at encode, the same per-version scan at the
  chunk-framing layer where Lane 8 put canonical enforcement.
- **SPEC**: §2.2 (version 0x03 + support rule), §4.1 (per-version
  canonical rules; the open-decision note resolved), §7 content_id
  statement per version, changelog entry.

## Conformance

New vectors alongside the existing 25:
- The same logical signed document at 0x02 (legacy order) and at 0x03
  (bytewise order): each verifies under its own version's rule.
- A 0x03 signed document with legacy-ordered keys in a signed chunk:
  INVALID (order now checked).
- A 0x02 signed document with bytewise-ordered keys: still VALID
  (legacy readers never checked order — leniency is part of the rule).
- 0x03 float/bignum non-minimal forms in a signed chunk: INVALID;
  the same bytes at 0x02: VALID (tightening is version-scoped).
The runner's Rust dispatch covers the new cases the same way it covers
18/19 and 24/25, so the guard cannot go blind on this surface again.

## Gates

Baseline before code (main `e6cce61` tree): conformance 25/25;
spif-py 895 passed / 18 failed / 1 error, failed set = the pre-existing
environmental Gemini-adapter + rust-sidecar set; cargo green except the
same 3 environmental compat failures on the base. Landing bar: failed
sets name-identical to baseline, conformance 25 + new vectors passing.

## Discovered during implementation: weak-key acceptance (both stacks)

The migration's byte changes dealt an existing Rust FFI test a body
for which a forged all-zero signature under an all-zero (small-order)
public key verified as VALID. Root cause is independent of CBOR:
cofactored ed25519 verification (ed25519-dalek `verify`, and OpenSSL
behind Python's `cryptography`) accepts forgeries under small-order
keys for roughly one message in four; a Python probe over hand-built
documents reproduced it (1 of 12 bodies accepted pre-fix). The hole
predates the migration — the new bytes merely exposed it.

Fix shipped in this branch: every ed25519 verify path in both
implementations rejects weak (small-order) signer keys before the
cryptographic check — `VerifyingKey::is_weak()` in Rust (reader +
the shared statement-verification helper) and
`is_weak_ed25519_public_key` in Python (pure-Python RFC 8032 point
math, [8]P == identity; wired into the reader, trust resolution,
hybrid assessment, rotation proofs, keystore, and CLI). Regression
tests: `tests/test_weak_key_rejection.py` (Python) and the existing
Rust FFI forged-signature tests, which now pass for the right reason.
