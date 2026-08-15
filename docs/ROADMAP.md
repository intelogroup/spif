# SPIF Roadmap: Long-Term Trust (post-v1.2)

This tracks work identified for SPIF's long-term (multi-decade) viability that is
**deliberately deferred** rather than built speculatively. See §7.5, §7.6, and §8.1 of
[`docs/SPEC.md`](SPEC.md) for the v1.2 addendum that already shipped the one piece of this
that was cheap to do now and expensive to retrofit later.

## Why deferred, not built now

SPIF is pre-adoption. The near-term risk isn't a 2035 quantum computer — it's that nobody uses
the format yet. Every chunk type, trust-authority dependency, or fetch policy built ahead of a
real deployment is surface area that slows down getting third-party readers written, guessing at
requirements (a TSA model, a cross-document fetch policy) that are better designed against actual
usage than against a thought experiment. v1.0's forward-compatibility rules — unknown chunks are
skipped (§3.1), unknown `Signature.algorithm` values are treated as unverifiable rather than
invalid (§7.2) — are the actual hedge. They mean all four items below can land later as optional,
skippable additions without a wire-format break, so there's no cost to waiting for a real signal:
a design partner needing multi-agent chains, or PQ timelines becoming non-optional.

## Hardening shipped since v1.2 (done)

A pentest-style pass over the implementation (not the spec) turned up three real gaps
between what `docs/SPEC.md` promised and what the code actually did, plus closed the
CI tooling gap that let them go unnoticed:

- **Rust zlib-bomb DoS** — `spif-rust`'s zlib decompression (`reader.rs::cbor_payload`)
  had no output size cap; a small compressed chunk could drive unbounded allocation.
  `spif-py` was already bounded via `MAX_DECOMPRESSED_SIZE` (10MB). Rust now matches it.
  This closes the "decompression bomb" gap for `flags2 & 0x01` (zlib) on both languages.
- **FFI signature-verification bypass** — `spif_document_get_verification_status()` in
  `ffi.rs` reported `"valid"` based on a SIGNATURE/MULTISIG chunk merely being *present*,
  not on it cryptographically verifying (the lenient `spif_document_parse` never called
  verification internally). A real authentication-bypass shape bug against the exact
  audience `spif.h` documents itself as targeting (security agents, firewalls). Fixed to
  report actual verification outcome (`"valid"` / `"unsigned"` / `"invalid"`).
- **Misleading zstd error** — `spif-rust` has no zstd dependency and silently mis-handled
  `flags2 & 0x02` (zstd) documents as if uncompressed, failing with a generic "Malformed
  CBOR" error. Not a security bug (fails safe), but wastes a caller's debugging time. Now
  names zstd as the actual unsupported feature.
- **CI tooling gap** — `cargo-deny` (RustSec advisories + license/source bans, supersedes
  a separate `cargo-audit`), `semgrep` (non-blocking first pass, registry rulesets not
  yet triaged), and Python added to the CodeQL language matrix (previously Rust-only,
  leaving the crypto-sensitive `spif-py` reference implementation unscanned) are now
  wired into CI. `cargo-fuzz` targets existed but weren't run anywhere; now they run on
  every PR touching `spif-rust` (60s smoke) and nightly (20min), including two new
  targets (`fuzz_stream`/`fuzz_stream_strict`, `fuzz_verify`) covering surface the
  original two targets never touched.

None of this required a spec change — it was implementation catching up to what
`docs/SPEC.md` already specified (§7.2's unverifiable-not-invalid rule, §9.1's compressed
payload bound). **Still open, small**: no automated check (CodeQL/semgrep custom query)
yet asserts the `signing_body = bytes before first auth chunk` invariant (§7.2) directly —
today it's only verified by the test suite reaching the right answer, not by a static rule
that would catch a future refactor breaking it silently.

## Shipped in v1.2 (done)

- **Signature algorithm registry** (§7.5) — `Signature.algorithm` is no longer hardcoded to
  `"ed25519"`; it accepts `"ml-dsa-65"` and the hybrid `"ed25519+ml-dsa-65"`. This was the one
  item worth doing immediately: near-zero cost (a string field, no new dependency, no wire
  break) and the one thing that would have been genuinely expensive to retrofit — if verify
  logic anywhere had assumed a hardcoded 64-byte signature, adding PQ later would have forced a
  v2.0 break instead of a v1.2 addendum.
- **REVOCATION chunk** (`0x0A`, §6.12, §7.6) — schema and timestamp-bound-trust semantics are
  specified (informational) so the wire format has a slot reserved; the trust-authority model
  below is what's still open.
- **Cross-document NodeRef** (§8.1) — `spif:sha256:<content_id>#<node_id>` form is specified as
  an opaque-string extension old readers already handle safely.

## Deferred — build when there's a real signal

Each item below sketches the test that would prove it, so picking one up later doesn't
start from a blank page — but the sketch is not a commitment to that exact shape, since
the whole point of deferring is to design against a real deployment instead of a guess.

### 1. Key rotation chunk (`KEY_ROTATION`, proposed `0x0B`)
`{old_key_id, new_key_id, rotation_sig, not_before}`, distinct from REVOCATION (compromise) vs.
rotation (planned handover). Blocked on: deciding whether rotation records live in-document or
in an external key-transparency log — building this before a real key-management deployment
means guessing at the wrong model.

**Test sketch** (`test_pq_hybrid.py`, once §7.5's `ml-dsa-65`/hybrid algorithms have a real
consumer): write a document with `MULTISIG [ed25519, ml-dsa-65]`; assert a pre-v1.2 reader
verifies the ed25519 component and ignores the unrecognized `ml-dsa-65` entry per §7.2's
unverifiable-not-invalid rule, while a PQ-aware reader in `require_pq=True` mode requires both.
Cross-check against NIST ACVP ML-DSA test vectors, the same way §7's Wycheproof/RFC 8032 vectors
already validate the ed25519 path — this is what would actually demonstrate "algorithm registry
independent of wire 0x02," not just that the field accepts new strings.

### 2. Trust-authority model for REVOCATION / timestamping
REVOCATION (§7.6) specifies the chunk shape but not *who* attests `revoked_ms`, or whether SPIF
needs an RFC 3161-style timestamp authority for "signed at T" claims stronger than the document's
own `HEADER.created_ms`. Needs: a CRL/OCSP-equivalent distribution model, or explicit deferral to
external systems (e.g., the sidecar CRL protocol already sketched in
[`draft-ietf-spif-00.md`](../draft-ietf-spif-00.md) §6) — don't build a bespoke TSA speculatively.

**Test sketch** (`test_revocation.py`): verification returns `VALID_AT(signed_ms)` rather than a
bare boolean (§7.6 already specifies this); fuzz a `revoked.json`-style registry and an expired
`signer` URL to confirm a document signed before revocation still reports valid-at-signing-time,
while a present-day trust check on the same document reports untrusted. This is the concrete
form of the "don't collapse two facts into one boolean" rule §7.6 already states.

### 3. Cross-document resolution (multi-agent lineage)
§8.1 defines the `NodeRef` string form; actually *resolving* it — fetching the referenced
document, verifying its `content_id()`, detecting cycles across document boundaries, and guarding
against DoS via unbounded external fetch — is unbuilt. Needs a fetch policy (allow-list? sandbox?
size/depth limits?) informed by how real multi-agent pipelines actually chain documents, not
guessed in advance.

**Test sketch** (`test_lineage.py`): a 3-agent chain, document A referenced by B referenced by C
via `spif:sha256:<content_id>#<node_id>`; mutating A's referenced node must invalidate C's
resolution (the `content_id()` pin in §8.1 catches it) without requiring C to re-fetch and
re-verify the entire chain eagerly. Also: cycle detection across document boundaries, not just
within one document's DAG (§7's `validate_payload_dag`/`validate_trace_dag` only handle the
in-document case today).

### 4. Checksum/hash agility
`CHECKSUM` (`0xFF`) is hardcoded to SHA-256. Reserve `0xFE = SHA3-256`, `0xFD = BLAKE3` (or
similar) in the chunk registry when a concrete migration need appears, following the same
registry-not-hardcode pattern used for `Signature.algorithm`.

**Test sketch** (`test_hash_agility.py`): a `spif re-attest old.spif --with ml-dsa-65` CLI
command that co-signs an aging document under a new algorithm — see item 5 below for why this
must preserve `content_id()` rather than mutate it — verified against documents written with
each reserved checksum algorithm.

### 5. Re-attestation as a stable envelope
§7.6 allows appending a new MULTISIG entry to re-sign an aging document, but re-attestation
changes the document's bytes and thus its checksum. Before this is real: define re-attestation as
a wrapping envelope that preserves the *original* `content_id()` rather than mutating the
document in place, so `content_id()` stability (§8) isn't silently broken by an archival service.

## Non-goals for now

- Building a hosted or reference trust-authority / TSA service
- Mandating PQ or hybrid signatures (stays opt-in until NIST/industry timelines force it)
- Any wire-format version bump — everything above targets optional chunks under the existing
  forward-compatibility rules
