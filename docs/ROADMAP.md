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

### 1. Key rotation chunk (`KEY_ROTATION`, proposed `0x0B`)
`{old_key_id, new_key_id, rotation_sig, not_before}`, distinct from REVOCATION (compromise) vs.
rotation (planned handover). Blocked on: deciding whether rotation records live in-document or
in an external key-transparency log — building this before a real key-management deployment
means guessing at the wrong model.

### 2. Trust-authority model for REVOCATION / timestamping
REVOCATION (§7.6) specifies the chunk shape but not *who* attests `revoked_ms`, or whether SPIF
needs an RFC 3161-style timestamp authority for "signed at T" claims stronger than the document's
own `HEADER.created_ms`. Needs: a CRL/OCSP-equivalent distribution model, or explicit deferral to
external systems (e.g., the sidecar CRL protocol already sketched in
[`draft-ietf-spif-00.md`](../draft-ietf-spif-00.md) §6) — don't build a bespoke TSA speculatively.

### 3. Cross-document resolution (multi-agent lineage)
§8.1 defines the `NodeRef` string form; actually *resolving* it — fetching the referenced
document, verifying its `content_id()`, detecting cycles across document boundaries, and guarding
against DoS via unbounded external fetch — is unbuilt. Needs a fetch policy (allow-list? sandbox?
size/depth limits?) informed by how real multi-agent pipelines actually chain documents, not
guessed in advance.

### 4. Checksum/hash agility
`CHECKSUM` (`0xFF`) is hardcoded to SHA-256. Reserve `0xFE = SHA3-256`, `0xFD = BLAKE3` (or
similar) in the chunk registry when a concrete migration need appears, following the same
registry-not-hardcode pattern used for `Signature.algorithm`.

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
