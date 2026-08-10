# SPIF vs. provenance/attestation systems

The old `BENCHMARKS.md` compares SPIF's encode/decode speed to JSON/CBOR/MsgPack.
That's a serialization-format comparison. It says nothing about SPIF's actual
claim, which is provenance: attaching a verifiable, tamper-evident record of
*how an AI output was produced*, cheaply enough to do it inline, per output,
at generation time. The real competitor set for that claim is Sigstore, C2PA,
and in-toto — not msgpack. This doc compares against those three, honestly,
including where SPIF loses or where a comparison isn't fair to make.

Quantitative numbers (build/verify latency, size) are produced by
`provenance_comparison_bench.py` — run it yourself to reproduce
(`python3 provenance_comparison_bench.py --reps 200`); output isn't
committed (`spif/results/*.txt` is gitignored, regenerate locally). SPIF and
in-toto are measured locally on equal terms: local keypair, no network,
**both signed** (SPIF via `spif.crypto.sign_document()` +
`SPIFReader().verify_signature()`, in-toto via a DSSE envelope). An earlier
draft of this doc compared an *unsigned* SPIF encode against in-toto's
signed envelope — caught in review, fixed. Latest rerun: Python 3.11.15,
`c2pa-python` 0.37.5, `securesystemslib` 1.4.0, Reps=200:

```
System                                    Build p50   Build p99  Verify p50  Verify p99   Size B
SPIF (signed, ed25519)                      273.0μ      306.7μ      424.5μ      449.9μ       828
in-toto (DSSE, local Ed25519 key)           198.8μ      223.5μ      407.9μ      474.5μ       896
```

Honest result: once both sides actually sign, **in-toto is ~1.4x faster to
build** (198.8μs vs 273.0μs — SPIF's two-pass encode, needed to lock chunk
layout before signing the exact preceding bytes, costs more than DSSE's
single-pass sign) and the two are **roughly tied on verify** (424.5μs vs
407.9μs, SPIF ~4% slower). SPIF is still ~8% smaller (828B vs 896B). The
previous claim of "SPIF wins 6x build / 14x verify" was an artifact of
comparing signed in-toto against unsigned SPIF — not a real result, and this
doc no longer makes it. SPIF's case at the crypto layer is size and
streaming decode, not raw signing speed; unsigned SPIF (no per-record
non-repudiation) is still ~11μs/~10μs for callers who don't need a signature
at all — a mode in-toto and C2PA don't have.

**Sigstore** was not measured in the latest rerun. The committed benchmark
intentionally excludes live Fulcio/Rekor latency because signing and
verification require network access, transparency-log interaction, and a
fresh OIDC token. A local CPU microbenchmark would not represent that real
workflow; any Sigstore latency figure should come from a separately committed
and reproducible live-infrastructure harness.

## Feature / guarantee matrix

| | SPIF | in-toto | C2PA | Sigstore |
|---|---|---|---|---|
| **Designed for** | Per-call AI output provenance | Software supply-chain build steps | Media content credentials (photo/video/audio) | Keyless code-signing artifacts |
| **Trust model** | Bring-your-own key (or unsigned) | Bring-your-own key + layout policy | CA-chain-issued cert or trust-anchor bundle **required** — refuses to sign with a self-signed cert, even with correct extensions (verified above) | Ephemeral cert from Fulcio, bound to an OIDC identity — no long-lived key at all |
| **Network dependency to sign** | None | None | None (once you have a cert) | Fulcio (cert issuance) + usually Rekor (transparency log) |
| **Transparency log** | No | No | No | Yes — public Rekor log, third-party auditable |
| **Granularity** | Per-node / per-tool-call, inline in the output stream | Per build step (link), chained via layout | Per asset/file | Per artifact (file, container image, etc.) |
| **Streaming-friendly** | Yes — chunked CBOR, decode incrementally | No — whole statement signed at once | No — whole asset signed at once | No — whole artifact signed at once |
| **Tamper detection scope** | Full document body (SHA-256, mandatory on decode) | Full DSSE payload (signature over PAE) | Full asset + manifest (signature) | Full artifact (signature) |
| **Confidence/uncertainty metadata** | Yes — native `Distribution` type (mean/var/shape) | No | No | No |
| **Setup cost to produce a first signed record** | Zero (unsigned) or one local keypair | One local keypair | A CA-issued cert — not obtainable with a self-signed test cert (confirmed by direct API test above) | An OIDC login (interactive or CI token) |
| **Best fit** | Streaming AI output, tool-call chains, audit trails needing per-hop granularity | Multi-step build pipelines with a defined layout/policy | Publishing media with a checkable authenticity chain | Publishing software artifacts with public, independently-checkable provenance |

## Where SPIF has no real answer

- **No transparency log.** SPIF's checksum + signature prove a document
  wasn't altered and (if signed) who signed it — but there's no public,
  third-party-auditable log the way Rekor gives Sigstore. A dishonest signer
  can produce two different "authentic" SPIF documents for the same event
  and nothing in SPIF itself catches that. If public non-repudiation across
  organizations matters (the supply-chain use case Sigstore targets), SPIF
  doesn't cover it and isn't trying to.
- **No policy/layout language.** in-toto's layout lets a verifier assert
  "these 4 steps happened, in this order, by these authorized keys." SPIF's
  `context_ref` chain proves hop-to-hop linkage (see `audit_chain_bench.txt`)
  but has no equivalent of an enforced multi-party layout policy.
- **Not a media-authenticity format.** C2PA is purpose-built for
  photo/video/audio provenance (camera → edit → publish chain) with tooling
  across the whole media industry. SPIF doesn't compete there and the two
  aren't substitutable.

## The honest positioning

SPIF's moat isn't "faster than JSON," and after the signed-vs-signed fix
above it isn't "faster than in-toto" either — the two are close (SPIF
somewhat slower to build, roughly tied to verify). It's: sub-millisecond,
sub-kilobyte, zero-network, zero-PKI-setup provenance attachable to *every*
single AI output/tool-call inline — a niche none of Sigstore, C2PA, or
in-toto occupy, because none of them were built for high-frequency, per-call,
streaming attestation with a native confidence/uncertainty field in the same
envelope. The tradeoff for that is giving up the things that make
Sigstore/in-toto/C2PA valuable in their own domains: a public transparency
log, a policy/layout language, and CA-backed identity respectively.
