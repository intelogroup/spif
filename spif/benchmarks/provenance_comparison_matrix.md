# SPIF vs. provenance/attestation systems

The old `BENCHMARKS.md` compares SPIF's encode/decode speed to JSON/CBOR/MsgPack.
That's a serialization-format comparison. It says nothing about SPIF's actual
claim, which is provenance: attaching a verifiable, tamper-evident record of
*how an AI output was produced*, cheaply enough to do it inline, per output,
at generation time. The real competitor set for that claim is Sigstore, C2PA,
and in-toto — not msgpack. This doc compares against those three, honestly,
including where SPIF loses or where a comparison isn't fair to make.

Quantitative numbers (build/verify latency, size) are in
`results/provenance_comparison_bench.txt`, produced by
`provenance_comparison_bench.py`. SPIF and in-toto were measured locally on
equal terms (local keypair, no network). Numbers:

```
System                                    Build p50   Build p99  Verify p50  Verify p99   Size B
SPIF                                         11.5μ       15.8μ       10.3μ       18.7μ       672
in-toto (DSSE, local Ed25519 key)            68.1μ       88.4μ      144.1μ      167.5μ       896
```

(final same-interpreter run, Python 3.12.13 — earlier 3.9 numbers moved <2%,
not a meaningful confound, but this is the run to cite)

SPIF is ~6x faster to build and ~14x faster to verify than an equivalent
in-toto DSSE-enveloped statement, and ~25% smaller. Both are local-keypair,
zero-network, offline-capable — this is an apples-to-apples number.

**Sigstore was also measured, live, against its staging Fulcio+Rekor
instance** (2026-08-09, real network calls, real transparency-log entries —
see `results/provenance_comparison_bench.txt` for the raw run).

FINAL pass (2026-08-09): re-run on one interpreter (Python 3.12.13) for all
three systems so version isn't a confound, and Sigstore verify bumped from
n=5 to n=30 with percentile reporting to match SPIF/in-toto's n=200 style.
Interpreter version turned out not material (SPIF/in-toto moved <2% between
3.9 and 3.12), but this run is the one to cite since everything's now on
equal footing:

```
SPIF verify (p50):      10.3μs
in-toto verify (p50):  144.1μs
Sigstore verify (p50):   4.3ms   (n=30, real staging Fulcio+Rekor, steady-state)
Sigstore verify (p99):  21.0ms   (pulled up by one cold-TLS sample, 26.4ms)
```

Fair comparison: Sigstore verify is ~417x slower than SPIF's, ~30x slower
than in-toto's — real, and still the same underlying story (every verify is
a network call to infrastructure you don't run, vs. SPIF/in-toto checking a
signature against a key you already have). Multiplier history as measurement
got fairer each round: 73,000x (CLI-subprocess bug) → 530-570x (in-process,
n=5, mixed interpreter) → 417x (in-process, n=30, same interpreter, p50).
Sign still isn't reportable as a clean number: live runs took 23.5s/14.1s
wall-clock, but that's interactive GitHub OIDC login time (0.35-0.39s of
actual CPU work), and no local session was cached — each run re-authenticated
as a different GitHub identity. A CI/service-account flow with an ambient
OIDC token would give a real sign number; manual interactive signing doesn't.

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

SPIF's moat isn't "faster than JSON." It's: cheap enough (double-digit
microseconds, sub-kilobyte) to attach real cryptographic provenance to every
single AI output/tool-call inline, with zero network dependency and zero PKI
setup — a niche none of Sigstore, C2PA, or in-toto occupy, because none of
them were built for high-frequency, per-call, streaming attestation. The
tradeoff for that is giving up the things that make Sigstore/in-toto/C2PA
valuable in their own domains: a public transparency log, a policy/layout
language, and CA-backed identity respectively.
