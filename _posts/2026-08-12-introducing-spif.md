---
layout: default
title: "Introducing SPIF: an 828-byte signed provenance envelope for AI outputs"
date: 2026-08-12
---

An AI output usually can't carry its own history: model, confidence, steps taken, tamper status. That metadata lives in a separate tracing system, if it exists at all, so it's the first thing lost once the response leaves your pipeline.

SPIF is a small binary (CBOR) envelope that attaches this directly to the output: model/tool identity, a confidence distribution (not just a token logprob), an optional DAG of intermediate steps, and an optional ed25519 signature. Decode is streaming and the whole thing is designed to be sub-millisecond, so it's cheap enough to attach inline, per response, instead of only living in a separate system.

```python
from spif import SPIFDocument, SPIFReader, Node
from spif.types import Distribution, Provenance
from spif.crypto import generate_key, sign_document

doc = SPIFDocument(
    payload=[Node(id="response", type="text", value="approach B minimizes latency",
                  confidence=Distribution(mean=0.85, var=0.03, shape="gaussian"))],
    provenance=Provenance(source_model="claude-sonnet-4-6", temperature=0.7,
                          input_hash=..., timestamp_ms=...),
)
key = generate_key()
blob = sign_document(doc, key)          # build + sign -> bytes
SPIFReader().verify_signature(blob)     # True
SPIFReader().decode(blob).provenance.source_model  # "claude-sonnet-4-6"
```

## What I can actually back up, having just run it myself

- 828 bytes for a signed single-response record, ~110μs to build / ~165μs to verify.
- Benchmarked signed-vs-signed against another local-keypair attestation format (DSSE-style, same machine, both signed): that format is ~1.4x faster to build, verification is roughly tied, SPIF is ~8% smaller. An earlier version of this comparison compared a signed competitor against unsigned SPIF and made SPIF look faster than it is. Fixed, numbers above are apples-to-apples.
- Fuzzing: built atheris from source and ran both fuzz targets myself against the real seed corpus: 12M execs / 91s on the base decoder, 11M execs / 91s on strict-mode decode, zero crashes on either.
- Cross-lang: Python, TypeScript, and Rust implementations decode the same bytes.

## Not really comparable to C2PA or Sigstore

Different problems. Both lean on infrastructure (CA-issued certs, public transparency logs) SPIF skips on purpose: one small record, local key, no network.

Fits best where provenance has to travel with the output itself: signing every AI API response inline, recording agent tool-call chains as one signed record, edge/offline inference with no network to phone home to, and high-volume paths where microsecond signing matters. Not a fit if you need a public auditable log or CA-backed signer identity.

An adapter also just landed that imports a C2PA manifest into a SPIF envelope, so you can attach your own tool chain/confidence metadata on top of an existing C2PA-signed asset.

Spec and code are Apache-2.0. Roast welcome, especially the DAG validation and the Rust decoder, I'd rather find the holes here than after someone depends on it.

[Repo](https://github.com/intelogroup/spif)
