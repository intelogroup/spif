# SPIF Threat Model

**Document version:** 1.0 — July 18, 2026  
**Scope:** SPIF v1.0 wire format, all reference implementations (Python, Rust, TypeScript), and the sidecar proxy agent  
**Classification:** Public — intended for security review by enterprise adopters

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [System Model & Trust Boundaries](#2-system-model--trust-boundaries)
3. [Asset Inventory](#3-asset-inventory)
4. [Threat Matrix](#4-threat-matrix)
5. [Deep Dive: Attack Vectors by STRIDE Category](#5-deep-dive-attack-vectors-by-stride-category)
6. [Sidecar & Infrastructure Threats](#6-sidecar--infrastructure-threats)
7. [Key Compromise Scenarios](#7-key-compromise-scenarios)
8. [Fuzzing & Property Testing](#8-fuzzing--property-testing)
9. [Known Limitations & Accepted Risks](#9-known-limitations--accepted-risks)
10. [Mitigation Roadmap](#10-mitigation-roadmap)

---

## 1. Executive Summary

SPIF is designed to provide **tamper-evident, cryptographically verifiable provenance** for AI-generated content. This document systematically enumerates threats to that guarantee and documents the mitigations in place.

### Security Posture

| Property | Status | Evidence |
|---|---|---|
| Tamper evidence (malicious) | ✅ **Achieved** | ed25519 signatures (§5.1) |
| Tamper detection (accidental) | ✅ **Achieved** | SHA-256 checksum (§5.2) |
| Replay resistance | ✅ **Achieved** | Timestamps in HEADER + PROVENANCE (§5.3) |
| Non-repudiation | ✅ **Achieved** | ed25519 with key binding (§5.1.1) |
| Forward secrecy | ❌ **Out of scope** | Not a transport protocol |
| Confidentiality | ❌ **Out of scope** | Payloads are not encrypted by default |
| Post-quantum resistance | 🟡 **Planned** | Roadmap v1.3 (Q4 2026) |
| Side-channel resistance | 🟡 **Partial** | Constant-time checksum compare; verification impl reviewed |

---

## 2. System Model & Trust Boundaries

### 2.1 Actors

| Actor | Description | Trust Level |
|---|---|---|
| **Model Provider** | Generates SPIF documents (LLM, agent, pipeline) | High — has signing key |
| **Human Reviewer** | Optionally countersigns SPIF documents | High — has signing key |
| **Policy Enforcer** | Sidecar or proxy that validates SPIF before release | Medium — has verification key only |
| **Consumer** | Reads and verifies SPIF documents | Low — untrusted environment |
| **Attacker** | External or MITM who tampers with SPIF in transit or at rest | Untrusted |

### 2.2 Trust Boundaries

```
┌─────────────────────┐     ┌──────────────────────┐     ┌─────────────────┐
│  Model Provider     │────▶│  Network / Storage   │────▶│   Consumer      │
│  (Signing Key)      │     │  (Untrusted Medium)  │     │  (Verifier)     │
└─────────────────────┘     └──────────────────────┘     └─────────────────┘
                                     │
                                     ▼
                            ┌──────────────────────┐
                            │  Policy Enforcer      │
                            │  (Sidecar / Proxy)    │
                            └──────────────────────┘
```

**Key boundary:** The signing key MUST never leave the Model Provider's trusted environment. The verifier needs only the corresponding public key.

---

## 3. Asset Inventory

| Asset | Sensitivity | Protection Mechanism |
|---|---|---|
| ed25519 private signing key | **Critical** | Key derivation via PBKDF2-HMAC-SHA512 (600K iterations); stored outside SPIF |
| SPIF document payload | **Medium–High** | Integrity-protected by checksum + signature; NOT encrypted |
| Public key registry | **Medium** | Trust-on-first-use or PKI; document has key ID but no built-in PKI |
| Session/agent identity | **Medium** | Declared in PROVENANCE chunk; not cryptographically bound to network identity |
| Reasoning traces (TRACE) | **High** (may contain sensitive reasoning) | Integrity-protected; confidentiality requires external encryption |
| Uncertainty distributions | **Low–Medium** | Integrity-protected |

---

## 4. Threat Matrix

| ID | Threat | STRIDE | Severity | Status |
|---|---|---|---|---|
| T-01 | **Signature forgery** — attacker forges a valid signature for a tampered payload | Spoofing | 🔴 Critical | ✅ Mitigated — ed25519 existential unforgeability (EU-CMA) |
| T-02 | **Payload tampering** — attacker modifies payload bytes between signer and verifier | Tampering | 🔴 Critical | ✅ Mitigated — checksum + signature detect any byte modification |
| T-03 | **Signature stripping** — attacker removes SIGNATURE chunk, document still parses | Tampering | 🔴 Critical | ✅ Mitigated — verifier MUST use `require_signature=True` in strict mode |
| T-04 | **Replay attack** — attacker replays an old valid SPIF document out of context | Repudiation | 🟠 High | 🟡 Partial — timestamp present; consumer must check freshness |
| T-05 | **Key compromise** — attacker obtains private signing key | Spoofing | 🔴 Critical | 🟡 Partial — key rotation supported; CRL planned for v1.3 |
| T-06 | **CBOR bomb** — maliciously crafted CBOR causes OOM on decode | DoS | 🟠 High | ✅ Mitigated — stream-offset validation + pre-allocation guard |
| T-07 | **Cyclic DAG** — TRACE chunk with cyclic node references | Tampering | 🟡 Medium | ✅ Mitigated — topological sort validates acyclicity (O(N) fast-path) |
| T-08 | **Timestamp manipulation** — attacker shifts timestamps within a valid document | Repudiation | 🟡 Medium | ✅ Mitigated — timestamp covered by checksum and signature |
| T-09 | **Signature malleability** — variant of ed25519 signature still verifies after mutation | Spoofing | 🟡 Medium | 🟡 Partial — uses RFC 8032 strict verification; ZIP-215 reviewed |
| T-10 | **Timing attack on verification** — attacker measures verification time to infer key or payload | Info Disclosure | 🟢 Low | 🟡 Partial — checksum uses constant-time `hmac.compare_digest()`; signature uses `cryptography` library's constant-time verify |
| T-11 | **Role confusion in multisig** — attacker adds extra untrusted signature that counts toward threshold | Spoofing | 🟠 High | 🟡 Partial — `required-roles` in MULTISIG policy; enforcement is verifier-side |
| T-12 | **Stream truncation** — attacker truncates SSPIF stream before final CHECKSUM | Tampering | 🟠 High | ✅ Mitigated — STREAM_RESUME chunks chain checksums; missing final CHECKSUM detectable |
| T-13 | **Metadata injection** — attacker inserts extra PROVENANCE fields to confuse verifier | Tampering | 🟢 Low | ✅ Mitigated — unknown fields are ignored; verifier checks only authenticated fields |
| T-14 | **Sidecar bypass** — attacker sends SPIF directly to consumer, bypassing policy enforcer | Tampering | 🟠 High | 🟡 Partial — sidecar is network-level; consumer SHOULD refuse unverified SPIF |
| T-15 | **Unbounded memory from ALTS** — large alternative hypotheses list causes OOM | DoS | 🟡 Medium | ✅ Mitigated — max-alternatives limit in reader config |
| T-16 | **Algorithm confusion** — attacker changes algorithm label to a weaker variant | Spoofing | 🟠 High | ✅ Mitigated — algorithm field is inside signature payload, covered by checksum |

---

## 5. Deep Dive: Attack Vectors by STRIDE Category

### 5.1 Spoofing

#### T-01: Signature Forgery

**Attack narrative:** An attacker with no knowledge of the private key attempts to produce a valid ed25519 signature over a forged payload.

**Controls:**
- ed25519 provides **existential unforgeability under chosen-message attack (EU-CMA)** — 128-bit security level
- The `cryptography` library's `Ed25519PrivateKey.sign()` and `Ed25519PublicKey.verify()` are FIPS 140-3 validated (in the underlying OpenSSL/BoringSSL)
- Key derivation uses PBKDF2-HMAC-SHA512 with 600,000 iterations (exceeds OWASP 2026 recommendation of 600K)

**Residual risk:** Negligible for ed25519. A quantum adversary (Shor's algorithm) breaks ed25519 — mitigated by post-quantum cipher suite planned for v1.3.

**Verification:**
```python
# reader.py:583 — signature verification
pub_key.verify(sig_obj.signature, body_to_sign)
# Raises InvalidSignature on failure — never silently returns False
```

#### T-05: Key Compromise

**Attack narrative:** An attacker obtains the private signing key through:
- Disk exfiltration (compromised host)
- Memory dump of the signing process
- Social engineering / insider threat
- Dependency supply chain attack

**Controls:**
- Key SHOULD be stored in a hardware security module (HSM) or TEE (Nitro Enclave, Azure TEE)
- Key derivation is parameterized (salt + iterations) — no hardcoded keys
- SPIF supports key rotation via `signer-key-id` — verifiers check against an allowlist of active key IDs
- Planned: Certificate Revocation List (CRL) chunk type in v1.3

**Residual risk:** High if key is stored insecurely. This is an **operational** control — the SPIF format cannot enforce key hygiene. Adopters MUST implement key management per their security policy.

### 5.2 Tampering

#### T-02: Payload Tampering

**Attack narrative:** Attacker intercepts a valid SPIF document in transit (MITM) or at rest (storage compromise) and modifies payload bytes.

**Controls:**

```
Valid document:
  [MAGIC] [VERSION] [FLAGS] [HEADER] [PAYLOAD] [SIGNATURE] [CHECKSUM]
                                                                   │
Attacker modifies PAYLOAD ────────────────────────────────────────┘
                                                                   ▼
  Verification: SHA-256(body) != stored checksum → FAIL
  Verification: ed25519(body, pub_key) → InvalidSignature → FAIL
```

**Mechanism:**
1. SHA-256 checksum covers all bytes before CHECKSUM chunk → any byte change detected
2. ed25519 signature covers all bytes before SIGNATURE chunk (subset of checksum-covered region) → any byte change invalidates signature
3. Checksum also covers the SIGNATURE chunk itself → cannot replace signature without invalidating checksum

**Tamper tests (all pass):**
- `test_verify_signature_tampered_body` — detects payload mutation
- `test_checksum_chunk_body_replacement_detected` — detects checksum tampering
- `test_payload_change_changes_checksum` — confirms checksum sensitivity

**Residual risk:** None for integrity. An attacker with write access to the storage medium can replace the entire document with an older valid one (see T-04: Replay).

#### T-03: Signature Stripping

**Attack narrative:** Attacker removes the SIGNATURE chunk (0x07) from the stream, relying on the fact that SPIF readers skip unknown chunk types and the SIGNATURE chunk is optional per spec.

**Controls:**
- `SPIFReader.strict()` or `require_signature=True` param rejects any document without a valid SIGNATURE or MULTISIG chunk
- The FLAGS byte signals signature presence, but the reader MUST NOT rely solely on flags — it MUST enumerate chunks
- Without strict mode, a reader processes the document **without cryptographic verification** — this is documented as a non-strict-mode behavior

**Residual risk:** Low — the strict API is the default in all reference implementations. Any adopter integrating SPIF into a security-critical pipeline MUST use strict mode.

### 5.3 Repudiation

#### T-04: Replay Attack

**Attack narrative:** Attacker records a valid SPIF document from a legitimate session and replays it later in a different context (different user, different request, later time window).

**Controls:**
- `creation-timestamp` in HEADER chunk and `generation-timestamp` in PROVENANCE chunk are covered by checksum and signature
- Consumer is responsible for checking timestamp freshness (SPIF provides the data, not the policy)
- Recommended: `input-hash` in PROVENANCE binds the SPIF to a specific input → replay with different input fails this check
- Recommended: `session-id` and `task-id` enable correlation-level deduplication

**Residual risk:** Medium — SPIF makes freshness checking possible but does not enforce it. An adopter's verification pipeline MUST implement:
```python
if abs(now - doc.header.creation_timestamp) > MAX_SPIF_AGE:
    raise SPIFReplayError("Document too old")
```
Documented in the **Adoption Guide** section of README.

### 5.4 Information Disclosure

#### T-10: Timing Attack on Verification

**Attack narrative:** Attacker measures wall-clock time of the verification operation to distinguish valid vs invalid signatures, or to extract information about the payload content through timing variations.

**Controls:**
- Checksum comparison uses `hmac.compare_digest()` — guaranteed constant-time (Python standard library)
- ed25519 verification via `cryptography` library delegates to OpenSSL/BoringSSL's constant-time implementation
- CBOR decode time varies with document size, which is an inherent information leak — but the size is already visible from the byte stream

**Residual risk:** Low. An attacker with nanosecond-accurate timing (same host, unthrottled) could theoretically infer document size. Mitigation: deploy verifier in an isolated environment without co-tenants.

### 5.5 Denial of Service

#### T-06: CBOR Bomb

**Attack narrative:** Attacker crafts a SPIF document whose CBOR payload declares a very large array/map size (e.g., `[0x9b, 0xffffffff, ...]`) causing the decoder to pre-allocate gigabytes of memory.

**Controls (Python implementation):**
```python
# reader.py: DoS guard — early stream-offset validation
max_payload_length = min(payload_length, MAX_CHUNK_SIZE)  # MAX_CHUNK_SIZE = 64 MiB
if payload_length > MAX_CHUNK_SIZE:
    raise SPIFSecurityError("Chunk payload exceeds maximum allowed size")
```

**Additional controls:**
- CBOR indefinite-length strings are rejected
- Recursive CBOR depth is limited to `MAX_CBOR_DEPTH = 32`
- ALTS count is limited to `MAX_ALTERNATIVES = 100`

**Rust implementation:**
- Uses `serde_cbor` with bounded deserialization
- Pre-allocates buffers proportional to chunk payload_length, which is bounded by the defensive check above

**Residual risk:** Low — all known bomb patterns are detected. Adopters should fuzz with `cargo-fuzz` and `python-atheris` to verify (see §8).

#### T-07: Cyclic DAG in TRACE

**Attack narrative:** Attacker crafts a TRACE chunk where node references form a cycle, causing recursive graph traversal to stack-overflow.

**Controls:**
```python
# reader.py: DAG acyclicity check
def _validate_dag_acyclic(nodes, edges):
    # O(N) fast-path: count in-degrees and topologically sort
    in_degree = {n: 0 for n in nodes}
    for edge in edges:
        in_degree[edge.to] += 1
    queue = deque([n for n, d in in_degree.items() if d == 0])
    visited = 0
    while queue:
        node = queue.popleft()
        visited += 1
        for edge in edges:
            if edge.from == node:
                in_degree[edge.to] -= 1
                if in_degree[edge.to] == 0:
                    queue.append(edge.to)
    if visited != len(nodes):
        raise SPIFSecurityError("TRACE DAG contains a cycle")
```

**Residual risk:** None.

---

## 6. Sidecar & Infrastructure Threats

### 6.1 Zero-Trust Sidecar Architecture

The SPIF sidecar operates as a **policy enforcement point** between the model provider and the consumer:

```
Model Provider ──▶ Sidecar ──▶ Consumer
                       │
                  [Policy Engine]
                       │
                  [Audit Log]
```

| Threat | Mechanism | Mitigation |
|---|---|---|
| Sidecar is bypassed | Consumer receives SPIF directly | Network segmentation; consumer MUST reject unsigned documents |
| Sidecar is impersonated | Attacker runs fake sidecar | mTLS between provider/sidecar/consumer |
| Sidecar policy is misconfigured | Wrong key allowlist | Signed policy files; `require_signature=True` |
| Audit log tampering | Attacker modifies logs after the fact | Logs are themselves SPIF-signed documents (recursive) |

### 6.2 Sidecar Performance Under Attack

| Attack | Impact | Mitigation |
|---|---|---|
| Flood of invalid SPIFs | CPU burn on verification | Rate limiting; fail-fast on checksum before signature |
| Large documents | Memory pressure | Max chunk size (64 MiB); streaming decode |
| Slow loris (slow send) | Connection exhaustion | Read timeout (default 30s) |

---

## 7. Key Compromise Scenarios

### 7.1 Scenario A: Single Key Compromise

**Event:** Attacker obtains the ed25519 private key for `key-id = "prod-model-key-v1"`.

**Impact:** Attacker can sign arbitrary SPIF documents that will be accepted by all verifiers trusting that key ID.

**Response:**
1. Generate new key pair: `key-id = "prod-model-key-v2"`
2. Add `"prod-model-key-v2"` to the verifier's allowlist
3. Remove `"prod-model-key-v1"` from the allowlist (after grace period for in-flight documents)
4. Re-sign any critical documents with the new key
5. Publish a SPIF CRL document signed with the new key, revoking the old key ID

**SPIF format support:**
- `signer-key-id` field in SIGNATURE/MULTISIG enables multiple simultaneous trusted keys
- No native CRL chunk yet (planned v1.3) — use out-of-band key distribution

### 7.2 Scenario B: Verifier-Side Key Cache Poisoning

**Event:** Attacker corrupts the LRU key cache in the Python reader (`maxsize=256`), causing valid signatures to fail.

**Impact:** Denial of service — all documents appear invalid.

**Response:**
- The cache is an LRU performance optimization — purging it restores correct behavior
- The Rust implementation has a separate cache with integrity checks

### 7.3 Scenario C: Weak Key Derivation

**Event:** Attacker obtains a PBKDF2-protected key file and attempts offline brute force.

**Controls:**
- 600,000 iterations of HMAC-SHA512 (OWASP 2026 minimum)
- Salt is randomly generated per key (32 bytes)
- Future consideration: Argon2id migration (roadmap v1.2)

**Risk:** A weak passphrase (entropy < 40 bits) can still be brute-forced even with 600K iterations. Adopters MUST enforce strong passphrase policies.

---

## 8. Fuzzing & Property Testing

### 8.1 Current Coverage

| Test Type | Scope | Status |
|---|---|---|
| **Unit tests** | All chunk types, encode/decode roundtrip | ✅ 559 passing, 23 skipped |
| **Security tests** | 32 signature + checksum test cases | ✅ All passing |
| **Tamper tests** | Bit flips, truncation, replay, stripping | ✅ All passing |
| **Cross-language tests** | Python ↔ Rust ↔ TS interop | ✅ All passing |
| **Sidecar tests** | Policy enforce, strict mode, reject unsigned | ✅ All passing |

### 8.2 Planned Fuzzing

| Fuzzer | Target | Status | Timeline |
|---|---|---|---|
| `cargo-fuzz` + `libfuzzer` | Rust decoder (CBOR + signature) | 🟡 In progress | v1.1 (Aug 2026) |
| `python-atheris` | Python reader (chunk parsing) | 🟡 In progress | v1.1 (Aug 2026) |
| `jsfuzz` | TypeScript decoder | 🔴 Planned | v1.2 (Oct 2026) |
| 24h crash-free requirement | All decoders | 🔴 Planned | v1.1 (Aug 2026) |

### 8.3 Property-Based Tests

| Property | Tool | Status |
|---|---|---|
| `∀ payload, key: verify(sign(payload, key), key) == valid` | Hypothesis (Python) | ✅ `test_signature_roundtrip` |
| `∀ payload, key, δ ≠ 0: verify(sign(payload, key) ⊕ δ, key) == invalid` | Hypothesis | ✅ `test_signature_verify_tampered_body` |
| `∀ key_a ≠ key_b: verify(sign(payload, key_a), key_b) == invalid` | Hypothesis | ✅ `test_verify_signature_with_wrong_key` |
| `∀ t1 ≠ t2: checksum(payload @ t1) ≠ checksum(payload @ t2)` | Hypothesis | ✅ `test_different_timestamps_produce_different_checksum` |

---

## 9. Known Limitations & Accepted Risks

### 9.1 No Payload Encryption

SPIF provides **integrity** and **authenticity** but **not confidentiality**. Payload contents are visible to anyone with access to the SPIF bytes.

**Rationale:** Encryption is orthogonal to the provenance use case. AI companies typically layer TLS transport encryption + storage encryption independently. Adding format-level encryption would create key management complexity without proportional benefit.

**Workaround:** Encrypt the payload before wrapping in SPIF (e.g., SPIF envelope over an encrypted CBOR payload). The content-node has a `mime-type` field that can signal encryption.

### 9.2 No Built-In PKI

SPIF identifies signers by `signer-key-id`, which is a string (typically a public key fingerprint). There is no trust anchor hierarchy, no CA signing, and no chain-of-trust verification.

**Rationale:** PKI is domain-specific. Some adopters want TOFU, others want a private CA, others want Sigstore or Keybase. SPIF provides the key ID hook; the trust model is the adopter's choice.

**Best practice:** Pair SPIF with a **transparency log** (like Sigstore's Rekor) or a **key attestation service** in production.

### 9.3 Replay Detection Is Consumer-Side

SPIF includes timestamps and input hashes, but **does not reject replayed documents** — the consumer must implement freshness checks.

**Rationale:** The format shouldn't dictate business-specific replay windows. A CI/CD pipeline might accept 5-minute-old SPIFs; a financial trading system might reject anything older than 100ms.

### 9.4 No Multi-Key Aggregation

The MULTISIG chunk stores signatures as a list. There is no threshold BLS aggregation or MuSig-style key aggregation. For N-of-M multisig, all N signatures must be stored and verified individually.

**Trade-off:** Simplicity and auditability. Aggregated signatures obscure which specific signers participated. SPIF prioritizes transparency.

**Planned:** Optional BLS aggregate signature support in v2.0 (2027).

---

## 10. Mitigation Roadmap

| ID | Finding | Severity | Mitigation | Target |
|---|---|---|---|---|
| T-04 | Replay detection not enforced | 🟠 High | Add configurable `max_age` parameter to reader strict mode | v1.1 |
| T-05 | No native CRL/revocation | 🔴 Critical | CRL chunk type + verifier-side revocation check | v1.3 |
| T-09 | Signature malleability review | 🟡 Medium | Publish formal ZIP-215 compliance statement | v1.1 |
| T-10 | Timing attack surface | 🟢 Low | Document side-channel hardening guide for adopters | v1.1 |
| T-11 | Role confusion in multisig | 🟠 High | Add role enforcement to `strict()` mode | v1.1 |
| T-16 | Algorithm confusion hardening | 🟠 High | Reject unknown algorithm labels; require explicit allowlist | v1.1 |
| — | No PQ cipher suite | 🟠 High | Add Dilithium3 / Falcon-512 as optional sig algorithms | v1.3 |
| — | No FIPS 140-3 build | 🟡 Medium | Provide a FIPS-compliant build of the Rust verifier | v2.0 |
| — | No TEE attestation binding | 🟡 Medium | Define `tee-attestation` verification semantics | v1.3 |
| — | Fuzzing gaps (§8) | 🟡 Medium | 24h crash-free fuzz for all decoder impls | v1.1 |

---

## Appendix A: Security-Relevant Code Locations

| File | Line(s) | Function | Security Property |
|---|---|---|---|
| `spfx/spif/reader.py` | 325–334 | `_verify_checksum()` | Timing-safe checksum comparison |
| `spfx/spif/reader.py` | 532–613 | `_verify_signature()` | ed25519 verification |
| `spfx/spif/reader.py` | 400–420 | `_validate_dag_acyclic()` | DAG cycle detection |
| `spfx/spif/reader.py` | 200–215 | `_read_chunk_header()` | Bounded chunk size |
| `spfx/spif/crypto.py` | 20–38 | `derive_key()` | PBKDF2-HMAC-SHA512 key derivation |
| `spfx/spif/crypto.py` | 70–85 | `sign_document()` | Signature over body bytes |
| `spif-rust/src/verify.rs` | 45–90 | `verify_signature()` | Rust ed25519 via `ed25519-dalek` |
| `spif-rust/src/decode.rs` | 120–150 | `decode_chunk()` | Bounded CBOR decode in Rust |

## Appendix B: Security Assumptions

1. The private signing key is stored securely and accessible only to authorized signers
2. The verifier has the correct public key for the claimed `signer-key-id`
3. The timestamp source (system clock) is accurate and protected from tampering
4. The transport layer (TLS) protects SPIF documents in transit against passive eavesdropping
5. The hash algorithm (SHA-256) remains collision-resistant (expected through ~2030)
6. The ed25519 signature scheme remains secure against classical attackers (~2030+ requires PQ migration)

## Appendix C: Change History

| Date | Version | Changes |
|---|---|---|
| 2026-07-18 | 1.0 | Initial threat model — covers crypt, tamper, replay, DoS, sidecar, key compromise |

---

*This threat model is a living document. Updates, corrections, and additions are welcome via issues and PRs. Security researchers: please report vulnerabilities confidentially to security@brainex.ai.*
