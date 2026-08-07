# SPIF CBOR Data Definition Language (CDDL) Schema

**Specification:** SPIF v1.0 — RFC 8610 CDDL  
**File:** `CDDL.md`  
**Status:** Companion to `SPEC.md` — machine-parseable schema of all CBOR-encoded chunk payloads

---

## 1. Conventions

This schema describes the CBOR payloads inside each SPIF chunk (chunk_type → payload). The chunk framing (magic bytes, version, flags, 5-byte chunk header) is defined in `SPEC.md` and is **not** represented in CDDL — CDDL covers only the CBOR-encoded payload bytes.

All multi-byte integers are big-endian per the SPIF spec. Deterministic CBOR encoding (RFC 8949 §4.2) MUST be used to ensure signature stability across implementations.

---

## 2. Chunk Payload CDDL

### 2.1 HEADER Chunk (0x00)

```cddl
spif-header = {
  spif-version: uint .size 1,         ; 0x02 for v1.0
  creation-timestamp: tdate,           ; RFC 3339 string, e.g. "2026-07-18T23:08:00Z"
  ? flags2: uint .size 1,             ; v0.2+ extension flags (reserved)
  * $$spif-header-extension           ; extensible for future fields
}
```

### 2.2 PROVENANCE Chunk (0x01)

```cddl
provenance-chunk = {
  model-id: tstr,                      ; e.g. "claude-3.5-sonnet-20241022"
  model-version: tstr,                 ; e.g. "20241022"
  generation-timestamp: tdate,
  ? attempt: uint,                     ; retry attempt number
  ? task-id: tstr,                     ; correlation / trace ID
  ? risk-tier: "low" / "medium" / "high" / "critical",
  ? model-card: tstr .uri,             ; URL to model card
  ? agent-id: tstr,                    ; identifier of the calling agent
  ? session-id: tstr,                  ; conversation / session identifier
  ? input-hash: bytes .size 32,        ; SHA-256 of the input prompt
  ? output-hash: bytes .size 32,       ; SHA-256 of the raw output before wrapping
  * $$provenance-extension
}
```

### 2.3 SEMANTIC Chunk (0x02)

```cddl
semantic-chunk = {
  embedding: [* float64],              ; dense embedding vector
  ? covariance: [* [* float64]],       ; covariance matrix (n x n)
  ? model: tstr,                       ; embedding model ID
  ? dimension: uint,                   ; vector dimensionality (redundant with embedding length, but explicit)
  * $$semantic-extension
}
```

### 2.4 TRACE Chunk (0x03)

```cddl
trace-chunk = {
  nodes: { * trace-node-id => trace-node },
  ? edges: [* trace-edge],
  ? root: trace-node-id,
  * $$trace-extension
}

trace-node-id = tstr                   ; unique node identifier within this trace

trace-node = {
  type: "reasoning" / "tool_call" / "observation" / "thought" / "plan" / "reflection",
  content: tstr,
  ? parent: trace-node-id,
  ? children: [* trace-node-id],
  ? confidence: float16,               ; 0.0 – 1.0
  ? token-count: uint,
  ? duration-ms: uint,
  ? tool-name: tstr,                   ; present when type = "tool_call"
  ? tool-input: any,                   ; input to the tool (any valid CBOR)
  ? tool-output: any,                  ; output from the tool
  * $$trace-node-extension
}

trace-edge = {
  from: trace-node-id,
  to: trace-node-id,
  label: tstr,
  ? weight: float16,
  * $$trace-edge-extension
}
```

### 2.5 PAYLOAD Chunk (0x04)

```cddl
payload-chunk = {
  nodes: { * uint => content-node },
  ? distribution-type: "categorical" / "gaussian" / "dirichlet" / "empirical",
  * $$payload-extension
}

content-node = {
  content: tstr,                       ; the actual generated text (or base64 for binary)
  ? role: "system" / "user" / "assistant" / "tool" / "function",
  ? mime-type: tstr,                   ; e.g. "text/markdown", "image/png", "application/json"
  ? index: uint,                       ; ordinal position in the output sequence
  ? confidence: float16,               ; 0.0 – 1.0
  ? token-probability: [* float16],    ; per-token log probabilities or probabilities
  ? entropy: float32,                  ; Shannon entropy of this node's probability distribution
  ? uncertainty: "low" / "medium" / "high" / "unknown",
  ? sequence: uint,                    ; for streaming: the token sequence number
  ? semantics: "epistemic" / "aleatoric" / "both",
  ? metadata: { * tstr => any },       ; arbitrary key-value extensions
  * $$content-node-extension
}
```

### 2.6 ALTS Chunk (0x05) — Alternative Hypotheses

```cddl
alts-chunk = {
  alternatives: [* alt-hypothesis],
  ? selection-strategy: "top_k" / "top_p" / "beam" / "nucleus" / "manual",
  * $$alts-extension
}

alt-hypothesis = {
  payload: [* content-node],           ; same structure as PAYLOAD nodes
  weight: float16,                     ; probability weight (sum of all weights ≈ 1.0)
  ? rationale: tstr,                   ; why this alternative was generated
  ? rank: uint,                        ; explicit ranking
  * $$alt-hypothesis-extension
}
```

### 2.7 DELTA Chunk (0x06)

```cddl
delta-chunk = {
  base-document-id: tstr,              ; identifier of the base SPIF document
  changes: [* delta-operation],
  ? base-checksum: bytes .size 32,     ; SHA-256 of the base document for verification
  * $$delta-extension
}

delta-operation = {
  op: "replace" / "insert" / "delete" / "append",
  path: tstr,                          ; JSON Pointer or CBOR path to the target
  ? value: any,                        ; new value (for replace/insert/append)
  ? index: uint,                       ; insertion index (for insert/delete on arrays)
  * $$delta-operation-extension
}
```

### 2.8 SIGNATURE Chunk (0x07)

```cddl
signature-chunk = {
  algorithm: "ed25519" / "ed448" / "ecdsa-p256" / "ecdsa-p384",
  signer-key-id: tstr,                 ; public key fingerprint or identifier
  signature: bytes,                    ; raw signature bytes (length depends on algorithm)
  ? signing-time: tdate,               ; when the signature was generated
  ? key-derivation: {
    algorithm: "pbkdf2-hmac-sha512",
    iterations: uint,
    salt: bytes,
  },
  ? tee-attestation: bytes,            ; optional TEE/Nitro/SEV attestation quote
  ? hash-algorithm: "sha-256" / "sha-384" / "sha-512",
  ? metadata: { * tstr => any },
  * $$signature-extension
}
```

### 2.9 MULTISIG Chunk (0x08)

```cddl
multisig-chunk = {
  signatures: [* signature-entry],
  ? policy: multisig-policy,
  * $$multisig-extension
}

signature-entry = {
  algorithm: "ed25519" / "ed448" / "ecdsa-p256" / "ecdsa-p384",
  signer-key-id: tstr,
  signature: bytes,
  ? signing-time: tdate,
  ? role: tstr,                        ; e.g. "model", "reviewer", "policy-enforcer", "auditor"
  ? tee-attestation: bytes,
  ? metadata: { * tstr => any },
  * $$signature-entry-extension
}

multisig-policy = {
  threshold: uint,                     ; minimum number of valid signatures required
  ? required-roles: [* tstr],          ; roles that MUST sign
  ? timeout-seconds: uint,             ; max age for signature collection
  * $$multisig-policy-extension
}
```

### 2.10 STREAM_RESUME Chunk (0x09) — SSPIF (Streaming)

```cddl
stream-resume-chunk = {
  previous-checksum: bytes .size 32,   ; SHA-256 of the previous segment's body
  segment-number: uint,                ; monotonically increasing segment counter
  ? total-segments: uint,              ; known only at the end, MAY be absent mid-stream
  * $$stream-resume-extension
}
```

### 2.11 CHECKSUM Chunk (0xFF)

```cddl
checksum-chunk = bytes .size 32       ; RAW SHA-256 hash (NOT CBOR-wrapped)
```

---

## 3. Complete Document (Informative)

A valid SPIF document (non-streaming) in schematic form:

```cddl
spif-document = [
  magic: h'89535049460D0A1A0A',        ; not CBOR, shown for reference
  version: 0x02,                        ; not CBOR
  flags: uint .size 1,                  ; bitmask, not CBOR
  chunks: spif-chunks,
]

spif-chunks = [
  header: spif-header,
  ? provenance: provenance-chunk,
  ? semantic: semantic-chunk,
  ? trace: trace-chunk,
  payload: payload-chunk,
  ? alts: alts-chunk,
  ? delta: delta-chunk,
  ? signature: signature-chunk,
  ? multisig: multisig-chunk,
  ? stream-resume: stream-resume-chunk,
  checksum: checksum-chunk,            ; MUST be last
]
```

---

## 4. Tag Assignments

The following CBOR tags are reserved for SPIF:

| Tag  | Semantics        | Applies To                    |
|------|------------------|-------------------------------|
| 1000 | Distribution     | Payload node probability dist |
| 1001 | NodeRef          | Reference to another node     |
| 1002 | Embedding        | Dense embedding vector        |

These tags MUST be registered with IANA in a future revision.

---

## 5. Validation Rules (Beyond CDDL)

The following invariants MUST hold and cannot be expressed in CDDL:

1. **Checksum coverage**: The CHECKSUM chunk payload is the SHA-256 of all bytes preceding the CHECKSUM chunk (including magic, version, flags, and all prior chunks).

2. **Signature coverage**: The SIGNATURE/MULTISIG chunk signature is over all bytes preceding the first authentication chunk (SIGNATURE or MULTISIG). The signature chunk itself is NOT covered.

3. **Checksum covers signature**: The CHECKSUM chunk covers the SIGNATURE/MULTISIG chunk bytes (they appear before CHECKSUM in the stream).

4. **DAG acyclicity**: The TRACE chunk's node/edge graph MUST be acyclic. Readers MUST reject cycles.

5. **Timestamp ordering**: When multiple signatures are present, `signing-time` SHOULD be monotonically non-decreasing.

6. **Flag consistency**: The FLAGS byte MUST be consistent with the actual chunks present, but readers MUST NOT reject a document solely on flag mismatch (the chunk sequence is the ground truth).

---

## 6. Test Vectors

Test vectors are published alongside this schema in `/test_vectors/`:

| File | Description |
|------|-------------|
| `test_vectors/valid_basic.cddl.json` | CBOR diagnostic output of a minimal valid document |
| `test_vectors/valid_full.cddl.json` | CBOR diagnostic of a document with all chunk types |
| `test_vectors/invalid_bad_checksum.cddl.json` | Document with intentionally corrupted checksum |
| `test_vectors/invalid_cycle_trace.cddl.json` | Trace with a deliberate cycle (must be rejected) |

Every SPIF implementation MUST pass all test vectors before claiming v1.0 conformance.

---

*Companion to SPEC.md — last updated 2026-07-18*
