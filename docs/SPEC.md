# SPIF — Semantic Provenance Inference Format
## Specification v1.0

**MIME type:** `application/x-spif`  
**File extension:** `.spif`  
**Status:** v1.0 wire contract is locked and stable. All implementations MUST support reading v0.2 documents for backward compatibility.

---

## 1. Purpose

SPIF is a binary container format for AI-generated content. It co-locates the generated output with its provenance (which model, when, at what temperature), its uncertainty (per-node probability distributions), and its reasoning trace — in a single self-describing, integrity-verified document.

Design goals:
- **Verifiable**: SHA-256 checksum and optional ed25519 signature over the full document body
- **Typed uncertainty**: every content node carries a probability distribution, not just a confidence score
- **Streaming-native**: a stream reader can display tokens as they arrive; a file reader sees the complete document
- **Compact**: CBOR binary encoding with optional zlib compression
- **Interoperable**: readable by any implementation that follows this spec; CBOR is an IETF standard (RFC 8949)

---

## 2. File Layout

A SPIF document is a sequence of bytes with the following structure:

```
MAGIC (9 bytes)
VERSION (1 byte)
FLAGS (1 byte)
CHUNK...  (zero or more chunks)
CHECKSUM chunk (required, always last)
```

All multi-byte integers are **big-endian** unless otherwise noted.

### 2.1 Magic Bytes

```
\x89 S P I F \r \n \x1a \n
```

Nine bytes: `89 53 50 49 46 0D 0A 1A 0A`.

The pattern mirrors the PNG magic bytes. The leading `\x89` flags the file as binary to tools that inspect the first byte. The `\r\n\x1a\n` sequence detects common line-ending corruptions and rejects plain-text tools that might accidentally process binary files.

### 2.2 Version Byte

The wire format version is `0x02`. This is locked for v1.0 and will not change unless a non-backward-compatible breaking change is required (which would trigger v2.0).

Readers MUST support versions `0x01` and `0x02`. Readers encountering an unknown version MUST raise `SPIFVersionError` rather than attempting to parse.

**v0.1 compatibility**: Readers MUST gracefully handle v0.1 documents, which do not have:
- `flags2` field in the HEADER chunk
- `semantics` field in Distribution (default to `"epistemic"`)
- SIGNATURE / MULTISIG chunks
- STREAM_RESUME chunk

### 2.3 Flags Byte

A bitmask indicating which optional chunk types are present:

| Bit | Mask         | Meaning                                    |
|-----|--------------|--------------------------------------------|
| 0   | `0b00000001` | PROVENANCE chunk present                   |
| 1   | `0b00000010` | SEMANTIC chunk present                     |
| 2   | `0b00000100` | TRACE chunk present                        |
| 3   | `0b00001000` | ALTS chunk present                         |
| 4   | `0b00010000` | DELTA chunk present                        |
| 5   | `0b00100000` | SIGNATURE chunk present (v0.2+)            |
| 6   | `0b01000000` | MULTISIG chunk present (v0.2+)             |
| 7   | `0b10000000` | Streaming document (SSPIF, v0.2+)          |

Readers SHOULD use this byte to pre-allocate or fast-path. Readers MUST NOT rely on it for correctness — the ground truth is the chunk sequence itself.

---

## 3. Chunk Framing

Every chunk has the same 5-byte header:

```
chunk_type     (1 byte,  uint8)
payload_length (4 bytes, uint32 big-endian)
payload        (payload_length bytes)
```

The payload is a CBOR-encoded value (see §4), except CHECKSUM whose payload is raw bytes (see §6.11). Unknown chunk types MUST be skipped — forward compatibility requires this. A reader that rejects unknown chunk types is not conformant.

### 3.1 Chunk Type Registry

| ID     | Name           | Required | Compressible | Description                                      |
|--------|----------------|----------|--------------|--------------------------------------------------|
| `0x00` | HEADER         | Yes      | No           | Version, flags, creation timestamp              |
| `0x01` | PROVENANCE     | No       | No           | Source model, temperature, input hash           |
| `0x02` | SEMANTIC       | No       | Yes          | Dense embedding vector + covariance             |
| `0x03` | TRACE          | No       | Yes          | Reasoning trace DAG                             |
| `0x04` | PAYLOAD        | Yes      | Yes          | Content node array (the main output)            |
| `0x05` | ALTS           | No       | Yes          | Alternative payload hypotheses with weights     |
| `0x06` | DELTA          | No       | Yes          | Diff from a base document                       |
| `0x07` | SIGNATURE      | No       | No           | Single ed25519 signature (v0.2+)                |
| `0x08` | MULTISIG       | No       | No           | Multiple ed25519 signatures (v0.2+)             |
| `0x09` | TASK           | No       | No           | Task/run envelope metadata (v1.1)               |
| `0xFF` | CHECKSUM       | Yes      | No           | SHA-256 over all preceding bytes                |
| `0x10` | PARTIAL_TEXT   | No       | No           | Streaming text fragment (SSPIF only)            |
| `0x11` | STREAM_META    | No       | No           | Early stream metadata (SSPIF, reserved)         |
| `0x12` | STREAM_RESUME  | No       | No           | Resume point for dropped streams (SSPIF v0.2+)  |

IDs `0x0A`–`0x0F` and `0x13`–`0xFE` are reserved for future use. Readers MUST skip them.

### 3.2 Required Chunk Order

A conformant writer MUST emit chunks in this order:

```
MAGIC + VERSION + FLAGS
HEADER
[PROVENANCE]
[SEMANTIC]
[TRACE]
PAYLOAD
[ALTS]
[DELTA]
[SIGNATURE]
[MULTISIG]
CHECKSUM
```

Readers MUST NOT require this order but SHOULD process chunks in order of appearance. Missing a required chunk (HEADER, PAYLOAD, CHECKSUM) MUST raise `SPIFFormatError`.

---

## 4. CBOR Encoding

All chunk payloads are CBOR-encoded (RFC 8949), except CHECKSUM which is raw bytes. CBOR is used because it is:
- Compact (no field names in the wire format for arrays)
- Self-describing (tag numbers carry type information)
- Widely implemented

### 4.1 Canonical Mode

Chunks covered by an ed25519 signature MUST be encoded in **canonical CBOR** (RFC 8949 §4.2): map keys sorted by length then lexicographic, no indefinite-length items.

Unsigned documents MAY use non-canonical CBOR for ~10–15% faster encoding. Readers MUST accept both.

### 4.2 Custom CBOR Tags

SPIF reserves tag numbers 1000–1099 for its own types:

| Tag    | Name         | Value type              | Description                            |
|--------|--------------|-------------------------|----------------------------------------|
| `1000` | Distribution | CBOR map (see §5.1)     | Probability distribution over [0, 1]  |
| `1001` | NodeRef      | CBOR text string        | Reference to another node by `id`      |
| `1002` | Embedding    | CBOR array of float32   | Dense vector (semantic embedding)      |

Readers MUST resolve these tags to their typed representations. Unknown tags MUST be passed through unmodified.

---

## 5. Data Types

### 5.1 Distribution

Encoded as `CBOR tag 1000` wrapping a map:

```
{
  "mean":      float64    (required) — expected value, in [0.0, 1.0]
  "var":       float64    (required) — variance, >= 0
  "shape":     text       (required) — "gaussian" | "beta" | "bimodal" | "uniform" | "point"
  "semantics": text       (required in v0.2; defaults to "epistemic" for v0.1 compat)
  "p5":        float64    (optional) — 5th percentile
  "p95":       float64    (optional) — 95th percentile
}
```

**Semantics vocabulary** — what `mean` represents:

| Value                | Meaning                                                     |
|----------------------|-------------------------------------------------------------|
| `"epistemic"`        | Subjective confidence (most general; use when uncertain)   |
| `"factual_accuracy"` | P(claim is factually correct)                              |
| `"output_stability"` | P(model produces equivalent output on retry)               |
| `"token_probability"`| Mean per-token softmax probability (from logprobs)         |
| `"custom:<name>"`    | Application-specific; suppresses unknown-semantics warning |

Writers SHOULD use a known semantics value. Readers MUST accept unknown values without error.

### 5.2 Node

Encoded as a CBOR map:

```
{
  "id":         text           (required) — stable identifier within this document
  "type":       text           (required) — node type (see §5.3)
  "value":      any            (required) — content; type depends on node type
  "confidence": Distribution   (required) — uncertainty over this node's value
  "refs":       [NodeRef...]   (optional) — references to other nodes this depends on
}
```

### 5.3 Node Types

| Type            | `value` type    | Description                                              |
|-----------------|-----------------|----------------------------------------------------------|
| `"text"`        | text string     | Natural language text                                    |
| `"fact"`        | text string     | A factual claim                                          |
| `"code"`        | text string     | Source code                                              |
| `"concept"`     | text string     | Abstract concept or category label                       |
| `"multimodal"`  | bytes or map    | Binary payload (image, audio, etc.) or structured data   |
| `"tool_call"`   | map (see below) | AI tool/function invocation (v0.2+)                     |
| `"tool_result"` | map (see below) | Result of a tool invocation (v0.2+)                     |

**Tool call node value schema:**
```
{
  "name":      text   — function name
  "arguments": map    — JSON-compatible argument map
  "call_id":   text   — unique call identifier for correlation
}
```

**Tool result node value schema:**
```
{
  "call_id":    text    — matches the tool_call node's call_id
  "content":    any     — result value (may be any CBOR type)
  "is_error":   bool    — true if the tool returned an error
  "error_type": text    (optional, v1.1) — exception class name (e.g. "TimeoutError")
  "error_code": text    (optional, v1.1) — machine-readable error code constant
  "latency_ms": float64 (optional, v1.1) — tool execution time in milliseconds
}
```

**Standard `error_code` values (v1.1):** `"PermissionError"` | `"TimeoutError"` | `"RateLimitError"` | `"ValidationError"` | `"ConnectionError"`

Link a `"text"` response node to the tool results it consumed using `refs`.

### 5.4 TraceStep

Encoded as a CBOR map:

```
{
  "id":           text           (required) — stable identifier
  "type":         text           (required) — step type (see below)
  "content":      any            (required) — step description or structured data
  "confidence":   Distribution   (required) — confidence in this step
  "deps":         [text...]      (optional) — IDs of steps this depends on (DAG edges)
  "alternatives": [any...]       (optional) — other values considered for this step
}
```

**Step types:** `"hypothesis"` | `"evidence"` | `"inference"` | `"conclusion"`

The `deps` array forms a DAG. Writers MUST NOT produce cycles. Readers SHOULD validate acyclicity.

### 5.5 Provenance

Encoded as a CBOR map:

```
{
  "source_model":  text    (required) — model identifier (e.g. "claude-sonnet-4-6")
  "model_version": text    (optional) — specific version/revision
  "temperature":   float64 (optional) — sampling temperature used
  "input_hash":    text    (optional) — SHA-256 hex of the generating prompt
  "context_ref":   text    (optional) — content_id() of the preceding document (multi-turn)
  "timestamp_ms":  uint64  (required) — Unix epoch milliseconds of generation
  "attempt":       uint32  (optional, v1.1) — retry index; 0 = first attempt
  "task_id":       text    (optional, v1.1) — stable parent task identifier across retries
}
```

`attempt` and `task_id` are included in the `content_id()` hash so each retry produces a distinct document ID even if the payload is identical.

### 5.6 SemanticLayer

Encoded as a CBOR map:

```
{
  "embedding_model": text           (required) — coordinate system identifier
  "dim":             uint32         (required) — embedding dimensionality
  "embedding":       Embedding tag  (required) — dense float32 vector, length == dim
  "covariance":      [[float64...]] (optional) — dim×dim covariance matrix
}
```

### 5.7 Alternative

Within the ALTS chunk's `"alts"` array:

```
{
  "weight": float64    — probability weight
  "nodes":  [Node...]  — alternative payload
}
```

The ALTS chunk also carries a top-level `"normalized"` boolean. When `true`, weights MUST sum to `1.0 ± 0.01`. When `false`, weights are unnormalized scores.

### 5.8 Signature

Encoded as a CBOR map:

```
{
  "algorithm": text   (required) — "ed25519"
  "signer":    text   (required) — URL or stable identifier for the signing key
  "signature": bytes  (required) — raw 64-byte ed25519 signature
  "key_id":    text   (optional) — rotation hint or secondary key identifier
}
```

---

## 6. Chunk Payload Schemas

### 6.1 HEADER (`0x00`)

```
{
  "version":    uint8    — FORMAT_VERSION (currently 0x02)
  "flags":      uint8    — same flags byte as in the file header
  "flags2":     uint8    — extended flags (v0.2+; absent in v0.1)
  "created_ms": uint64   — document creation time (Unix epoch ms)
}
```

**Extended flags (`flags2`) bitmask:**

| Bit | Mask         | Meaning                                                      |
|-----|--------------|--------------------------------------------------------------|
| 0   | `0b00000001` | Chunk payloads are zlib-compressed (see §9)                  |
| 1   | `0b00000010` | Chunk payloads are zstd-compressed instead of zlib (v1.1)    |
| 2   | `0b00000100` | A TASK chunk (`0x09`) is present in this document (v1.1)     |

Bits 0 and 1 are mutually exclusive. If both are set the reader MUST raise `SPIFFormatError`.

### 6.2 PROVENANCE (`0x01`)

The Provenance map (§5.5). Never compressed — routers and validators may inspect it without decompressing the document.

### 6.3 SEMANTIC (`0x02`)

The SemanticLayer map (§5.6). May be compressed.

### 6.4 TRACE (`0x03`)

```
{
  "method": text           — trace production method (see below)
  "steps":  [TraceStep...] — ordered list of reasoning steps
}
```

**Trace methods:** `"post-hoc"` | `"live"` | `"verified"`

| Value        | Meaning                                                            |
|--------------|--------------------------------------------------------------------|
| `"post-hoc"` | Model narrates reasoning after producing output (most LLM CoT)    |
| `"live"`     | Trace generated simultaneously with output (tool calls, structured gen) |
| `"verified"` | Derived from model internals (mechanistic interpretability)        |

May be compressed.

### 6.5 PAYLOAD (`0x04`)

A CBOR array of Node maps (§5.2). MUST contain at least one node. May be compressed.

### 6.6 ALTS (`0x05`)

```
{
  "normalized": bool          — whether weights are probabilities (sum to 1.0)
  "alts": [Alternative...]    — array of alternatives
}
```

May be compressed.

### 6.7 DELTA (`0x06`)

```
{
  "base_hash": text      — content_id() of the base document (see §8)
  "changes":   [dict...] — list of application-defined change records
}
```

The schema of individual change records is application-defined. May be compressed.

### 6.8 SIGNATURE (`0x07`)

A single Signature map (§5.8). Never compressed. See §7 for signing protocol.

### 6.9 MULTISIG (`0x08`)

A CBOR array of Signature maps. Never compressed.

### 6.10 TASK (`0x09`) — v1.1

Task/run envelope metadata. Never compressed — monitoring infrastructure may inspect it without decompressing the document. Present only when `FLAG_HAS_TASK` (`flags2 & 0x04`) is set.

```
{
  "task_id":     text    (required) — stable identifier shared across retries of the same task
  "attempt":     uint32  (optional) — retry index (0 = first attempt)
  "status":      text    (optional) — "ok" | "failed" | "aborted"
  "total_ms":    uint64  (optional) — total wall-clock time for this attempt in milliseconds
  "tool_count":  uint32  (optional) — number of tool calls made
  "error_count": uint32  (optional) — number of tool calls that returned is_error=true
}
```

The TASK chunk MUST be emitted immediately after the HEADER chunk. Old readers (pre-v1.1) will skip it per the unknown-chunk-skip rule (§3.1).

### 6.11 CHECKSUM (`0xFF`)

Raw 32 bytes — SHA-256 digest. **Not CBOR-encoded.** The `payload_length` field will be exactly `32`. Readers MUST verify this and raise `SPIFFormatError` if the length differs.

---

## 7. Integrity and Authentication

### 7.1 Checksum

The CHECKSUM chunk payload is SHA-256 over every byte from the first byte of MAGIC through the last byte before the CHECKSUM chunk header:

```
checksum = SHA-256(MAGIC || VERSION || FLAGS || all_chunks_before_checksum)
```

Readers MUST verify this immediately after parsing the CHECKSUM chunk. A mismatch MUST raise `SPIFChecksumError`.

When `FLAG_COMPRESSED` is set (`flags2 & 0x01`), the checksum covers the **compressed** payloads. Decompression happens after verification.

### 7.2 Signature

The ed25519 signature covers the **signing body**: all bytes from MAGIC through the last byte before the first SIGNATURE or MULTISIG chunk. CHECKSUM is emitted after all authentication chunks and therefore covers the signature bytes as well.

```
signing_body = MAGIC || VERSION || FLAGS || <all chunks before first auth chunk>
signature = ed25519_sign(private_key, signing_body)
```

If both SIGNATURE and MULTISIG are present, every signature in both chunks MUST verify against the same `signing_body`, namely the bytes before the first authentication chunk.

Writers MUST use a two-pass approach:
1. Assemble the unsigned body (all chunks before SIGNATURE / MULTISIG)
2. Sign that unsigned body
3. Append SIGNATURE and/or MULTISIG chunks
4. Append CHECKSUM as the final chunk

Readers verify by locating the first SIGNATURE or MULTISIG chunk, taking all preceding bytes as `signing_body`, and calling `ed25519_verify(public_key, signing_body, sig.signature)` for every present signature.

`signer` SHOULD be a stable, publicly fetchable URL, e.g. `https://keys.anthropic.com/claude-sonnet-4-6.pub`.

### 7.3 Strict Mode

Readers SHOULD support a `require_signature=True` mode (also activatable via `SPIF_REQUIRE_SIGNATURE=1` environment variable) that rejects unsigned documents. Production AI pipelines SHOULD use strict mode.

```python
reader = SPIFReader.strict()        # Python
let reader = SPIFReader::strict();  // Rust
```

### 7.4 Key Management

Keys are managed outside the format. The `SPIFKeyStore` reference implementation stores raw 32-byte ed25519 public keys as `{key_id_slug}.pub` files in a directory, with `revoked.json` for revocation.

Production deployments SHOULD:
- Maintain a revocation list
- Rotate keys periodically via mnemonic-derived key generation
- Use the `signer` URL as the stable identifier in `Signature.signer`

---

## 8. Content Identity

`content_id()` returns a stable, content-addressed ID for a document:

```
content_id = SHA-256(canonical_CBOR({
  "payload":    [Node...],
  "trace":      [TraceStep...],
  "provenance": Provenance | null
}))
```

This hash is **independent** of: framing bytes, signatures, embeddings, alternatives, delta, and compression. Two documents with identical semantic content but different signatures produce the same `content_id`.

Use `content_id()` to populate `Provenance.context_ref` for multi-turn conversation chaining:

```python
response2 = adapter.complete("follow-up", context=response1)
# response2.provenance.context_ref == response1.content_id()
```

---

## 9. Compression

### 9.1 zlib (`FLAG_COMPRESSED`, `flags2 & 0x01`)

When `FLAG_COMPRESSED` is set in the HEADER chunk:

- The SEMANTIC, TRACE, PAYLOAD, ALTS, and DELTA chunk payloads are zlib-compressed (RFC 1950, level 9)
- HEADER, PROVENANCE, TASK, SIGNATURE, MULTISIG, and CHECKSUM are **never compressed**
- The `payload_length` field in each chunk header is the **compressed** length
- The SHA-256 checksum covers compressed payloads — readers verify before decompressing
- Readers auto-detect compression from `flags2`; callers do not need to signal it

Typical compression ratios: 40–70% reduction for large payloads, up to 93% for embedding-heavy documents with large semantic layers.

### 9.2 zstd (`FLAG_ZSTD`, `flags2 & 0x02`) — v1.1

When `FLAG_ZSTD` is set (and `FLAG_COMPRESSED` is not), the same set of chunk payloads are compressed with Zstandard (RFC 8878) at level 10. The same framing rules apply. Readers that encounter `FLAG_ZSTD` but do not have the `zstandard` library available MUST raise `SPIFFormatError` with a message indicating the missing dependency.

`FLAG_COMPRESSED` and `FLAG_ZSTD` MUST NOT both be set. Writers MUST set exactly one or neither.

---

## 10. Streaming Protocol (SSPIF)

When `FLAG_STREAMING` is set (`flags & 0b10000000`), the document was emitted token-by-token. A streaming document is a **valid SPIF document** — any v0.2 reader can parse it by skipping unknown chunks (`0x10`, `0x12`) and processing PAYLOAD + CHECKSUM normally.

### 10.1 Stream Wire Format

```
MAGIC + VERSION + FLAGS(|FLAG_STREAMING)
HEADER chunk
[PROVENANCE chunk]
[STREAM_RESUME chunk]       ← present only when resuming a dropped stream
PARTIAL_TEXT chunk...       ← one per token/fragment, seq starting at 0
PAYLOAD chunk
[TRACE / ALTS / DELTA chunks]
[SIGNATURE / MULTISIG chunks]
CHECKSUM chunk
```

### 10.2 PARTIAL_TEXT Chunk (`0x10`)

One chunk per generated token or text fragment:

```
{
  "node_id": text    — which payload node this fragment belongs to
  "seq":     uint32  — monotonically increasing, starting at 0; gaps allowed after resume
  "text":    text    — the text fragment
}
```

### 10.3 STREAM_RESUME Chunk (`0x12`)

Present only when a producer resumes a dropped connection. Emitted immediately after HEADER (and optional PROVENANCE):

```
{
  "seq":       uint32  — number of PARTIAL_TEXT chunks already confirmed by the consumer
  "body_hash": bytes   — SHA-256 of all stream bytes the consumer confirmed receiving
}
```

The PARTIAL_TEXT chunks that follow MUST start at `seq` (i.e. tokens 0 through `seq - 1` are not re-sent).

### 10.4 Resume Token Format

A resume token is a base64url string encoding 36 raw bytes:

```
bytes[0:4]  = seq (uint32, big-endian)
bytes[4:36] = SHA-256 of all stream bytes confirmed received
```

Example: after confirming `seq=3` tokens from a stream, the consumer computes a 36-byte token and base64url-encodes it (always exactly 48 characters, no padding).

### 10.5 Resume Protocol

1. Consumer calls `writer.resume_token()` after each received token and stores the result.
2. On reconnect, consumer sends the stored token to the producer out of band.
3. Producer creates `SPIFStreamWriter(resume_from=token)` and calls `open()`, which emits a STREAM_RESUME chunk.
4. Producer replays all tokens from index 0. `partial_text()` silently drops tokens whose seq is below the confirmed resume seq.
5. The resulting byte stream is a valid SPIF document readable by any conformant reader.

### 10.6 Stream Reader Events

| Event type      | Fields           | When emitted                                          |
|-----------------|------------------|-------------------------------------------------------|
| `"opened"`      | —                | Magic and header successfully parsed                  |
| `"resumed"`     | `seq`, `resume_token` | STREAM_RESUME chunk received                  |
| `"partial_text"`| `text`, `seq`, `node_id` | PARTIAL_TEXT chunk received                |
| `"verified"`    | `document`       | CHECKSUM verified; full SPIFDocument available        |
| `"error"`       | `error`          | Unrecoverable parse or integrity failure              |

After `"verified"` or `"error"`, further `feed()` calls return empty lists.

---

## 11. Version Negotiation

| Version | Changes from prior                                               |
|---------|------------------------------------------------------------------|
| `0x01`  | Initial: HEADER, PROVENANCE, SEMANTIC, TRACE, PAYLOAD, ALTS, DELTA, CHECKSUM |
| `0x02`  | SIGNATURE, MULTISIG; `flags2` in HEADER; Distribution `semantics`; FLAG_STREAMING; PARTIAL_TEXT, STREAM_RESUME; zlib compression; NODE_TOOL_CALL, NODE_TOOL_RESULT; content_id |
| v1.1†  | CHUNK_TASK (`0x09`); FLAG_ZSTD (`flags2 & 0x02`); FLAG_HAS_TASK (`flags2 & 0x04`); Provenance `attempt`/`task_id`; NODE_TOOL_RESULT `error_type`/`error_code`/`latency_ms` |

† v1.1 additions are backward-compatible extensions to wire format `0x02`. Old readers skip CHUNK_TASK and ignore unknown CBOR keys per the forward-compatibility rules.

Readers MUST support both versions. Writers SHOULD emit version `0x02`.

For v0.1 documents, readers MUST default `Distribution.semantics` to `"epistemic"` when the field is absent.

---

## 12. Conformance

### 12.1 Reader MUST

- Validate magic bytes; raise `SPIFMagicError` on mismatch
- Validate version byte; raise `SPIFVersionError` for unsupported versions
- Skip unknown chunk types without error
- Verify SHA-256 checksum; raise `SPIFChecksumError` on mismatch
- Resolve CBOR tags 1000, 1001, 1002 to their typed representations
- Accept both canonical and non-canonical CBOR

### 12.2 Reader SHOULD

- Support `require_signature=True` mode rejecting unsigned documents
- Honour `SPIF_REQUIRE_SIGNATURE=1` environment variable
- Validate PAYLOAD contains at least one node
- Validate the trace DAG is acyclic

### 12.3 Reader MAY

- Emit a `UserWarning` (not an error) for unknown `Distribution.semantics` values
- Cache documents by `content_id()`
- Accept v0.1 documents without `flags2` or `semantics` fields

### 12.4 Writer MUST

- Emit magic bytes exactly as specified
- Emit FORMAT_VERSION `0x02`
- Emit HEADER as the first chunk
- Emit PAYLOAD with at least one node
- Emit CHECKSUM as the last chunk
- Use canonical CBOR for all chunks when a signature is present
- Not emit SIGNATURE/MULTISIG after CHECKSUM

### 12.5 Writer SHOULD

- Populate PROVENANCE for AI-generated documents
- Set `FLAG_COMPRESSED` in `flags2` when compression is enabled
- Use known `Distribution.semantics` values

---

## 13. MIME Type and File Association

**MIME type:** `application/x-spif`  
**File extension:** `.spif`  
**Magic bytes:** `\x89SPIF\r\n\x1a\n`

HTTP responses serving SPIF documents SHOULD include:

```http
Content-Type: application/x-spif
```

---

## 14. Reference Implementations

| Language   | Location              | Status   |
|------------|-----------------------|----------|
| Python     | `spif/`               | Complete (alpha package) |
| Rust       | `spif-rust/`          | Complete |

The Python implementation is authoritative for format questions. Rust is
validated against the Python-generated compatibility fixtures for
v0.2 read/write/streaming/signature interoperability. When implementations
disagree on behavior, Python is correct.

### 14.1 Test Vectors

The Python test suite (`spif/tests/`) serves as executable format tests:

| File                       | Coverage                                              |
|----------------------------|-------------------------------------------------------|
| `test_roundtrip.py`        | Encode/decode parity for all chunk types and options  |
| `test_security.py`         | Tamper detection, signature verification              |
| `test_streaming.py`        | SSPIF protocol including resume (44 tests)            |
| `test_keystore.py`         | Key management and revocation                         |
| `test_fuzz.py`             | Property-based tests via Hypothesis                   |

---

## Appendix A: Minimal Document Example

Binary layout of the smallest valid SPIF document (unsigned, no provenance, one node):

```
89 53 50 49 46 0D 0A 1A 0A   -- magic: \x89SPIF\r\n\x1a\n
02                            -- version 0x02
00                            -- flags: no optional layers
00 <4-byte len> <CBOR map>   -- HEADER chunk
04 <4-byte len> <CBOR array> -- PAYLOAD chunk
FF 00 00 00 20 <32 bytes>    -- CHECKSUM chunk (type=0xFF, length=32, SHA-256)
```

The PAYLOAD CBOR array contains one map:

```
[{
  "id":         "n1",
  "type":       "fact",
  "value":      "Paris",
  "confidence": tag(1000, {
                  "mean": 0.99, "var": 0.01,
                  "shape": "point", "semantics": "epistemic"
                }),
  "refs":       []
}]
```

---

## Appendix B: Changelog

**v0.2** (current):
- SIGNATURE (`0x07`) and MULTISIG (`0x08`) chunks for ed25519 authentication
- `flags2` extended flags field in HEADER chunk
- `FLAG_COMPRESSED` (`flags2 & 0x01`) for zlib payload compression
- `semantics` field added to Distribution; four standard vocabulary values
- `FLAG_STREAMING` and PARTIAL_TEXT (`0x10`) for token-streaming
- STREAM_RESUME (`0x12`) for connection resumption with resume tokens
- `NODE_TOOL_CALL` and `NODE_TOOL_RESULT` node types for agent pipelines
- `content_id()` for stable content-addressed document identity
- `context_ref` in Provenance for multi-turn conversation chaining

**v0.1** (initial):
- Core format: HEADER, PROVENANCE, SEMANTIC, TRACE, PAYLOAD, ALTS, DELTA, CHECKSUM
- CBOR encoding with custom tags 1000–1002
- SHA-256 checksum integrity
