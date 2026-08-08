"""
Binary format constants for SPIF — Semantic Provenance Inference Format.

⚠️  FROZEN FOR v1.0
These constants define the wire format specification and MUST NOT be changed.
Changing any value will break backward compatibility.

If a change is necessary, it requires:
1. New major version (v2.0)
2. New FORMAT_VERSION byte
3. Implementation of parallel wire format support

Readers MUST support all previous versions (v0.1, v0.2) indefinitely.
"""

# Magic bytes: \x89SPIF\r\n\x1a\n  (mirrors PNG magic byte pattern)
# FROZEN: Do not change. Identifies all SPIF files.
MAGIC = b"\x89SPIF\r\n\x1a\n"

# Wire format version. v0.2 is locked for v1.0 release.
# History:
#   0x01: Initial release (v0.1)
#   0x02: Added signature support, trace method, distribution semantics (v0.2/v1.0)
FORMAT_VERSION = 0x02

# Chunk type IDs
CHUNK_HEADER     = 0x00
CHUNK_PROVENANCE = 0x01
CHUNK_SEMANTIC   = 0x02
CHUNK_TRACE      = 0x03
CHUNK_PAYLOAD    = 0x04
CHUNK_ALTS       = 0x05
CHUNK_DELTA      = 0x06
CHUNK_SIGNATURE  = 0x07   # ed25519 signature over body (v0.2+)
CHUNK_MULTISIG   = 0x08   # list of ed25519 signatures (v0.2+)
CHUNK_TASK       = 0x09   # task/run envelope — attempt, status, tool counts (v1.1+)
CHUNK_CHECKSUM      = 0xFF

# Streaming-only chunk types (0x10-0x1F reserved for SSPIF)
CHUNK_PARTIAL_TEXT   = 0x10  # Incremental text fragment (one per token)
CHUNK_STREAM_META    = 0x11  # Early metadata emitted before first token
CHUNK_STREAM_RESUME  = 0x12  # Resume point: seq + sha256 of bytes confirmed received

CHUNK_NAMES = {
    CHUNK_HEADER:     "HEADER",
    CHUNK_PROVENANCE: "PROVENANCE",
    CHUNK_SEMANTIC:   "SEMANTIC",
    CHUNK_TRACE:      "TRACE",
    CHUNK_PAYLOAD:    "PAYLOAD",
    CHUNK_ALTS:       "ALTS",
    CHUNK_DELTA:      "DELTA",
    CHUNK_SIGNATURE:  "SIGNATURE",
    CHUNK_MULTISIG:   "MULTISIG",
    CHUNK_TASK:       "TASK",
    CHUNK_CHECKSUM:      "CHECKSUM",
    CHUNK_PARTIAL_TEXT:   "PARTIAL_TEXT",
    CHUNK_STREAM_META:    "STREAM_META",
    CHUNK_STREAM_RESUME:  "STREAM_RESUME",
}

# Flags bitmask (1 byte) — which optional layers are present
FLAG_PROVENANCE  = 0b00000001
FLAG_SEMANTIC    = 0b00000010
FLAG_TRACE       = 0b00000100
FLAG_ALTS        = 0b00001000
FLAG_DELTA       = 0b00010000
FLAG_SIGNATURE   = 0b00100000   # v0.2+
FLAG_MULTISIG    = 0b01000000   # v0.2+: multiple signatures
FLAG_STREAMING   = 0b10000000   # SSIF: document was emitted as a stream

# Extended flags byte 2 (reserved for future use; stored in HEADER chunk)
FLAG_COMPRESSED  = 0b00000001   # v0.2+: chunk payloads are zlib-compressed
                                 # PROVENANCE and CHECKSUM are never compressed
FLAG_ZSTD        = 0b00000010   # v1.1+: zstd compression instead of zlib (requires zstandard pkg)
FLAG_HAS_TASK    = 0b00000100   # v1.1+: TASK chunk (0x09) is present

# Custom CBOR tags (range 1000-1099 reserved for SPIF)
TAG_DISTRIBUTION = 1000  # Distribution: {mean, var, shape, semantics, p5, p95}
TAG_NODEREF      = 1001  # Reference to another node by ID: str
TAG_EMBEDDING    = 1002  # Dense float vector: [f32, ...]

# Node types
NODE_TEXT        = "text"
NODE_CODE        = "code"
NODE_FACT        = "fact"
NODE_CONCEPT     = "concept"
NODE_MULTIMODAL  = "multimodal"
# Agent/tool-use nodes (v0.2) — value is a dict with the fields below
# NODE_TOOL_CALL value schema:   {"name": str, "arguments": dict, "call_id": str}
# NODE_TOOL_RESULT value schema: {"call_id": str, "content": Any, "is_error": bool,
#   "error_type": str (opt), "error_code": int (opt), "latency_ms": float (opt)}
# Link response text to the tool results it consumed via Node.refs.

# Tool error type constants — use in NODE_TOOL_RESULT value["error_type"]
TOOL_ERROR_PERMISSION  = "PermissionError"
TOOL_ERROR_TIMEOUT     = "TimeoutError"
TOOL_ERROR_RATE_LIMIT  = "RateLimitError"
TOOL_ERROR_VALIDATION  = "ValidationError"
TOOL_ERROR_CONNECTION  = "ConnectionError"
NODE_TOOL_CALL   = "tool_call"
NODE_TOOL_RESULT = "tool_result"

# Trace step types
STEP_HYPOTHESIS = "hypothesis"
STEP_EVIDENCE   = "evidence"
STEP_INFERENCE  = "inference"
STEP_CONCLUSION = "conclusion"

# Distribution shapes
DIST_GAUSSIAN = "gaussian"
DIST_BETA     = "beta"
DIST_BIMODAL  = "bimodal"
DIST_UNIFORM  = "uniform"
DIST_POINT    = "point"

# Distribution semantics (v0.2) — what the probability represents
DIST_SEM_FACTUAL    = "factual_accuracy"   # P(claim is factually correct)
DIST_SEM_STABILITY  = "output_stability"   # P(model produces equivalent output again)
DIST_SEM_EPISTEMIC  = "epistemic"          # Subjective confidence (default / most general)
DIST_SEM_TOKEN_PROB = "token_probability"  # Mean per-token softmax probability (from logprobs)

# Set of all known semantics strings — used for UserWarning on unknown values
KNOWN_DIST_SEMANTICS = frozenset({
    DIST_SEM_FACTUAL,
    DIST_SEM_STABILITY,
    DIST_SEM_EPISTEMIC,
    DIST_SEM_TOKEN_PROB,
})

# Trace method (v0.2) — how the trace was produced
TRACE_POSTHOC  = "post-hoc"   # model narrates reasoning after output (most LLM CoT)
TRACE_LIVE     = "live"       # trace generated simultaneously (tool calls, structured gen)
TRACE_VERIFIED = "verified"   # derived from model internals (mechanistic interpretability)
