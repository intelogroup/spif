/**
 * Binary format constants for SPIF — Semantic Provenance Inference Format.
 */

// Magic bytes: \x89SPIF\r\n\x1a\n  (mirrors PNG magic byte pattern)
export const MAGIC = new Uint8Array([0x89, 0x53, 0x50, 0x49, 0x46, 0x0d, 0x0a, 0x1a, 0x0a]);

export const FORMAT_VERSION = 0x02;

// Chunk type IDs
export const CHUNK_HEADER = 0x00;
export const CHUNK_PROVENANCE = 0x01;
export const CHUNK_SEMANTIC = 0x02;
export const CHUNK_TRACE = 0x03;
export const CHUNK_PAYLOAD = 0x04;
export const CHUNK_ALTS = 0x05;
export const CHUNK_DELTA = 0x06;
export const CHUNK_SIGNATURE = 0x07;   // ed25519 signature over body (v0.2+)
export const CHUNK_MULTISIG = 0x08;    // list of ed25519 signatures (v0.2+)
export const CHUNK_CHECKSUM = 0xff;

// Streaming-only chunk types (0x10-0x1F reserved for SSPIF)
export const CHUNK_PARTIAL_TEXT = 0x10;   // Incremental text fragment (one per token)
export const CHUNK_STREAM_META = 0x11;    // Early metadata emitted before first token

export const CHUNK_NAMES: Record<number, string> = {
  [CHUNK_HEADER]: 'HEADER',
  [CHUNK_PROVENANCE]: 'PROVENANCE',
  [CHUNK_SEMANTIC]: 'SEMANTIC',
  [CHUNK_TRACE]: 'TRACE',
  [CHUNK_PAYLOAD]: 'PAYLOAD',
  [CHUNK_ALTS]: 'ALTS',
  [CHUNK_DELTA]: 'DELTA',
  [CHUNK_SIGNATURE]: 'SIGNATURE',
  [CHUNK_MULTISIG]: 'MULTISIG',
  [CHUNK_CHECKSUM]: 'CHECKSUM',
  [CHUNK_PARTIAL_TEXT]: 'PARTIAL_TEXT',
  [CHUNK_STREAM_META]: 'STREAM_META',
};

// Flags bitmask (1 byte) — which optional layers are present
export const FLAG_PROVENANCE = 0b00000001;
export const FLAG_SEMANTIC = 0b00000010;
export const FLAG_TRACE = 0b00000100;
export const FLAG_ALTS = 0b00001000;
export const FLAG_DELTA = 0b00010000;
export const FLAG_SIGNATURE = 0b00100000;   // v0.2+
export const FLAG_MULTISIG = 0b01000000;    // v0.2+: multiple signatures
export const FLAG_STREAMING = 0b10000000;   // SSIF: document was emitted as a stream

// Extended HEADER flags (flags2)
export const FLAG_COMPRESSED = 0b00000001;  // v0.2+: zlib-compressed payload-bearing chunks

// Custom CBOR tags (range 1000-1099 reserved for SPIF)
export const TAG_DISTRIBUTION = 1000;  // Distribution: {mean, var, shape, semantics, p5, p95}
export const TAG_NODEREF = 1001;       // Reference to another node by ID: str
export const TAG_EMBEDDING = 1002;     // Dense float vector: [f32, ...]

// Node types
export const NODE_TEXT = 'text';
export const NODE_CODE = 'code';
export const NODE_FACT = 'fact';
export const NODE_CONCEPT = 'concept';
export const NODE_MULTIMODAL = 'multimodal';

// Trace step types
export const STEP_HYPOTHESIS = 'hypothesis';
export const STEP_EVIDENCE = 'evidence';
export const STEP_INFERENCE = 'inference';
export const STEP_CONCLUSION = 'conclusion';

// Distribution shapes
export const DIST_GAUSSIAN = 'gaussian';
export const DIST_BETA = 'beta';
export const DIST_BIMODAL = 'bimodal';
export const DIST_UNIFORM = 'uniform';
export const DIST_POINT = 'point';

// Distribution semantics (v0.2) — what the probability represents
export const DIST_SEM_FACTUAL = 'factual_accuracy';    // P(claim is factually correct)
export const DIST_SEM_STABILITY = 'output_stability';  // P(model produces equivalent output again)
export const DIST_SEM_EPISTEMIC = 'epistemic';          // Subjective confidence (default)

// Trace methods (v0.2) — how the trace was produced
export const TRACE_POSTHOC = 'post-hoc';   // model narrates reasoning after output
export const TRACE_LIVE = 'live';           // trace generated simultaneously
export const TRACE_VERIFIED = 'verified';  // derived from model internals

export const SUPPORTED_VERSIONS = new Set([0x01, 0x02]);
