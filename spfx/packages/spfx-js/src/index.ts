/**
 * spif-js — TypeScript implementation of SPIF (Semantic Provenance Inference Format)
 *
 * @module spif-js
 */

// Types
export type {
  Distribution,
  Node,
  TraceStep,
  Provenance,
  SemanticLayer,
  Alternative,
  Delta,
  Signature,
  SPIFDocument,
} from './types.js';
export { certainDistribution, emptyDocument } from './types.js';

// Format constants
export {
  MAGIC,
  FORMAT_VERSION,
  CHUNK_HEADER,
  CHUNK_PROVENANCE,
  CHUNK_SEMANTIC,
  CHUNK_TRACE,
  CHUNK_PAYLOAD,
  CHUNK_ALTS,
  CHUNK_DELTA,
  CHUNK_SIGNATURE,
  CHUNK_MULTISIG,
  CHUNK_CHECKSUM,
  CHUNK_PARTIAL_TEXT,
  CHUNK_STREAM_META,
  CHUNK_NAMES,
  FLAG_PROVENANCE,
  FLAG_SEMANTIC,
  FLAG_TRACE,
  FLAG_ALTS,
  FLAG_DELTA,
  FLAG_SIGNATURE,
  FLAG_MULTISIG,
  FLAG_STREAMING,
  FLAG_COMPRESSED,
  TAG_DISTRIBUTION,
  TAG_NODEREF,
  TAG_EMBEDDING,
  NODE_TEXT,
  NODE_CODE,
  NODE_FACT,
  NODE_CONCEPT,
  NODE_MULTIMODAL,
  STEP_HYPOTHESIS,
  STEP_EVIDENCE,
  STEP_INFERENCE,
  STEP_CONCLUSION,
  DIST_GAUSSIAN,
  DIST_BETA,
  DIST_BIMODAL,
  DIST_UNIFORM,
  DIST_POINT,
  DIST_SEM_FACTUAL,
  DIST_SEM_STABILITY,
  DIST_SEM_EPISTEMIC,
  TRACE_POSTHOC,
  TRACE_LIVE,
  TRACE_VERIFIED,
  SUPPORTED_VERSIONS,
} from './format.js';

// Errors
export {
  SPIFError,
  SPIFMagicError,
  SPIFVersionError,
  SPIFChecksumError,
  SPIFSignatureError,
  SPIFFormatError,
} from './errors.js';

// Reader
export { SPIFReader } from './reader.js';

// Writer
export { SPIFWriter } from './writer.js';

// Streaming
export type { StreamEvent } from './streaming.js';
export { SPIFStreamWriter, SPIFStreamReader } from './streaming.js';

// Adapters
export type { Message, OpenAIAdapterOptions } from './adapters/openai.js';
export { OpenAISPIFAdapter } from './adapters/openai.js';
