/**
 * Core TypeScript interfaces for SPIF — Semantic Provenance Inference Format.
 */

export interface Distribution {
  mean: number;        // [0.0, 1.0]
  var: number;         // >= 0.0
  shape: string;       // "gaussian" | "beta" | "point" | etc.
  semantics: string;   // "epistemic" | "factual_accuracy" | "output_stability" | etc.
  p5?: number;
  p95?: number;
}

export interface Node {
  id: string;
  type: string;         // "text" | "fact" | "code" | "concept" | "multimodal"
  value: unknown;       // string for text nodes
  confidence: Distribution;
  refs: string[];       // node IDs (decoded from Tag(1001, str))
}

export interface TraceStep {
  id: string;
  type: string;
  content: unknown;
  confidence: Distribution;
  deps: string[];
  alternatives: unknown[];
}

export interface Provenance {
  source_model: string;
  model_version: string;
  temperature: number;
  input_hash: string;
  context_ref: string;
  timestamp_ms: number;
}

export interface SemanticLayer {
  embedding: number[];
  embedding_model: string;
  covariance: number[][];
}

export interface Alternative {
  weight: number;
  nodes: Node[];
  normalized: boolean;
}

export interface Delta {
  base_hash: string;
  changes: unknown;
}

export interface Signature {
  algorithm: string;
  signer: string;
  signature: Uint8Array;
  key_id: string;
}

export interface SPIFDocument {
  payload: Node[];
  provenance?: Provenance;
  semantic?: SemanticLayer;
  trace: TraceStep[];
  trace_method: string;
  alternatives: Alternative[];
  delta?: Delta;
  signature?: Signature;
  signatures: Signature[];
}

// Helper to create a Distribution with certain confidence
export function certainDistribution(semantics = 'epistemic'): Distribution {
  return { mean: 1.0, var: 0.0, shape: 'point', semantics };
}

// Helper to create an empty SPIFDocument
export function emptyDocument(payload: Node[]): SPIFDocument {
  return {
    payload,
    trace: [],
    trace_method: 'post-hoc',
    alternatives: [],
    signatures: [],
  };
}
