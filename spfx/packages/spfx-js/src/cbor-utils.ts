/**
 * CBOR encoding/decoding utilities for SPIF.
 * Uses cbor-x for encoding and decoding with custom tag support.
 */

import { encode, decode, Tag } from 'cbor-x';
import type { Distribution, Node, TraceStep } from './types.js';
import {
  TAG_DISTRIBUTION,
  TAG_NODEREF,
  TAG_EMBEDDING,
  DIST_SEM_EPISTEMIC,
} from './format.js';

// ---------------------------------------------------------------------------
// Encoding
// ---------------------------------------------------------------------------

export function encodeDistribution(d: Distribution): Tag {
  const obj: Record<string, unknown> = {
    mean: d.mean,
    var: d.var,
    shape: d.shape,
    semantics: d.semantics,
  };
  if (d.p5 !== undefined) obj['p5'] = d.p5;
  if (d.p95 !== undefined) obj['p95'] = d.p95;
  return new Tag(obj, TAG_DISTRIBUTION);
}

export function encodeNodeRef(nodeId: string): Tag {
  return new Tag(nodeId, TAG_NODEREF);
}

export function encodeEmbedding(v: number[]): Tag {
  return new Tag(v, TAG_EMBEDDING);
}

export function encodeNode(n: Node): Record<string, unknown> {
  return {
    id: n.id,
    type: n.type,
    value: n.value,
    confidence: encodeDistribution(n.confidence),
    refs: n.refs.map(r => encodeNodeRef(r)),
  };
}

export function encodeStep(s: TraceStep): Record<string, unknown> {
  return {
    id: s.id,
    type: s.type,
    content: s.content,
    confidence: encodeDistribution(s.confidence),
    deps: s.deps,
    alternatives: s.alternatives,
  };
}

export function cborEncode(data: unknown): Uint8Array {
  return encode(data);
}

// ---------------------------------------------------------------------------
// Decoding
// ---------------------------------------------------------------------------

function resolveTag(tag: Tag): unknown {
  if (tag.tag === TAG_DISTRIBUTION) {
    const v = tag.value as Record<string, unknown>;
    const dist: Distribution = {
      mean: v['mean'] as number,
      var: (v['var'] as number) ?? 0.0,
      shape: (v['shape'] as string) ?? 'gaussian',
      semantics: (v['semantics'] as string) ?? DIST_SEM_EPISTEMIC,
    };
    if (v['p5'] !== undefined) dist.p5 = v['p5'] as number;
    if (v['p95'] !== undefined) dist.p95 = v['p95'] as number;
    return dist;
  }
  if (tag.tag === TAG_NODEREF) {
    // Return just the string node ID
    return tag.value as string;
  }
  if (tag.tag === TAG_EMBEDDING) {
    return tag.value;
  }
  return tag;
}

function resolveValue(v: unknown): unknown {
  if (v instanceof Tag) {
    return resolveTag(v);
  }
  if (Array.isArray(v)) {
    return v.map(resolveValue);
  }
  if (v !== null && typeof v === 'object' && !(v instanceof Uint8Array)) {
    const out: Record<string, unknown> = {};
    for (const [k, val] of Object.entries(v as Record<string, unknown>)) {
      out[k] = resolveValue(val);
    }
    return out;
  }
  return v;
}

export function cborDecode(data: Uint8Array): unknown {
  const raw = decode(data);
  return resolveValue(raw);
}

// ---------------------------------------------------------------------------
// Node/Step decoders
// ---------------------------------------------------------------------------

function isDistribution(v: unknown): v is Distribution {
  return (
    typeof v === 'object' &&
    v !== null &&
    'mean' in v &&
    'var' in v &&
    'shape' in v &&
    'semantics' in v
  );
}

export function decodeDistributionFromRaw(v: unknown): Distribution {
  if (isDistribution(v)) return v;
  if (v instanceof Tag && v.tag === TAG_DISTRIBUTION) {
    return resolveTag(v) as Distribution;
  }
  throw new Error(`Expected Distribution, got ${typeof v}`);
}

export function decodeNodeFromRaw(d: Record<string, unknown>): Node {
  const conf = d['confidence'];
  let confidence: Distribution;
  if (isDistribution(conf)) {
    confidence = conf;
  } else {
    confidence = decodeDistributionFromRaw(conf);
  }

  // refs may come in as strings (after NodeRef resolution) or raw Tags
  const rawRefs = (d['refs'] as unknown[]) ?? [];
  const refs: string[] = rawRefs.map(r => {
    if (typeof r === 'string') return r;
    if (r instanceof Tag && r.tag === TAG_NODEREF) return r.value as string;
    return String(r);
  });

  return {
    id: d['id'] as string,
    type: d['type'] as string,
    value: d['value'],
    confidence,
    refs,
  };
}

export function decodeStepFromRaw(d: Record<string, unknown>): TraceStep {
  const conf = d['confidence'];
  let confidence: Distribution;
  if (isDistribution(conf)) {
    confidence = conf;
  } else {
    confidence = decodeDistributionFromRaw(conf);
  }

  return {
    id: d['id'] as string,
    type: d['type'] as string,
    content: d['content'],
    confidence,
    deps: (d['deps'] as string[]) ?? [],
    alternatives: (d['alternatives'] as unknown[]) ?? [],
  };
}
