/**
 * SPIFWriter — serialize a SPIFDocument to bytes.
 */

import {
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
  FLAG_PROVENANCE,
  FLAG_SEMANTIC,
  FLAG_TRACE,
  FLAG_ALTS,
  FLAG_DELTA,
  FLAG_SIGNATURE,
  FLAG_MULTISIG,
  FLAG_COMPRESSED,
} from './format.js';
import type { SPIFDocument } from './types.js';
import { sha256Sync } from './checksum.js';
import { deflateSync } from 'zlib';
import {
  cborEncode,
  encodeNode,
  encodeStep,
  encodeEmbedding,
} from './cbor-utils.js';

// ---------------------------------------------------------------------------
// Chunk helpers
// ---------------------------------------------------------------------------

function makeChunk(chunkType: number, data: unknown, compress = false): Uint8Array {
  let payload = cborEncode(data);
  if (compress) {
    payload = new Uint8Array(deflateSync(payload));
  }
  return buildChunk(chunkType, payload);
}

function buildChunk(chunkType: number, payload: Uint8Array): Uint8Array {
  const header = new Uint8Array(5);
  const view = new DataView(header.buffer);
  header[0] = chunkType;
  view.setUint32(1, payload.length, false); // big-endian
  const out = new Uint8Array(5 + payload.length);
  out.set(header, 0);
  out.set(payload, 5);
  return out;
}

function makeRawChunk(chunkType: number, raw: Uint8Array): Uint8Array {
  return buildChunk(chunkType, raw);
}

// ---------------------------------------------------------------------------
// SPIFWriter
// ---------------------------------------------------------------------------

export class SPIFWriter {
  private readonly compress: boolean;

  constructor(options: { compress?: boolean } = {}) {
    this.compress = options.compress ?? false;
  }

  encode(doc: SPIFDocument): Uint8Array {
    let flags = 0;
    let flags2 = 0;
    if (doc.provenance) flags |= FLAG_PROVENANCE;
    if (doc.semantic) flags |= FLAG_SEMANTIC;
    if (doc.trace && doc.trace.length > 0) flags |= FLAG_TRACE;
    if (doc.alternatives && doc.alternatives.length > 0) flags |= FLAG_ALTS;
    if (doc.delta) flags |= FLAG_DELTA;
    if (doc.signature) flags |= FLAG_SIGNATURE;
    if (doc.signatures && doc.signatures.length > 0) flags |= FLAG_MULTISIG;
    if (this.compress) flags2 |= FLAG_COMPRESSED;

    const parts: Uint8Array[] = [];

    // Fixed header (10 bytes: 9 magic + 1 version + 1 flags)
    parts.push(MAGIC);
    parts.push(new Uint8Array([FORMAT_VERSION, flags]));

    // HEADER chunk
    parts.push(makeChunk(CHUNK_HEADER, {
      version: FORMAT_VERSION,
      flags,
      flags2,
      created_ms: doc.provenance?.timestamp_ms ?? 0,
    }));

    // PROVENANCE chunk
    if (doc.provenance) {
      const p = doc.provenance;
      parts.push(makeChunk(CHUNK_PROVENANCE, {
        source_model: p.source_model,
        model_version: p.model_version,
        temperature: p.temperature,
        input_hash: p.input_hash,
        context_ref: p.context_ref,
        timestamp_ms: p.timestamp_ms,
      }));
    }

    // SEMANTIC chunk
    if (doc.semantic) {
      const s = doc.semantic;
      parts.push(makeChunk(CHUNK_SEMANTIC, {
        embedding_model: s.embedding_model,
        dim: s.embedding.length,
        embedding: encodeEmbedding(s.embedding),
        covariance: s.covariance,
      }, this.compress));
    }

    // TRACE chunk (v0.2: wrapped with method)
    if (doc.trace && doc.trace.length > 0) {
      parts.push(makeChunk(CHUNK_TRACE, {
        method: doc.trace_method,
        steps: doc.trace.map(st => encodeStep(st)),
      }, this.compress));
    }

    // PAYLOAD chunk (required)
    parts.push(makeChunk(CHUNK_PAYLOAD, doc.payload.map(n => encodeNode(n)), this.compress));

    // ALTS chunk
    if (doc.alternatives && doc.alternatives.length > 0) {
      const alts = doc.alternatives;
      // Validate weights if normalized
      if (alts[0].normalized) {
        const total = alts.reduce((sum, a) => sum + a.weight, 0);
        if (Math.abs(total - 1.0) > 0.01) {
          throw new Error(
            `Alternative weights must sum to 1.0 ± 0.01 when normalized=true, got ${total.toFixed(4)}`
          );
        }
      }
      parts.push(makeChunk(CHUNK_ALTS, {
        normalized: alts[0].normalized,
        alts: alts.map(a => ({
          weight: a.weight,
          nodes: a.nodes.map(n => encodeNode(n)),
        })),
      }, this.compress));
    }

    // DELTA chunk
    if (doc.delta) {
      parts.push(makeChunk(CHUNK_DELTA, {
        base_hash: doc.delta.base_hash,
        changes: doc.delta.changes,
      }, this.compress));
    }

    // SIGNATURE chunk
    if (doc.signature) {
      const sig = doc.signature;
      parts.push(makeChunk(CHUNK_SIGNATURE, {
        algorithm: sig.algorithm,
        signer: sig.signer,
        signature: sig.signature,
        key_id: sig.key_id,
      }));
    }

    // MULTISIG chunk
    if (doc.signatures && doc.signatures.length > 0) {
      parts.push(makeChunk(CHUNK_MULTISIG, doc.signatures.map(s => ({
        algorithm: s.algorithm,
        signer: s.signer,
        signature: s.signature,
        key_id: s.key_id,
      }))));
    }

    // Concatenate all parts to compute checksum
    const totalBodyLength = parts.reduce((sum, p) => sum + p.length, 0);
    const body = new Uint8Array(totalBodyLength);
    let offset = 0;
    for (const part of parts) {
      body.set(part, offset);
      offset += part.length;
    }

    // CHECKSUM — raw SHA-256 bytes (not CBOR-encoded)
    const checksum = sha256Sync(body);
    const checksumChunk = makeRawChunk(CHUNK_CHECKSUM, checksum);

    // Final output
    const out = new Uint8Array(body.length + checksumChunk.length);
    out.set(body, 0);
    out.set(checksumChunk, body.length);
    return out;
  }
}
