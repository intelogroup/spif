/**
 * SPIFReader — deserialize bytes into a SPIFDocument.
 */

import {
  MAGIC,
  SUPPORTED_VERSIONS,
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
  FLAG_COMPRESSED,
  TAG_NODEREF,
  TRACE_POSTHOC,
} from './format.js';
import type {
  SPIFDocument,
  Node,
  TraceStep,
  Provenance,
  SemanticLayer,
  Alternative,
  Delta,
  Signature,
} from './types.js';
import {
  SPIFMagicError,
  SPIFVersionError,
  SPIFChecksumError,
  SPIFSignatureError,
  SPIFFormatError,
} from './errors.js';
import { sha256Sync, timingSafeEqual } from './checksum.js';
import { cborDecode, decodeNodeFromRaw, decodeStepFromRaw } from './cbor-utils.js';
import { Tag } from 'cbor-x';
import { createPublicKey, verify as verifySignatureRaw } from 'crypto';
import { inflateSync } from 'zlib';

// ---------------------------------------------------------------------------
// Chunk iteration
// ---------------------------------------------------------------------------

interface Chunk {
  type: number;
  data: Uint8Array;
  offset: number; // byte offset of the chunk header in the original buffer
}

function* iterChunks(data: Uint8Array, offset: number): Generator<Chunk> {
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  while (offset < data.length) {
    if (offset + 5 > data.length) {
      throw new SPIFFormatError('Truncated chunk header');
    }
    const chunkType = data[offset];
    const length = view.getUint32(offset + 1, false); // big-endian
    const payloadStart = offset + 5;
    const payloadEnd = payloadStart + length;
    if (payloadEnd > data.length) {
      throw new SPIFFormatError(
        `Chunk 0x${chunkType.toString(16).padStart(2, '0')} claims ${length} bytes but only ${data.length - payloadStart} remain`
      );
    }
    yield {
      type: chunkType,
      data: data.subarray(payloadStart, payloadEnd),
      offset,
    };
    offset = payloadEnd;
  }
}

// ---------------------------------------------------------------------------
// DAG validation
// ---------------------------------------------------------------------------

function validateTraceDAG(steps: TraceStep[]): void {
  const seen = new Set<string>();
  for (const s of steps) {
    if (seen.has(s.id)) {
      throw new SPIFFormatError(`Duplicate TraceStep id: '${s.id}'`);
    }
    seen.add(s.id);
  }

  const ids = new Set(steps.map(s => s.id));
  for (const s of steps) {
    for (const dep of s.deps) {
      if (!ids.has(dep)) {
        throw new SPIFFormatError(
          `TraceStep '${s.id}' references unknown dep '${dep}'`
        );
      }
    }
  }

  // Kahn's algorithm to detect cycles
  const inDegree = new Map<string, number>(steps.map(s => [s.id, 0]));
  const dependents = new Map<string, string[]>(steps.map(s => [s.id, []]));

  for (const s of steps) {
    for (const dep of s.deps) {
      inDegree.set(s.id, (inDegree.get(s.id) ?? 0) + 1);
      dependents.get(dep)!.push(s.id);
    }
  }

  const queue: string[] = [];
  for (const [id, deg] of inDegree) {
    if (deg === 0) queue.push(id);
  }

  let visited = 0;
  while (queue.length > 0) {
    const node = queue.shift()!;
    visited++;
    for (const child of dependents.get(node) ?? []) {
      const deg = (inDegree.get(child) ?? 0) - 1;
      inDegree.set(child, deg);
      if (deg === 0) queue.push(child);
    }
  }

  if (visited !== steps.length) {
    const cycleMembers = [...inDegree.entries()]
      .filter(([, deg]) => deg > 0)
      .map(([id]) => id);
    throw new SPIFFormatError(
      `Cycle detected in trace DAG involving steps: ${cycleMembers.join(', ')}`
    );
  }
}

// ---------------------------------------------------------------------------
// Safe CBOR loader
// ---------------------------------------------------------------------------

function cborLoad(data: Uint8Array, chunkName: string, compressed = false): unknown {
  try {
    const raw = compressed ? new Uint8Array(inflateSync(data)) : data;
    return cborDecode(raw);
  } catch (e) {
    throw new SPIFFormatError(
      `Malformed CBOR in ${chunkName} chunk: ${e instanceof Error ? e.message : String(e)}`
    );
  }
}

function findFirstAuthChunkOffset(data: Uint8Array): number | null {
  let offset = MAGIC.length + 2;
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);

  while (offset < data.length) {
    if (offset + 5 > data.length) return null;
    const chunkType = data[offset];
    const length = view.getUint32(offset + 1, false);
    if (chunkType === CHUNK_SIGNATURE || chunkType === CHUNK_MULTISIG) {
      return offset;
    }
    if (chunkType === CHUNK_CHECKSUM) {
      return null;
    }
    offset += 5 + length;
  }

  return null;
}

const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

// ---------------------------------------------------------------------------
// Main reader
// ---------------------------------------------------------------------------

export class SPIFReader {
  private requireSignature: boolean;

  constructor(options: { requireSignature?: boolean } = {}) {
    this.requireSignature = options.requireSignature ?? false;
  }

  decode(data: Uint8Array): SPIFDocument {
    // 1. Validate magic
    if (data.length < MAGIC.length + 2) {
      throw new SPIFMagicError('File too short to be a SPIF document');
    }
    for (let i = 0; i < MAGIC.length; i++) {
      if (data[i] !== MAGIC[i]) {
        throw new SPIFMagicError(
          `Bad magic bytes: ${Buffer.from(data.subarray(0, MAGIC.length)).toString('hex')} (expected ${Buffer.from(MAGIC).toString('hex')})`
        );
      }
    }

    const version = data[MAGIC.length];
    if (!SUPPORTED_VERSIONS.has(version)) {
      throw new SPIFVersionError(`Unsupported SPIF version: ${version}`);
    }

    // 2. Find CHECKSUM chunk
    let checksumOffset: number | null = null;
    let scanOffset = MAGIC.length + 2;
    const scanView = new DataView(data.buffer, data.byteOffset, data.byteLength);

    while (scanOffset < data.length) {
      if (scanOffset + 5 > data.length) break;
      const chunkType = data[scanOffset];
      const length = scanView.getUint32(scanOffset + 1, false);
      if (chunkType === CHUNK_CHECKSUM) {
        checksumOffset = scanOffset;
        break;
      }
      scanOffset += 5 + length;
    }

    if (checksumOffset === null) {
      throw new SPIFFormatError('No CHECKSUM chunk found');
    }

    // 3. Validate checksum
    const body = data.subarray(0, checksumOffset);
    const csumLen = scanView.getUint32(checksumOffset + 1, false);
    const storedChecksum = data.subarray(checksumOffset + 5, checksumOffset + 5 + csumLen);
    const computed = sha256Sync(body);

    if (!timingSafeEqual(storedChecksum, computed)) {
      throw new SPIFChecksumError(
        `Checksum mismatch: stored=${Buffer.from(storedChecksum).toString('hex')}, computed=${Buffer.from(computed).toString('hex')}`
      );
    }

    // 4. Parse all chunks up to CHECKSUM
    const chunks = new Map<number, Uint8Array[]>();
    for (const chunk of iterChunks(data, MAGIC.length + 2)) {
      if (chunk.type === CHUNK_CHECKSUM) break;
      if (!chunks.has(chunk.type)) chunks.set(chunk.type, []);
      chunks.get(chunk.type)!.push(chunk.data);
    }

    let compressed = false;
    if (chunks.has(CHUNK_HEADER)) {
      const header = cborLoad(chunks.get(CHUNK_HEADER)![0], 'HEADER') as Record<string, unknown>;
      if (typeof header !== 'object' || header === null || Array.isArray(header)) {
        throw new SPIFFormatError('HEADER chunk must decode to a dict');
      }
      compressed = (((header['flags2'] as number) ?? 0) & FLAG_COMPRESSED) !== 0;
    }

    // 5. PAYLOAD (required)
    if (!chunks.has(CHUNK_PAYLOAD)) {
      throw new SPIFFormatError('Missing required PAYLOAD chunk');
    }

    const rawPayload = cborLoad(chunks.get(CHUNK_PAYLOAD)![0], 'PAYLOAD', compressed);
    if (!Array.isArray(rawPayload)) {
      throw new SPIFFormatError('PAYLOAD chunk must decode to a list');
    }
    const payload: Node[] = rawPayload.map((n: unknown) =>
      decodeNodeFromRaw(n as Record<string, unknown>)
    );

    if (payload.length === 0) {
      throw new SPIFFormatError('PAYLOAD must contain at least one node');
    }

    // 6. PROVENANCE
    let provenance: Provenance | undefined;
    if (chunks.has(CHUNK_PROVENANCE)) {
      const p = cborLoad(chunks.get(CHUNK_PROVENANCE)![0], 'PROVENANCE') as Record<string, unknown>;
      if (typeof p !== 'object' || p === null || Array.isArray(p)) {
        throw new SPIFFormatError('PROVENANCE chunk must decode to a dict');
      }
      provenance = {
        source_model: (p['source_model'] as string) ?? '',
        model_version: (p['model_version'] as string) ?? '',
        temperature: (p['temperature'] as number) ?? 0.0,
        input_hash: (p['input_hash'] as string) ?? '',
        context_ref: (p['context_ref'] as string) ?? '',
        timestamp_ms: (p['timestamp_ms'] as number) ?? 0,
      };
    }

    // 7. SEMANTIC
    let semantic: SemanticLayer | undefined;
    if (chunks.has(CHUNK_SEMANTIC)) {
      const s = cborLoad(chunks.get(CHUNK_SEMANTIC)![0], 'SEMANTIC', compressed) as Record<string, unknown>;
      if (typeof s !== 'object' || s === null || Array.isArray(s)) {
        throw new SPIFFormatError('SEMANTIC chunk must decode to a dict');
      }
      const emb = (s['embedding'] as number[]) ?? [];
      semantic = {
        embedding: emb,
        embedding_model: (s['embedding_model'] as string) ?? '',
        covariance: (s['covariance'] as number[][]) ?? [],
      };
    }

    // 8. TRACE (v0.2: wrapped dict; v0.1: bare list)
    let trace: TraceStep[] = [];
    let traceMethod = TRACE_POSTHOC;
    if (chunks.has(CHUNK_TRACE)) {
      const raw = cborLoad(chunks.get(CHUNK_TRACE)![0], 'TRACE', compressed);
      if (Array.isArray(raw)) {
        // v0.1 format: bare list of steps
        trace = raw.map((st: unknown) => decodeStepFromRaw(st as Record<string, unknown>));
      } else {
        // v0.2 format: {method, steps}
        const rawObj = raw as Record<string, unknown>;
        traceMethod = (rawObj['method'] as string) ?? TRACE_POSTHOC;
        trace = ((rawObj['steps'] as unknown[]) ?? []).map((st: unknown) =>
          decodeStepFromRaw(st as Record<string, unknown>)
        );
      }
    }

    // DAG validation
    if (trace.length > 0) {
      validateTraceDAG(trace);
    }

    // 9. ALTS (v0.2: wrapped dict; v0.1: bare list)
    const alternatives: Alternative[] = [];
    if (chunks.has(CHUNK_ALTS)) {
      const raw = cborLoad(chunks.get(CHUNK_ALTS)![0], 'ALTS', compressed);
      if (Array.isArray(raw)) {
        // v0.1 format
        for (const a of raw as Array<Record<string, unknown>>) {
          alternatives.push({
            weight: a['weight'] as number,
            nodes: (a['nodes'] as Array<Record<string, unknown>>).map(decodeNodeFromRaw),
            normalized: true,
          });
        }
      } else {
        // v0.2 format: {normalized, alts}
        const rawObj = raw as Record<string, unknown>;
        const normalized = (rawObj['normalized'] as boolean) ?? true;
        for (const a of (rawObj['alts'] as Array<Record<string, unknown>>) ?? []) {
          alternatives.push({
            weight: a['weight'] as number,
            nodes: (a['nodes'] as Array<Record<string, unknown>>).map(decodeNodeFromRaw),
            normalized,
          });
        }
        // Validate weights if normalized
        if (normalized && alternatives.length > 0) {
          const total = alternatives.reduce((sum, a) => sum + a.weight, 0);
          if (Math.abs(total - 1.0) > 0.01) {
            throw new SPIFFormatError(
              `ALTS normalized=True but weights sum to ${total.toFixed(4)}, expected 1.0 ± 0.01`
            );
          }
        }
      }
    }

    // 10. DELTA
    let delta: Delta | undefined;
    if (chunks.has(CHUNK_DELTA)) {
      const d = cborLoad(chunks.get(CHUNK_DELTA)![0], 'DELTA', compressed) as Record<string, unknown>;
      if (typeof d !== 'object' || d === null || Array.isArray(d)) {
        throw new SPIFFormatError('DELTA chunk must decode to a dict');
      }
      delta = {
        base_hash: d['base_hash'] as string,
        changes: d['changes'],
      };
    }

    // 11. SIGNATURE (v0.2)
    let signature: Signature | undefined;
    if (chunks.has(CHUNK_SIGNATURE)) {
      const s = cborLoad(chunks.get(CHUNK_SIGNATURE)![0], 'SIGNATURE') as Record<string, unknown>;
      if (typeof s !== 'object' || s === null || Array.isArray(s)) {
        throw new SPIFFormatError('SIGNATURE chunk must decode to a dict');
      }
      let sigBytes = s['signature'];
      if (sigBytes instanceof Tag) sigBytes = sigBytes.value;
      if (!(sigBytes instanceof Uint8Array)) {
        sigBytes = new Uint8Array(sigBytes as ArrayBuffer);
      }
      signature = {
        algorithm: (s['algorithm'] as string) ?? 'ed25519',
        signer: (s['signer'] as string) ?? '',
        signature: sigBytes as Uint8Array,
        key_id: (s['key_id'] as string) ?? '',
      };
    }

    // 12. MULTISIG (v0.2+)
    const signatures: Signature[] = [];
    if (chunks.has(CHUNK_MULTISIG)) {
      const raw = cborLoad(chunks.get(CHUNK_MULTISIG)![0], 'MULTISIG');
      if (!Array.isArray(raw)) {
        throw new SPIFFormatError('MULTISIG chunk must decode to a list');
      }
      for (const s of raw as Array<Record<string, unknown>>) {
        let sigBytes = s['signature'];
        if (sigBytes instanceof Tag) sigBytes = sigBytes.value;
        if (!(sigBytes instanceof Uint8Array)) {
          sigBytes = new Uint8Array(sigBytes as ArrayBuffer);
        }
        signatures.push({
          algorithm: (s['algorithm'] as string) ?? 'ed25519',
          signer: (s['signer'] as string) ?? '',
          signature: sigBytes as Uint8Array,
          key_id: (s['key_id'] as string) ?? '',
        });
      }
    }

    const doc: SPIFDocument = {
      payload,
      provenance,
      semantic,
      trace,
      trace_method: traceMethod,
      alternatives,
      delta,
      signature,
      signatures,
    };

    if (this.requireSignature) {
      if (!doc.signature && doc.signatures.length === 0) {
        throw new SPIFSignatureError(
          'Document is unsigned. SPIFReader was created with requireSignature=true'
        );
      }
      this.verifySignaturesInternal(data, doc);
    }

    return doc;
  }

  private verifySignaturesInternal(data: Uint8Array, doc: SPIFDocument): boolean {
    const signatures: Signature[] = [];
    if (doc.signature) signatures.push(doc.signature);
    signatures.push(...doc.signatures);

    if (signatures.length === 0) {
      return false;
    }

    const authOffset = findFirstAuthChunkOffset(data);
    if (authOffset === null) {
      throw new SPIFSignatureError(
        'Document advertises signature data but no SIGNATURE/MULTISIG chunk was found before CHECKSUM'
      );
    }
    const bodyToSign = Buffer.from(data.subarray(0, authOffset));

    for (const sig of signatures) {
      if (sig.algorithm !== 'ed25519') {
        throw new SPIFSignatureError(
          `Unsupported signature algorithm '${sig.algorithm}'; only ed25519 is supported`
        );
      }

      try {
        const rawPublicKey = Buffer.from(sig.signer, 'base64');
        if (rawPublicKey.length !== 32) {
          throw new Error('signer public key must decode to 32 bytes');
        }
        const publicKey = createPublicKey({
          key: Buffer.concat([ED25519_SPKI_PREFIX, rawPublicKey]),
          format: 'der',
          type: 'spki',
        });
        const ok = verifySignatureRaw(null, bodyToSign, publicKey, Buffer.from(sig.signature));
        if (!ok) {
          throw new Error('invalid signature');
        }
      } catch (e) {
        throw new SPIFSignatureError(
          `Signature verification failed: ${e instanceof Error ? e.message : String(e)}`
        );
      }
    }

    return true;
  }

  verifySignature(data: Uint8Array): boolean {
    const doc = this.decode(data);
    return this.verifySignaturesInternal(data, doc);
  }
}
