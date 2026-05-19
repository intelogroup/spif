/**
 * SPIF Streaming (SSPIF) — incremental delivery protocol.
 *
 * Wire format (strict superset of the SPIF file format):
 *   MAGIC + VERSION(0x02) + FLAGS(|FLAG_STREAMING)
 *   HEADER chunk
 *   [PROVENANCE chunk]           -- emitted at open() if model info is known
 *   PARTIAL_TEXT(0x10) chunk...  -- one per token/fragment during generation
 *   PAYLOAD(0x04) chunk          -- commit point — full assembled content
 *   [TRACE / ALTS / DELTA chunks]
 *   CHECKSUM(0xFF) chunk         -- SHA-256 trailer over ALL preceding bytes
 */

import {
  MAGIC,
  FORMAT_VERSION,
  CHUNK_HEADER,
  CHUNK_PROVENANCE,
  CHUNK_PAYLOAD,
  CHUNK_TRACE,
  CHUNK_ALTS,
  CHUNK_DELTA,
  CHUNK_SIGNATURE,
  CHUNK_MULTISIG,
  CHUNK_CHECKSUM,
  CHUNK_PARTIAL_TEXT,
  FLAG_PROVENANCE,
  FLAG_TRACE,
  FLAG_ALTS,
  FLAG_DELTA,
  FLAG_SIGNATURE,
  FLAG_MULTISIG,
  FLAG_STREAMING,
} from './format.js';
import type { SPIFDocument, Provenance } from './types.js';
import { sha256Sync } from './checksum.js';
import { cborEncode, encodeNode, encodeStep, cborDecode } from './cbor-utils.js';
import { SPIFReader } from './reader.js';

// ---------------------------------------------------------------------------
// Chunk helpers (mirrors writer.ts but inline for streaming independence)
// ---------------------------------------------------------------------------

function makeChunk(chunkType: number, data: unknown): Uint8Array {
  const payload = cborEncode(data);
  const header = new Uint8Array(5);
  const view = new DataView(header.buffer);
  header[0] = chunkType;
  view.setUint32(1, payload.length, false);
  const out = new Uint8Array(5 + payload.length);
  out.set(header, 0);
  out.set(payload, 5);
  return out;
}

function makeRawChunk(chunkType: number, raw: Uint8Array): Uint8Array {
  const header = new Uint8Array(5);
  const view = new DataView(header.buffer);
  header[0] = chunkType;
  view.setUint32(1, raw.length, false);
  const out = new Uint8Array(5 + raw.length);
  out.set(header, 0);
  out.set(raw, 5);
  return out;
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((s, p) => s + p.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

// ---------------------------------------------------------------------------
// Events
// ---------------------------------------------------------------------------

export type StreamEvent =
  | { type: 'opened' }
  | { type: 'partial_text'; nodeId: string; text: string; seq: number }
  | { type: 'committed' }
  | { type: 'verified'; document: SPIFDocument }
  | { type: 'error'; error: string };

// ---------------------------------------------------------------------------
// Stream Writer
// ---------------------------------------------------------------------------

export class SPIFStreamWriter {
  private body: Uint8Array[] = [];
  private seq = 0;
  private opened = false;
  private committed = false;

  open(provenance?: Provenance): Uint8Array {
    if (this.opened) throw new Error('SPIFStreamWriter.open() called twice');
    this.opened = true;

    let flags = FLAG_STREAMING;
    if (provenance) flags |= FLAG_PROVENANCE;

    const ts = provenance?.timestamp_ms ?? Date.now();

    const parts: Uint8Array[] = [
      MAGIC,
      new Uint8Array([FORMAT_VERSION, flags]),
      makeChunk(CHUNK_HEADER, {
        version: FORMAT_VERSION,
        flags,
        flags2: 0,
        created_ms: ts,
      }),
    ];

    if (provenance) {
      parts.push(makeChunk(CHUNK_PROVENANCE, {
        source_model: provenance.source_model,
        model_version: provenance.model_version,
        temperature: provenance.temperature,
        input_hash: provenance.input_hash,
        context_ref: provenance.context_ref,
        timestamp_ms: provenance.timestamp_ms,
      }));
    }

    const data = concat(...parts);
    this.body.push(data);
    return data;
  }

  partialText(text: string, nodeId = 'main'): Uint8Array {
    this.requireOpen();
    const data = makeChunk(CHUNK_PARTIAL_TEXT, {
      node_id: nodeId,
      seq: this.seq,
      text,
    });
    this.seq++;
    this.body.push(data);
    return data;
  }

  commit(doc: SPIFDocument): Uint8Array {
    this.requireOpen();
    if (this.committed) throw new Error('SPIFStreamWriter.commit() called twice');
    this.committed = true;

    const tailParts: Uint8Array[] = [];

    // PAYLOAD (required)
    tailParts.push(makeChunk(CHUNK_PAYLOAD, doc.payload.map(n => encodeNode(n))));

    // TRACE
    if (doc.trace && doc.trace.length > 0) {
      tailParts.push(makeChunk(CHUNK_TRACE, {
        method: doc.trace_method,
        steps: doc.trace.map(s => encodeStep(s)),
      }));
    }

    // ALTS
    if (doc.alternatives && doc.alternatives.length > 0) {
      tailParts.push(makeChunk(CHUNK_ALTS, {
        normalized: doc.alternatives[0].normalized,
        alts: doc.alternatives.map(a => ({
          weight: a.weight,
          nodes: a.nodes.map(n => encodeNode(n)),
        })),
      }));
    }

    // DELTA
    if (doc.delta) {
      tailParts.push(makeChunk(CHUNK_DELTA, {
        base_hash: doc.delta.base_hash,
        changes: doc.delta.changes,
      }));
    }

    // SIGNATURE
    if (doc.signature) {
      const sig = doc.signature;
      tailParts.push(makeChunk(CHUNK_SIGNATURE, {
        algorithm: sig.algorithm,
        signer: sig.signer,
        signature: sig.signature,
        key_id: sig.key_id,
      }));
    }

    // MULTISIG
    if (doc.signatures && doc.signatures.length > 0) {
      tailParts.push(makeChunk(CHUNK_MULTISIG, doc.signatures.map(s => ({
        algorithm: s.algorithm,
        signer: s.signer,
        signature: s.signature,
        key_id: s.key_id,
      }))));
    }

    const tail = concat(...tailParts);
    this.body.push(tail);

    // CHECKSUM over complete body so far
    const fullBody = concat(...this.body);
    const checksum = sha256Sync(fullBody);
    const checksumChunk = makeRawChunk(CHUNK_CHECKSUM, checksum);

    return concat(tail, checksumChunk);
  }

  assembled(): Uint8Array {
    if (!this.committed) throw new Error('Call commit() first');
    return concat(...this.body);
  }

  private requireOpen(): void {
    if (!this.opened) throw new Error('Call open() before writing chunks');
    if (this.committed) throw new Error('Stream already committed');
  }
}

// ---------------------------------------------------------------------------
// Stream Reader
// ---------------------------------------------------------------------------

export class SPIFStreamReader {
  private buf: Uint8Array[] = [];
  private bufLen = 0;
  private pos = 0;
  private state: 'header' | 'chunks' | 'done' = 'header';
  private requireSignature: boolean;

  constructor(options: { requireSignature?: boolean } = {}) {
    this.requireSignature = options.requireSignature ?? false;
  }

  get done(): boolean {
    return this.state === 'done';
  }

  feed(data: Uint8Array): StreamEvent[] {
    if (this.state === 'done') return [];

    // Append to buffer
    this.buf.push(data);
    this.bufLen += data.length;

    const events: StreamEvent[] = [];
    this.pump(events);
    return events;
  }

  private getFlat(): Uint8Array {
    if (this.buf.length === 1) return this.buf[0];
    const merged = new Uint8Array(this.bufLen);
    let off = 0;
    for (const chunk of this.buf) {
      merged.set(chunk, off);
      off += chunk.length;
    }
    this.buf = [merged];
    return merged;
  }

  private pump(events: StreamEvent[]): void {
    const buf = this.getFlat();

    if (this.state === 'header') {
      if (buf.length < MAGIC.length + 2) return;

      // Validate magic
      for (let i = 0; i < MAGIC.length; i++) {
        if (buf[i] !== MAGIC[i]) {
          events.push({
            type: 'error',
            error: `Invalid magic bytes: ${Buffer.from(buf.subarray(0, MAGIC.length)).toString('hex')}`,
          });
          this.state = 'done';
          return;
        }
      }

      this.pos = MAGIC.length + 2;
      this.state = 'chunks';
      events.push({ type: 'opened' });
    }

    while (this.state === 'chunks') {
      if (this.pos + 5 > buf.length) return;

      const chunkType = buf[this.pos];
      const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
      const chunkLen = view.getUint32(this.pos + 1, false);
      const payloadStart = this.pos + 5;
      const payloadEnd = payloadStart + chunkLen;

      if (payloadEnd > buf.length) return; // wait for more data

      const payload = buf.subarray(payloadStart, payloadEnd);
      this.dispatch(chunkType, payload, payloadEnd, events, buf);
      this.pos = payloadEnd;
    }
  }

  private dispatch(
    chunkType: number,
    payload: Uint8Array,
    payloadEnd: number,
    events: StreamEvent[],
    buf: Uint8Array,
  ): void {
    if (chunkType === CHUNK_PARTIAL_TEXT) {
      try {
        const d = cborDecode(payload) as Record<string, unknown>;
        events.push({
          type: 'partial_text',
          nodeId: (d['node_id'] as string) ?? 'main',
          text: (d['text'] as string) ?? '',
          seq: (d['seq'] as number) ?? 0,
        });
      } catch (e) {
        events.push({
          type: 'error',
          error: `Malformed PARTIAL_TEXT chunk: ${e instanceof Error ? e.message : String(e)}`,
        });
        this.state = 'done';
      }
    } else if (chunkType === CHUNK_CHECKSUM) {
      // Stream complete — decode full accumulated buffer
      const fullBytes = buf.subarray(0, payloadEnd);
      try {
        const reader = new SPIFReader({ requireSignature: this.requireSignature });
        const doc = reader.decode(fullBytes);
        events.push({ type: 'verified', document: doc });
      } catch (e) {
        events.push({
          type: 'error',
          error: e instanceof Error ? e.message : String(e),
        });
      }
      this.state = 'done';
    }
    // All other chunks are silently buffered
  }
}
