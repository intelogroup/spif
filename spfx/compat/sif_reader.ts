/**
 * A4 — Minimal SIF reader in TypeScript/Deno.
 *
 * Validates cross-implementation compatibility: files written by the Python
 * writer must be fully parseable by this independent implementation.
 *
 * Covers: magic validation, chunk framing, checksum, CBOR decoding,
 * custom tag resolution (Distribution tag 1000, NodeRef tag 1001, Embedding tag 1002).
 *
 * Usage: deno run --allow-read compat/sif_reader.ts <file.sif>
 */

// Deno CBOR: use cbor-x via npm specifier or a pure-TS CBOR impl.
// We use the npm:cbor-x package via Deno npm compatibility.
// deno run --allow-read --allow-net compat/sif_reader.ts file.sif

// ---------------------------------------------------------------------------
// Constants (must match sif/format.py exactly)
// ---------------------------------------------------------------------------

const MAGIC = new Uint8Array([0x89, 0x53, 0x49, 0x46, 0x0d, 0x0a, 0x1a, 0x0a]);
const SUPPORTED_VERSIONS = new Set([0x01, 0x02]);

const CHUNK_HEADER     = 0x00;
const CHUNK_PROVENANCE = 0x01;
const CHUNK_SEMANTIC   = 0x02;
const CHUNK_TRACE      = 0x03;
const CHUNK_PAYLOAD    = 0x04;
const CHUNK_ALTS       = 0x05;
const CHUNK_DELTA      = 0x06;
const CHUNK_CHECKSUM   = 0xFF;

const CHUNK_NAMES: Record<number, string> = {
  [CHUNK_HEADER]:     "HEADER",
  [CHUNK_PROVENANCE]: "PROVENANCE",
  [CHUNK_SEMANTIC]:   "SEMANTIC",
  [CHUNK_TRACE]:      "TRACE",
  [CHUNK_PAYLOAD]:    "PAYLOAD",
  [CHUNK_ALTS]:       "ALTS",
  [CHUNK_DELTA]:      "DELTA",
  [CHUNK_CHECKSUM]:   "CHECKSUM",
};

const TAG_DISTRIBUTION = 1000;
const TAG_NODEREF      = 1001;
const TAG_EMBEDDING    = 1002;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface Distribution {
  _type: "Distribution";
  mean: number;
  var: number;
  shape: string;
  p5?: number;
  p95?: number;
}

interface NodeRef {
  _type: "NodeRef";
  node_id: string;
}

interface SIFNode {
  id: string;
  type: string;
  value: unknown;
  confidence: Distribution;
  refs: NodeRef[];
}

interface TraceStep {
  id: string;
  type: string;
  content: unknown;
  confidence: Distribution;
  deps: string[];
  alternatives: unknown[];
}

interface Provenance {
  source_model: string;
  model_version?: string;
  temperature: number;
  input_hash?: string;
  timestamp_ms?: number;
}

interface SIFDocument {
  payload: SIFNode[];
  trace: TraceStep[];
  provenance?: Provenance;
  semanticDim?: number;
  alternativeCount?: number;
  deltaBaseHash?: string;
}

// ---------------------------------------------------------------------------
// CBOR decoder (minimal pure-TS implementation for the types SIF uses)
// ---------------------------------------------------------------------------

class CBORDecoder {
  private view: DataView;
  private offset: number;

  constructor(data: Uint8Array) {
    this.view = new DataView(data.buffer, data.byteOffset, data.byteLength);
    this.offset = 0;
  }

  decode(): unknown {
    const initialByte = this.view.getUint8(this.offset++);
    const majorType = (initialByte >> 5) & 0x07;
    const additionalInfo = initialByte & 0x1f;

    // Handle majorType 7 (float/simple) before decodeArg — float cases
    // use additionalInfo as a type tag, not a length, so decodeArg must not run.
    if (majorType === 7) {
      if (additionalInfo === 20) return false;
      if (additionalInfo === 21) return true;
      if (additionalInfo === 22) return null;
      if (additionalInfo === 25) {
        const v = this.decodeFloat16(this.view.getUint16(this.offset, false));
        this.offset += 2;
        return v;
      }
      if (additionalInfo === 26) { const v = this.view.getFloat32(this.offset, false); this.offset += 4; return v; }
      if (additionalInfo === 27) { const v = this.view.getFloat64(this.offset, false); this.offset += 8; return v; }
      return additionalInfo; // simple value
    }

    const arg = this.decodeArg(additionalInfo);

    switch (majorType) {
      case 0: return arg; // unsigned int
      case 1: return -1 - arg; // negative int
      case 2: { // bytes
        const bytes = new Uint8Array(this.view.buffer, this.view.byteOffset + this.offset, arg);
        this.offset += arg;
        return bytes;
      }
      case 3: { // text
        const bytes = new Uint8Array(this.view.buffer, this.view.byteOffset + this.offset, arg);
        this.offset += arg;
        return new TextDecoder().decode(bytes);
      }
      case 4: { // array
        const arr: unknown[] = [];
        if (additionalInfo === 31) { // indefinite length
          while (this.view.getUint8(this.offset) !== 0xff) arr.push(this.decode());
          this.offset++; // break code
        } else {
          for (let i = 0; i < arg; i++) arr.push(this.decode());
        }
        return arr;
      }
      case 5: { // map
        const map: Record<string, unknown> = {};
        if (additionalInfo === 31) {
          while (this.view.getUint8(this.offset) !== 0xff) {
            const k = this.decode() as string;
            map[k] = this.decode();
          }
          this.offset++;
        } else {
          for (let i = 0; i < arg; i++) {
            const k = this.decode() as string;
            map[k] = this.decode();
          }
        }
        return map;
      }
      case 6: { // tag
        const tagNum = arg;
        const value = this.decode();
        return this.resolveTag(tagNum, value);
      }
      default:
        throw new Error(`Unsupported CBOR major type: ${majorType}`);
    }
  }

  private decodeArg(additionalInfo: number): number {
    if (additionalInfo < 24) return additionalInfo;
    if (additionalInfo === 24) return this.view.getUint8(this.offset++);
    if (additionalInfo === 25) { const v = this.view.getUint16(this.offset, false); this.offset += 2; return v; }
    if (additionalInfo === 26) { const v = this.view.getUint32(this.offset, false); this.offset += 4; return v; }
    if (additionalInfo === 27) {
      // 8-byte unsigned int — read as BigInt, convert to Number (sufficient for timestamps)
      const hi = this.view.getUint32(this.offset, false);
      const lo = this.view.getUint32(this.offset + 4, false);
      this.offset += 8;
      return Number((BigInt(hi) << 32n) | BigInt(lo));
    }
    if (additionalInfo === 31) return Infinity; // indefinite length sentinel
    throw new Error(`Unsupported additional info: ${additionalInfo}`);
  }

  private decodeFloat16(half: number): number {
    const exp = (half >> 10) & 0x1f;
    const mant = half & 0x3ff;
    let val: number;
    if (exp === 0) val = mant * (2 ** -24);
    else if (exp !== 31) val = (mant + 1024) * (2 ** (exp - 25));
    else val = mant === 0 ? Infinity : NaN;
    return (half & 0x8000) ? -val : val;
  }

  private resolveTag(tag: number, value: unknown): unknown {
    if (tag === TAG_DISTRIBUTION) {
      const d = value as Record<string, unknown>;
      return {
        _type: "Distribution",
        mean: d.mean as number,
        var: (d.var ?? 0) as number,
        shape: (d.shape ?? "gaussian") as string,
        p5: d.p5 as number | undefined,
        p95: d.p95 as number | undefined,
      } satisfies Distribution;
    }
    if (tag === TAG_NODEREF) {
      return { _type: "NodeRef", node_id: value as string } satisfies NodeRef;
    }
    if (tag === TAG_EMBEDDING) {
      return { _type: "Embedding", values: value as number[] };
    }
    // Unknown tag — return as-is
    return { _tag: tag, value };
  }
}

function decodeCBOR(data: Uint8Array): unknown {
  return new CBORDecoder(data).decode();
}

// ---------------------------------------------------------------------------
// SHA-256 (Deno Web Crypto API)
// ---------------------------------------------------------------------------

async function sha256(data: Uint8Array): Promise<Uint8Array> {
  const hash = await crypto.subtle.digest("SHA-256", data);
  return new Uint8Array(hash);
}

// ---------------------------------------------------------------------------
// SIF reader
// ---------------------------------------------------------------------------

async function readSIF(data: Uint8Array): Promise<SIFDocument> {
  // 1. Magic
  if (data.length < 10) throw new Error("File too short");
  for (let i = 0; i < 8; i++) {
    if (data[i] !== MAGIC[i]) throw new Error(`Bad magic at byte ${i}: got ${data[i].toString(16)}`);
  }
  if (!SUPPORTED_VERSIONS.has(data[8])) throw new Error(`Unsupported version: ${data[8]}`);

  // 2. Find CHECKSUM chunk and validate
  let checksumOffset = -1;
  let offset = 10;
  while (offset < data.length) {
    if (offset + 5 > data.length) throw new Error("Truncated chunk header");
    const chunkType = data[offset];
    const length = new DataView(data.buffer, data.byteOffset + offset + 1, 4).getUint32(0, false);
    if (chunkType === CHUNK_CHECKSUM) { checksumOffset = offset; break; }
    offset += 5 + length;
  }
  if (checksumOffset < 0) throw new Error("No CHECKSUM chunk found");

  const body = data.slice(0, checksumOffset);
  const storedChecksum = data.slice(checksumOffset + 5, checksumOffset + 5 + 32);
  const computed = await sha256(body);
  for (let i = 0; i < 32; i++) {
    if (storedChecksum[i] !== computed[i]) throw new Error("Checksum mismatch — file corrupted");
  }

  // 3. Parse chunks
  const chunks = new Map<number, Uint8Array>();
  offset = 10;
  while (offset < checksumOffset) {
    const chunkType = data[offset];
    const length = new DataView(data.buffer, data.byteOffset + offset + 1, 4).getUint32(0, false);
    chunks.set(chunkType, data.slice(offset + 5, offset + 5 + length));
    offset += 5 + length;
  }

  if (!chunks.has(CHUNK_PAYLOAD)) throw new Error("Missing required PAYLOAD chunk");

  // 4. Decode payload
  const payloadRaw = decodeCBOR(chunks.get(CHUNK_PAYLOAD)!) as Record<string, unknown>[];
  const payload: SIFNode[] = payloadRaw.map(n => ({
    id: n.id as string,
    type: n.type as string,
    value: n.value,
    confidence: n.confidence as Distribution,
    refs: (n.refs as unknown[] ?? []).map(r => r as NodeRef),
  }));

  // 5. Decode trace (optional; v0.2: {method, steps}, v0.1: bare array)
  const trace: TraceStep[] = [];
  if (chunks.has(CHUNK_TRACE)) {
    const rawTrace = decodeCBOR(chunks.get(CHUNK_TRACE)!);
    const steps: Record<string, unknown>[] = Array.isArray(rawTrace)
      ? rawTrace as Record<string, unknown>[]
      : ((rawTrace as Record<string, unknown>).steps as Record<string, unknown>[]) ?? [];
    for (const s of steps) {
      trace.push({
        id: s.id as string,
        type: s.type as string,
        content: s.content,
        confidence: s.confidence as Distribution,
        deps: (s.deps as string[]) ?? [],
        alternatives: (s.alternatives as unknown[]) ?? [],
      });
    }
  }

  // 6. Decode provenance (optional)
  let provenance: Provenance | undefined;
  if (chunks.has(CHUNK_PROVENANCE)) {
    const p = decodeCBOR(chunks.get(CHUNK_PROVENANCE)!) as Record<string, unknown>;
    provenance = {
      source_model: p.source_model as string,
      model_version: p.model_version as string,
      temperature: p.temperature as number,
      input_hash: p.input_hash as string,
      timestamp_ms: p.timestamp_ms as number,
    };
  }

  let semanticDim: number | undefined;
  if (chunks.has(CHUNK_SEMANTIC)) {
    const s = decodeCBOR(chunks.get(CHUNK_SEMANTIC)!) as Record<string, unknown>;
    const emb = s.embedding as { values?: number[] } | number[];
    semanticDim = Array.isArray(emb) ? emb.length : (emb?.values?.length ?? 0);
  }

  let alternativeCount: number | undefined;
  if (chunks.has(CHUNK_ALTS)) {
    const rawAlts = decodeCBOR(chunks.get(CHUNK_ALTS)!);
    const altsList: unknown[] = Array.isArray(rawAlts)
      ? rawAlts
      : ((rawAlts as Record<string, unknown>).alts as unknown[]) ?? [];
    alternativeCount = altsList.length;
  }

  let deltaBaseHash: string | undefined;
  if (chunks.has(CHUNK_DELTA)) {
    const d = decodeCBOR(chunks.get(CHUNK_DELTA)!) as Record<string, unknown>;
    deltaBaseHash = d.base_hash as string;
  }

  return { payload, trace, provenance, semanticDim, alternativeCount, deltaBaseHash };
}

// ---------------------------------------------------------------------------
// CLI entry point
// ---------------------------------------------------------------------------

async function main() {
  const path = Deno.args[0];
  if (!path) {
    console.error("Usage: deno run --allow-read compat/sif_reader.ts <file.sif>");
    Deno.exit(1);
  }

  const data = await Deno.readFile(path);
  let doc: SIFDocument;

  try {
    doc = await readSIF(data);
  } catch (e) {
    console.error(`ERROR: ${(e as Error).message}`);
    Deno.exit(1);
  }

  // Output JSON for diffing against Python reference
  console.log(JSON.stringify({
    payload_count: doc.payload.length,
    payload: doc.payload.map(n => ({
      id: n.id,
      type: n.type,
      value: n.value,
      confidence_mean: n.confidence?.mean,
      confidence_shape: n.confidence?.shape,
      ref_ids: n.refs.map(r => r.node_id),
    })),
    trace_count: doc.trace.length,
    trace: doc.trace.map(s => ({
      id: s.id,
      type: s.type,
      confidence_mean: s.confidence?.mean,
      deps: s.deps,
      alternatives_count: s.alternatives.length,
    })),
    provenance: doc.provenance ? {
      source_model: doc.provenance.source_model,
      temperature: doc.provenance.temperature,
    } : null,
    semantic_dim: doc.semanticDim ?? null,
    alternative_count: doc.alternativeCount ?? null,
    delta_base_hash: doc.deltaBaseHash ?? null,
  }, null, 2));
}

await main();
