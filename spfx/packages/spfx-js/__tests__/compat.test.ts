import { beforeAll, describe, expect, test } from '@jest/globals';
import { mkdtempSync, readFileSync } from 'fs';
import { tmpdir } from 'os';
import { join, resolve } from 'path';
import { execFileSync, spawnSync } from 'child_process';
import { createHash } from 'crypto';

import { SPIFReader } from '../src/reader.js';
import { SPIFWriter } from '../src/writer.js';
import type { SPIFDocument, Node, Provenance } from '../src/types.js';
import { FLAG_COMPRESSED, MAGIC } from '../src/format.js';
import { cborDecode } from '../src/cbor-utils.js';

interface ManifestEntry {
  name: string;
  filename: string;
  sha256: string;
  bytes: number;
}

interface Manifest {
  fixtures: ManifestEntry[];
}

function repoRoot(): string {
  return resolve(process.cwd(), '../../..');
}

function findPythonWithSpifDeps(): string {
  if (process.env.SPIF_PYTHON) {
    return process.env.SPIF_PYTHON;
  }

  const candidates = [
    'python3',
    'python',
    '/Users/kalinovdameus/miniforge3/bin/python3',
    '/Users/kalinovdameus/miniforge3/bin/python',
    '/opt/homebrew/bin/python3',
    '/usr/bin/python3',
  ];

  for (const candidate of candidates) {
    const result = spawnSync(candidate, [
      '-c',
      "import importlib.util; raise SystemExit(0 if all(importlib.util.find_spec(m) for m in ('cbor2','cryptography')) else 1)",
    ]);
    if (result.status === 0) {
      return candidate;
    }
  }

  throw new Error(
    'Could not find a Python interpreter with cbor2 and cryptography installed; set SPIF_PYTHON to override'
  );
}

function generateFixtures(): { fixtureDir: string; manifest: Manifest } {
  const root = repoRoot();
  const fixtureDir = mkdtempSync(join(tmpdir(), 'spif-js-fixtures-'));
  const generator = join(root, 'spfx', 'compat', 'generate_compat_fixtures.py');
  const python = findPythonWithSpifDeps();

  execFileSync(python, [generator, fixtureDir], {
    cwd: root,
    stdio: 'pipe',
  });

  const manifest = JSON.parse(
    readFileSync(join(fixtureDir, 'manifest.json'), 'utf8')
  ) as Manifest;

  return { fixtureDir, manifest };
}

function fixtureBytes(fixtureDir: string, filename: string): Uint8Array {
  const data = readFileSync(join(fixtureDir, filename));
  return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
}

function minimalDocWithBlob(): SPIFDocument {
  const node: Node = {
    id: 'blob',
    type: 'text',
    value: 'x'.repeat(4096),
    confidence: { mean: 1.0, var: 0.0, shape: 'point', semantics: 'epistemic' },
    refs: [],
  };
  const provenance: Provenance = {
    source_model: 'test',
    model_version: 'test',
    temperature: 0,
    input_hash: '',
    context_ref: '',
    timestamp_ms: 123,
  };
  return {
    payload: [node],
    provenance,
    trace: [],
    trace_method: 'post-hoc',
    alternatives: [],
    signatures: [],
  };
}

describe('SPIF compatibility', () => {
  let fixtureDir: string;
  let manifest: Manifest;

  beforeAll(() => {
    ({ fixtureDir, manifest } = generateFixtures());
  });

  test('test_python_fixtures_roundtrip_in_typescript', () => {
    const reader = new SPIFReader();

    for (const fixture of manifest.fixtures) {
      const bytes = fixtureBytes(fixtureDir, fixture.filename);
      const sha256 = createHash('sha256').update(bytes).digest('hex');

      expect(bytes.length).toBe(fixture.bytes);
      expect(sha256).toBe(fixture.sha256);

      const doc = reader.decode(bytes);
      expect(doc.payload.length).toBeGreaterThan(0);
    }
  });

  test('test_python_signed_fixtures_verify_in_typescript', () => {
    const reader = new SPIFReader();

    expect(reader.verifySignature(fixtureBytes(fixtureDir, 'signed_single.spfx'))).toBe(true);
    expect(reader.verifySignature(fixtureBytes(fixtureDir, 'multisig.spfx'))).toBe(true);
  });

  test('test_tampered_python_signed_fixture_is_rejected', () => {
    const reader = new SPIFReader();
    const bytes = fixtureBytes(fixtureDir, 'signed_single.spfx');
    const marker = Buffer.from('Minimal fixture', 'utf8');
    const offset = Buffer.from(bytes).indexOf(marker);

    expect(offset).toBeGreaterThanOrEqual(0);

    const tampered = new Uint8Array(bytes);
    tampered[offset] ^= 0x01;

    expect(() => reader.decode(tampered)).toThrow();
    expect(() => reader.verifySignature(tampered)).toThrow();
  });

  test('test_writer_emits_compressed_chunks_and_flags2', () => {
    const plain = new SPIFWriter().encode(minimalDocWithBlob());
    const compressed = new SPIFWriter({ compress: true }).encode(minimalDocWithBlob());
    const restored = new SPIFReader().decode(compressed);

    expect(compressed.length).toBeLessThan(plain.length);
    expect(restored.payload[0].id).toBe('blob');
    expect(restored.payload[0].value).toBe('x'.repeat(4096));

    expect(compressed[0]).toBe(MAGIC[0]);
    expect(restored.provenance?.timestamp_ms).toBe(123);

    const rawHeader = readHeaderFlags2(compressed);
    expect(rawHeader & FLAG_COMPRESSED).toBe(FLAG_COMPRESSED);
  });
});

function readHeaderFlags2(data: Uint8Array): number {
  const headerLength = new DataView(
    data.buffer,
    data.byteOffset,
    data.byteLength,
  ).getUint32(MAGIC.length + 3, false);
  const headerPayload = data.subarray(MAGIC.length + 7, MAGIC.length + 7 + headerLength);
  const parsed = cborDecode(headerPayload) as { flags2?: number };
  return parsed.flags2 ?? 0;
}
