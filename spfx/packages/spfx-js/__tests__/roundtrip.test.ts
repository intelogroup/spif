/**
 * Roundtrip tests for SPIF TypeScript implementation.
 */

import { describe, test, expect } from '@jest/globals';
import { SPIFReader } from '../src/reader.js';
import { SPIFWriter } from '../src/writer.js';
import { MAGIC, FORMAT_VERSION } from '../src/format.js';
import { SPIFChecksumError, SPIFFormatError } from '../src/errors.js';
import type { SPIFDocument, Node } from '../src/types.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeMinimalDoc(): SPIFDocument {
  const node: Node = {
    id: 'n0',
    type: 'text',
    value: 'Hello, SPIF!',
    confidence: { mean: 0.9, var: 0.01, shape: 'gaussian', semantics: 'epistemic' },
    refs: [],
  };
  return {
    payload: [node],
    trace: [],
    trace_method: 'post-hoc',
    alternatives: [],
    signatures: [],
  };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('SPIF roundtrip', () => {
  test('test_magic_bytes', () => {
    const writer = new SPIFWriter();
    const doc = makeMinimalDoc();
    const encoded = writer.encode(doc);

    // First 9 bytes must match magic
    expect(encoded.length).toBeGreaterThan(9);
    for (let i = 0; i < MAGIC.length; i++) {
      expect(encoded[i]).toBe(MAGIC[i]);
    }
  });

  test('test_version_byte', () => {
    const writer = new SPIFWriter();
    const doc = makeMinimalDoc();
    const encoded = writer.encode(doc);

    // Byte at offset 9 (MAGIC.length) is the version
    expect(encoded[MAGIC.length]).toBe(FORMAT_VERSION);
    expect(encoded[MAGIC.length]).toBe(0x02);
  });

  test('test_roundtrip_minimal', () => {
    const writer = new SPIFWriter();
    const reader = new SPIFReader();
    const doc = makeMinimalDoc();

    const encoded = writer.encode(doc);
    const decoded = reader.decode(encoded);

    expect(decoded.payload.length).toBe(1);
    expect(decoded.payload[0].id).toBe('n0');
    expect(decoded.payload[0].type).toBe('text');
    expect(decoded.payload[0].value).toBe('Hello, SPIF!');
    expect(decoded.payload[0].confidence.mean).toBeCloseTo(0.9);
    expect(decoded.payload[0].confidence.var).toBeCloseTo(0.01);
    expect(decoded.payload[0].confidence.shape).toBe('gaussian');
    expect(decoded.payload[0].confidence.semantics).toBe('epistemic');
  });

  test('test_roundtrip_with_provenance', () => {
    const writer = new SPIFWriter();
    const reader = new SPIFReader();
    const doc: SPIFDocument = {
      ...makeMinimalDoc(),
      provenance: {
        source_model: 'claude-sonnet-4-6',
        model_version: 'claude-sonnet-4-6-20251001',
        temperature: 0.7,
        input_hash: 'abc123',
        context_ref: '',
        timestamp_ms: 1700000000000,
      },
    };

    const encoded = writer.encode(doc);
    const decoded = reader.decode(encoded);

    expect(decoded.provenance).toBeDefined();
    expect(decoded.provenance!.source_model).toBe('claude-sonnet-4-6');
    expect(decoded.provenance!.model_version).toBe('claude-sonnet-4-6-20251001');
    expect(decoded.provenance!.temperature).toBeCloseTo(0.7);
    expect(decoded.provenance!.input_hash).toBe('abc123');
    expect(decoded.provenance!.timestamp_ms).toBe(1700000000000);
  });

  test('test_roundtrip_with_trace', () => {
    const writer = new SPIFWriter();
    const reader = new SPIFReader();
    const doc: SPIFDocument = {
      ...makeMinimalDoc(),
      trace: [
        {
          id: 'step0',
          type: 'hypothesis',
          content: 'Initial hypothesis',
          confidence: { mean: 0.8, var: 0.02, shape: 'gaussian', semantics: 'epistemic' },
          deps: [],
          alternatives: [],
        },
        {
          id: 'step1',
          type: 'inference',
          content: 'Derived inference',
          confidence: { mean: 0.75, var: 0.03, shape: 'gaussian', semantics: 'epistemic' },
          deps: ['step0'],
          alternatives: [],
        },
      ],
      trace_method: 'post-hoc',
    };

    const encoded = writer.encode(doc);
    const decoded = reader.decode(encoded);

    expect(decoded.trace.length).toBe(2);
    expect(decoded.trace[0].id).toBe('step0');
    expect(decoded.trace[0].type).toBe('hypothesis');
    expect(decoded.trace[0].content).toBe('Initial hypothesis');
    expect(decoded.trace[1].id).toBe('step1');
    expect(decoded.trace[1].deps).toEqual(['step0']);
    expect(decoded.trace_method).toBe('post-hoc');
  });

  test('test_checksum_verified', () => {
    const writer = new SPIFWriter();
    const reader = new SPIFReader();
    const doc = makeMinimalDoc();

    const encoded = writer.encode(doc);
    // Should not throw
    const decoded = reader.decode(encoded);
    expect(decoded.payload.length).toBe(1);
  });

  test('test_tampered_checksum_rejected', () => {
    const writer = new SPIFWriter();
    const reader = new SPIFReader();
    const doc = makeMinimalDoc();

    const encoded = writer.encode(doc);
    // Flip the last byte (part of the checksum payload)
    const tampered = new Uint8Array(encoded);
    tampered[tampered.length - 1] ^= 0xff;

    expect(() => reader.decode(tampered)).toThrow(SPIFChecksumError);
  });

  test('test_truncated_rejected', () => {
    const writer = new SPIFWriter();
    const reader = new SPIFReader();
    const doc = makeMinimalDoc();

    const encoded = writer.encode(doc);
    // Strip checksum chunk (last 37 bytes = 5 header + 32 checksum)
    const truncated = encoded.subarray(0, encoded.length - 37);

    expect(() => reader.decode(truncated)).toThrow(SPIFFormatError);
  });
});
