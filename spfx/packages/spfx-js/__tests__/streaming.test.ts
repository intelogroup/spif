/**
 * Streaming tests for SPIF TypeScript implementation.
 */

import { describe, test, expect } from '@jest/globals';
import { SPIFStreamWriter, SPIFStreamReader } from '../src/streaming.js';
import { SPIFReader } from '../src/reader.js';
import { FLAG_STREAMING, CHUNK_PARTIAL_TEXT, MAGIC } from '../src/format.js';
import type { SPIFDocument, Node } from '../src/types.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeMinimalDoc(): SPIFDocument {
  const node: Node = {
    id: 'main',
    type: 'text',
    value: 'Hello streaming world!',
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
// Tests
// ---------------------------------------------------------------------------

describe('SPIF streaming', () => {
  test('test_stream_produces_valid_spif', () => {
    const writer = new SPIFStreamWriter();
    const doc = makeMinimalDoc();

    const header = writer.open();
    const p1 = writer.partialText('Hello ');
    const p2 = writer.partialText('streaming ');
    const p3 = writer.partialText('world!');
    const tail = writer.commit(doc);

    const full = concat(header, p1, p2, p3, tail);

    const reader = new SPIFReader();
    const decoded = reader.decode(full);

    expect(decoded.payload.length).toBe(1);
    expect(decoded.payload[0].id).toBe('main');
  });

  test('test_stream_flag_set', () => {
    const writer = new SPIFStreamWriter();
    const doc = makeMinimalDoc();

    const header = writer.open();
    const tail = writer.commit(doc);

    const full = concat(header, tail);

    // Flags byte is at MAGIC.length + 1 (index 10)
    const flagsByte = full[MAGIC.length + 1];
    expect(flagsByte & FLAG_STREAMING).toBe(FLAG_STREAMING);
  });

  test('test_partial_text_chunk_type', () => {
    const writer = new SPIFStreamWriter();
    writer.open();

    const partial = writer.partialText('test token');

    // First byte of a partial text chunk is the chunk type
    expect(partial[0]).toBe(CHUNK_PARTIAL_TEXT);
    expect(partial[0]).toBe(0x10);
  });

  test('test_stream_reader_events', () => {
    const writer = new SPIFStreamWriter();
    const doc = makeMinimalDoc();

    const header = writer.open();
    const p1 = writer.partialText('Hello ');
    const p2 = writer.partialText('world');
    const p3 = writer.partialText('!');
    const tail = writer.commit(doc);

    const full = concat(header, p1, p2, p3, tail);

    const reader = new SPIFStreamReader();
    const events = reader.feed(full);

    expect(reader.done).toBe(true);

    const types = events.map(e => e.type);
    expect(types).toContain('opened');
    expect(types.filter(t => t === 'partial_text').length).toBe(3);
    expect(types).toContain('verified');

    const partialEvents = events.filter(e => e.type === 'partial_text');
    expect(partialEvents[0]).toMatchObject({ type: 'partial_text', text: 'Hello ', seq: 0 });
    expect(partialEvents[1]).toMatchObject({ type: 'partial_text', text: 'world', seq: 1 });
    expect(partialEvents[2]).toMatchObject({ type: 'partial_text', text: '!', seq: 2 });

    const verifiedEvent = events.find(e => e.type === 'verified');
    expect(verifiedEvent).toBeDefined();
    if (verifiedEvent && verifiedEvent.type === 'verified') {
      expect(verifiedEvent.document.payload.length).toBe(1);
    }
  });

  test('test_incremental_feed', () => {
    const writer = new SPIFStreamWriter();
    const doc = makeMinimalDoc();

    const header = writer.open();
    const p1 = writer.partialText('token1');
    const tail = writer.commit(doc);

    const full = concat(header, p1, tail);

    // Feed byte by byte
    const reader = new SPIFStreamReader();
    const allEvents: { type: string }[] = [];

    for (let i = 0; i < full.length; i++) {
      const events = reader.feed(full.subarray(i, i + 1));
      allEvents.push(...events);
    }

    expect(reader.done).toBe(true);

    const types = allEvents.map(e => e.type);
    expect(types).toContain('opened');
    expect(types).toContain('partial_text');
    expect(types).toContain('verified');
  });

  test('test_tampered_partial_chunk_detected', () => {
    const writer = new SPIFStreamWriter();
    const doc = makeMinimalDoc();

    const header = writer.open();
    const partial = writer.partialText('hello');
    const tail = writer.commit(doc);

    // Corrupt the PARTIAL_TEXT chunk payload (bytes 6+)
    const tamperedPartial = new Uint8Array(partial);
    if (tamperedPartial.length > 6) {
      tamperedPartial[6] ^= 0xff;
    }

    const full = concat(header, tamperedPartial, tail);

    const reader = new SPIFStreamReader();
    const events = reader.feed(full);

    // Either partial_text decoding fails with error, or the checksum fails at verified
    const hasError = events.some(e => e.type === 'error');
    const verifiedEvent = events.find(e => e.type === 'verified');

    // At minimum the checksum must catch the tampering
    if (verifiedEvent && verifiedEvent.type === 'verified') {
      // The document decoded successfully despite corruption (partial text corruption
      // doesn't affect checksummed content if CBOR decode still succeeds).
      // The checksum covers the full byte stream, so if we corrupted the partial chunk,
      // the checksum verification will fail.
    }

    // The checksum failure should either show as an error event or the full stream
    // fails to decode — either way we should NOT get a clean verified event
    // without detecting the corruption.
    // Note: partial text corruption corrupts the full byte stream which changes the checksum.
    expect(hasError || !verifiedEvent).toBe(true);
  });
});
