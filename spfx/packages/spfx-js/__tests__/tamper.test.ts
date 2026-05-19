/**
 * Byte-level tamper detection: verifies that SPIF catches corruption in
 * every significant region of the encoded document.
 */

import { describe, test, expect } from '@jest/globals';
import { generateKeyPairSync, sign as cryptoSign } from 'crypto';

import { SPIFReader } from '../src/reader.js';
import { SPIFWriter } from '../src/writer.js';
import { MAGIC, FORMAT_VERSION, CHUNK_SIGNATURE, CHUNK_CHECKSUM } from '../src/format.js';
import { SPIFChecksumError, SPIFMagicError, SPIFFormatError } from '../src/errors.js';
import type { SPIFDocument, Node, Provenance, Signature } from '../src/types.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeDoc(payloadSize = 1): SPIFDocument {
  const nodes: Node[] = Array.from({ length: payloadSize }, (_, i) => ({
    id: `n${i}`,
    type: 'fact',
    value: `Claim number ${i} about something important.`,
    confidence: { mean: 0.9, var: 0.01, shape: 'gaussian', semantics: 'epistemic' },
    refs: [],
  }));
  const provenance: Provenance = {
    source_model: 'test-model',
    model_version: '1.0',
    temperature: 0.7,
    input_hash: 'b'.repeat(64),
    context_ref: '',
    timestamp_ms: 1_700_000_000_000,
  };
  return {
    payload: nodes,
    provenance,
    trace: [],
    trace_method: 'post-hoc',
    alternatives: [],
    signatures: [],
  };
}

function flipByte(data: Uint8Array, offset: number, xorMask = 0xff): Uint8Array {
  const copy = new Uint8Array(data);
  copy[offset] ^= xorMask;
  return copy;
}

function encode(doc: SPIFDocument): Uint8Array {
  return new SPIFWriter().encode(doc);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('SPIF tamper detection', () => {
  test('test_byte_flip_in_payload_region_raises_checksum_error', () => {
    const data = encode(makeDoc());
    // Middle of the document is typically inside PAYLOAD chunk
    const mid = Math.floor(data.length / 2);
    const tampered = flipByte(data, mid);

    expect(() => new SPIFReader().decode(tampered)).toThrow(SPIFChecksumError);
  });

  test('test_byte_flip_near_end_of_body_raises_checksum_error', () => {
    const data = encode(makeDoc(3));
    // Near end (before CHECKSUM) should still be covered
    const tampered = flipByte(data, data.length - 40);

    expect(() => new SPIFReader().decode(tampered)).toThrow();
  });

  test('test_flip_multiple_bytes_raises_checksum_error', () => {
    const data = encode(makeDoc());
    const tampered = new Uint8Array(data);
    for (let i = 20; i < 30; i++) {
      tampered[i] ^= 0xaa;
    }

    expect(() => new SPIFReader().decode(tampered)).toThrow(SPIFChecksumError);
  });

  test('test_wrong_magic_raises_magic_error', () => {
    const data = encode(makeDoc());
    const tampered = new Uint8Array(data);
    tampered[0] = 0x00; // corrupt first magic byte

    expect(() => new SPIFReader().decode(tampered)).toThrow(SPIFMagicError);
  });

  test('test_truncated_document_raises', () => {
    const data = encode(makeDoc());
    const truncated = data.subarray(0, Math.floor(data.length / 2));

    expect(() => new SPIFReader().decode(truncated)).toThrow();
  });

  test('test_empty_input_raises', () => {
    expect(() => new SPIFReader().decode(new Uint8Array(0))).toThrow();
  });

  test('test_magic_only_input_raises', () => {
    expect(() => new SPIFReader().decode(MAGIC)).toThrow();
  });

  test('test_all_zeros_raises', () => {
    const zeros = new Uint8Array(64);
    expect(() => new SPIFReader().decode(zeros)).toThrow();
  });

  test('test_checksum_bytes_replaced_with_zeros_raises', () => {
    const data = encode(makeDoc());
    const tampered = new Uint8Array(data);

    // Find CHECKSUM chunk (0xff) and zero out its 32-byte payload
    const dv = new DataView(tampered.buffer, tampered.byteOffset, tampered.byteLength);
    let offset = MAGIC.length + 2;
    while (offset < tampered.length) {
      const ct = tampered[offset];
      const cl = dv.getUint32(offset + 1, false);
      if (ct === CHUNK_CHECKSUM) {
        // Zero out checksum payload
        tampered.fill(0x00, offset + 5, offset + 5 + cl);
        break;
      }
      offset += 5 + cl;
    }

    expect(() => new SPIFReader().decode(tampered)).toThrow(SPIFChecksumError);
  });

  test('test_signature_chunk_body_tampered_raises_checksum_error', () => {
    // A signed document whose SIGNATURE chunk body is flipped:
    // the checksum covers the signature chunk, so this must raise SPIFChecksumError.
    const writer = new SPIFWriter();
    const reader = new SPIFReader();

    const { publicKey, privateKey } = generateKeyPairSync('ed25519');
    const spkiDer: Buffer = publicKey.export({ type: 'spki', format: 'der' });
    const signerB64 = spkiDer.subarray(12).toString('base64');

    // Build signed doc using two-pass pattern
    const doc = makeDoc();
    const dummySig = { algorithm: 'ed25519', signer: signerB64, signature: new Uint8Array(64), key_id: '' };
    const pass1 = writer.encode({ ...doc, signature: dummySig });

    const dv1 = new DataView(pass1.buffer, pass1.byteOffset, pass1.byteLength);
    let offset = MAGIC.length + 2;
    let sigOffset = 0;
    while (offset < pass1.length) {
      const ct = pass1[offset];
      const cl = dv1.getUint32(offset + 1, false);
      if (ct === CHUNK_SIGNATURE) { sigOffset = offset; break; }
      if (ct === CHUNK_CHECKSUM) break;
      offset += 5 + cl;
    }
    const rawSig = cryptoSign(null, Buffer.from(pass1.subarray(0, sigOffset)), privateKey);
    const encoded = writer.encode({
      ...doc,
      signature: { algorithm: 'ed25519', signer: signerB64, signature: new Uint8Array(rawSig), key_id: '' },
    });

    // Tamper inside SIGNATURE chunk payload (first byte of the 64-byte sig)
    const tampered = new Uint8Array(encoded);
    const dv2 = new DataView(tampered.buffer, tampered.byteOffset, tampered.byteLength);
    let off2 = MAGIC.length + 2;
    while (off2 < tampered.length) {
      const ct = tampered[off2];
      const cl = dv2.getUint32(off2 + 1, false);
      if (ct === CHUNK_SIGNATURE) {
        tampered[off2 + 5] ^= 0x01; // flip first byte of SIGNATURE chunk payload
        break;
      }
      off2 += 5 + cl;
    }

    // Checksum must catch this before signature check
    expect(() => reader.decode(tampered)).toThrow(SPIFChecksumError);
  });

  test('test_garbage_appended_after_checksum_is_ignored', () => {
    const data = encode(makeDoc());
    const withTrailer = new Uint8Array(data.length + 50);
    withTrailer.set(data);
    withTrailer.fill(0xAB, data.length);

    // SPIF reader stops at CHECKSUM chunk — trailing bytes are ignored
    expect(() => new SPIFReader().decode(withTrailer)).not.toThrow();
  });

  test('test_detection_rate_across_100_random_mutations', () => {
    // Statistical check: ~100% of mutations should be detected
    const data = encode(makeDoc(3));
    const reader = new SPIFReader();
    let detected = 0;
    const total = 100;

    for (let i = 0; i < total; i++) {
      // Mutate at a deterministic position spread across the document body
      const pos = 11 + (i * 3) % (data.length - 44); // stay away from magic/checksum
      const tampered = flipByte(data, pos);
      try {
        reader.decode(tampered);
      } catch {
        detected++;
      }
    }

    // SPIF SHA-256 covers full body → expect 100% detection
    expect(detected).toBe(total);
  });
});
