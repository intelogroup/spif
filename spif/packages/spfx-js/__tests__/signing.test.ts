/**
 * Ed25519 signing: two-pass sign, verify, and rejection edge cases.
 */

import { describe, test, expect } from '@jest/globals';
import { generateKeyPairSync, sign as cryptoSign, createHash } from 'crypto';

import { SPIFReader } from '../src/reader.js';
import { SPIFWriter } from '../src/writer.js';
import { CHUNK_SIGNATURE, CHUNK_CHECKSUM, MAGIC } from '../src/format.js';
import { SPIFChecksumError, SPIFSignatureError } from '../src/errors.js';
import type { SPIFDocument, Node, Provenance, Signature } from '../src/types.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeDoc(): SPIFDocument {
  const node: Node = {
    id: 'claim_0',
    type: 'fact',
    value: 'Paris is the capital of France.',
    confidence: { mean: 0.99, var: 0.001, shape: 'point', semantics: 'epistemic' },
    refs: [],
  };
  const provenance: Provenance = {
    source_model: 'claude-sonnet-4-6',
    model_version: 'claude-sonnet-4-6',
    temperature: 0.0,
    input_hash: 'a'.repeat(64),
    context_ref: '',
    timestamp_ms: 1_700_000_000_000,
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

/**
 * Two-pass Ed25519 signing using Node.js crypto (mirrors Python test_signature.py).
 *
 * Pass 1: encode with a 64-byte dummy signature to establish the final body layout.
 * Pass 2: sign the bytes before CHUNK_SIGNATURE, re-encode with the real signature.
 */
function signDoc(
  doc: SPIFDocument,
  privateKey: ReturnType<typeof generateKeyPairSync>['privateKey'],
  signerB64: string,
): Uint8Array {
  const writer = new SPIFWriter();

  // Pass 1: dummy sig
  const dummySig: Signature = {
    algorithm: 'ed25519',
    signer: signerB64,
    signature: new Uint8Array(64),
    key_id: '',
  };
  const pass1 = writer.encode({ ...doc, signature: dummySig });

  // Find CHUNK_SIGNATURE (0x07) offset
  const dv = new DataView(pass1.buffer, pass1.byteOffset, pass1.byteLength);
  let offset = MAGIC.length + 2; // magic(9) + version(1) + flags(1)
  let sigOffset: number | null = null;

  while (offset < pass1.length) {
    const chunkType = pass1[offset];
    const chunkLen = dv.getUint32(offset + 1, false);
    if (chunkType === CHUNK_SIGNATURE) {
      sigOffset = offset;
      break;
    }
    if (chunkType === CHUNK_CHECKSUM) break;
    offset += 5 + chunkLen;
  }

  if (sigOffset === null) {
    throw new Error('SIGNATURE chunk not found in pass-1 encoding');
  }

  const bodyToSign = Buffer.from(pass1.subarray(0, sigOffset));
  const rawSig = cryptoSign(null, bodyToSign, privateKey);

  const realSig: Signature = {
    algorithm: 'ed25519',
    signer: signerB64,
    signature: new Uint8Array(rawSig),
    key_id: '',
  };
  return writer.encode({ ...doc, signature: realSig });
}

function makeKeyPair(): { privateKey: ReturnType<typeof generateKeyPairSync>['privateKey']; signerB64: string } {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  // SPKI DER for Ed25519 = 12-byte ASN.1 header + 32-byte raw key
  const spkiDer = publicKey.export({ type: 'spki', format: 'der' }) as Buffer;
  const signerB64 = spkiDer.subarray(12).toString('base64');
  return { privateKey, signerB64 };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('SPIF signing (Ed25519)', () => {
  test('test_signed_document_roundtrip', () => {
    const { privateKey, signerB64 } = makeKeyPair();
    const doc = makeDoc();
    const encoded = signDoc(doc, privateKey, signerB64);

    const reader = new SPIFReader();
    const decoded = reader.decode(encoded);

    expect(decoded.signature).toBeDefined();
    expect(decoded.signature!.algorithm).toBe('ed25519');
    expect(decoded.signature!.signer).toBe(signerB64);
    expect(decoded.signature!.signature.length).toBe(64);
    expect(decoded.payload.length).toBe(1);
    expect(decoded.payload[0].id).toBe('claim_0');
  });

  test('test_verify_signature_valid', () => {
    const { privateKey, signerB64 } = makeKeyPair();
    const encoded = signDoc(makeDoc(), privateKey, signerB64);

    const reader = new SPIFReader();
    expect(reader.verifySignature(encoded)).toBe(true);
  });

  test('test_verify_signature_with_wrong_key', () => {
    const { privateKey, signerB64 } = makeKeyPair();
    const { signerB64: wrongSignerB64 } = makeKeyPair(); // different public key

    const writer = new SPIFWriter();

    // Sign with correct privateKey but store wrong public key as signer
    const doc = makeDoc();
    const dummySig: Signature = {
      algorithm: 'ed25519',
      signer: wrongSignerB64,   // wrong pub key
      signature: new Uint8Array(64),
      key_id: '',
    };
    const pass1 = writer.encode({ ...doc, signature: dummySig });

    const dv = new DataView(pass1.buffer, pass1.byteOffset, pass1.byteLength);
    let offset = MAGIC.length + 2;
    let sigOffset: number | null = null;
    while (offset < pass1.length) {
      const ct = pass1[offset];
      const cl = dv.getUint32(offset + 1, false);
      if (ct === CHUNK_SIGNATURE) { sigOffset = offset; break; }
      if (ct === CHUNK_CHECKSUM) break;
      offset += 5 + cl;
    }
    const bodyToSign = Buffer.from(pass1.subarray(0, sigOffset!));
    const rawSig = cryptoSign(null, bodyToSign, privateKey);  // correct key
    const data = writer.encode({
      ...doc,
      signature: { algorithm: 'ed25519', signer: wrongSignerB64, signature: new Uint8Array(rawSig), key_id: '' },
    });

    expect(() => new SPIFReader().verifySignature(data)).toThrow(SPIFSignatureError);
  });

  test('test_verify_signature_rejects_wrong_algorithm', () => {
    // Encode a doc with algorithm='rsa' — verifySignature must throw
    const writer = new SPIFWriter();
    const doc = makeDoc();
    const badSig: Signature = {
      algorithm: 'rsa',
      signer: 'aGVsbG8=',  // dummy base64
      signature: new Uint8Array(64),
      key_id: '',
    };
    const encoded = writer.encode({ ...doc, signature: badSig });

    // decode() succeeds (no sig verification on plain decode)
    const decoded = new SPIFReader().decode(encoded);
    expect(decoded.signature!.algorithm).toBe('rsa');

    // verifySignature() must throw SPIFSignatureError for unknown algorithm
    expect(() => new SPIFReader().verifySignature(encoded)).toThrow(SPIFSignatureError);
  });

  test('test_unsigned_document_verify_returns_false', () => {
    const doc = makeDoc();
    const encoded = new SPIFWriter().encode(doc);
    expect(new SPIFReader().verifySignature(encoded)).toBe(false);
  });

  test('test_tampered_body_raises_checksum_before_sig_verify', () => {
    const { privateKey, signerB64 } = makeKeyPair();
    const encoded = signDoc(makeDoc(), privateKey, signerB64);

    // Flip a byte in the middle — checksum fires before signature check
    const tampered = new Uint8Array(encoded);
    tampered[Math.floor(encoded.length / 2)] ^= 0xff;

    expect(() => new SPIFReader().decode(tampered)).toThrow(SPIFChecksumError);
  });

  test('test_require_signature_mode_rejects_unsigned', () => {
    const doc = makeDoc();
    const encoded = new SPIFWriter().encode(doc);

    // requireSignature=true → decode must throw SPIFSignatureError for unsigned doc
    const strictReader = new SPIFReader({ requireSignature: true });
    expect(() => strictReader.decode(encoded)).toThrow(SPIFSignatureError);
  });

  test('test_require_signature_mode_accepts_signed', () => {
    const { privateKey, signerB64 } = makeKeyPair();
    const encoded = signDoc(makeDoc(), privateKey, signerB64);

    const strictReader = new SPIFReader({ requireSignature: true });
    expect(() => strictReader.decode(encoded)).not.toThrow();
  });

  test('test_vulnerability_tampered_document_bypasses_signature_verification_in_strict_mode', () => {
    const { privateKey, signerB64 } = makeKeyPair();
    const encoded = signDoc(makeDoc(), privateKey, signerB64);

    // 1. Convert to string and corrupt the payload
    // Let's find "Paris" in the encoded body and replace it with "tampe" (both are 5 bytes, maintaining size)
    const tampered = new Uint8Array(encoded);
    const parisIndex = Buffer.from(tampered).indexOf('Paris');
    expect(parisIndex).toBeGreaterThan(0);
    tampered.set(Buffer.from('tampe'), parisIndex);

    // 2. Locate checksum chunk, recalculate checksum of the tampered body
    let checksumOffset: number | null = null;
    let scanOffset = MAGIC.length + 2;
    const scanView = new DataView(tampered.buffer, tampered.byteOffset, tampered.byteLength);

    while (scanOffset < tampered.length) {
      if (scanOffset + 5 > tampered.length) break;
      const chunkType = tampered[scanOffset];
      const length = scanView.getUint32(scanOffset + 1, false);
      if (chunkType === CHUNK_CHECKSUM) {
        checksumOffset = scanOffset;
        break;
      }
      scanOffset += 5 + length;
    }
    expect(checksumOffset).not.toBeNull();

    // Recalculate checksum over the body using Node.js crypto
    const body = tampered.subarray(0, checksumOffset!);
    const computed = createHash('sha256').update(body).digest();
    tampered.set(computed, checksumOffset! + 5);

    // 3. Decode with strict reader
    const strictReader = new SPIFReader({ requireSignature: true });
    
    // We expect this to fail cryptographically under strict mode!
    expect(() => strictReader.decode(tampered)).toThrow(SPIFSignatureError);
  });
});
