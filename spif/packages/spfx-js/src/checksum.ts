/**
 * SHA-256 checksum utilities for SPIF.
 * Uses Node.js built-in crypto when available, falls back to WebCrypto.
 */

import { createHash } from 'crypto';

export async function sha256(data: Uint8Array): Promise<Uint8Array> {
  return sha256Sync(data);
}

export function sha256Sync(data: Uint8Array): Uint8Array {
  const hash = createHash('sha256');
  hash.update(data);
  return new Uint8Array(hash.digest());
}

export function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a[i] ^ b[i];
  }
  return result === 0;
}
