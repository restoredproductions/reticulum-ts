/**
 * HMAC-SHA256 implementation.
 * Wraps @noble/hashes hmac for Reticulum wire compatibility.
 */

import { hmac } from '@noble/hashes/hmac';
import { sha256 } from '@noble/hashes/sha256';

/** HMAC output length in bytes */
export const HMAC_LENGTH = 32;

/** Compute HMAC-SHA256 */
export function hmacSha256(key: Uint8Array, data: Uint8Array): Uint8Array {
  return hmac(sha256, key, data);
}

/**
 * Incremental HMAC builder (mirrors Python's hmac interface).
 * Allows calling update() multiple times before digest().
 */
export class HMACBuilder {
  private _key: Uint8Array;
  private _chunks: Uint8Array[] = [];

  constructor(key: Uint8Array) {
    this._key = key;
  }

  update(data: Uint8Array): HMACBuilder {
    this._chunks.push(data);
    return this;
  }

  digest(): Uint8Array {
    // Concatenate all chunks
    let totalLen = 0;
    for (const chunk of this._chunks) totalLen += chunk.length;
    const combined = new Uint8Array(totalLen);
    let offset = 0;
    for (const chunk of this._chunks) {
      combined.set(chunk, offset);
      offset += chunk.length;
    }
    return hmacSha256(this._key, combined);
  }
}
