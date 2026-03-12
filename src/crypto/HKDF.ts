/**
 * HKDF - HMAC-based Key Derivation Function (RFC 5869).
 * Uses SHA-256 as the underlying hash, matching Python Reticulum.
 */

import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha256';

/**
 * Derive key material using HKDF-SHA256.
 *
 * @param length - Desired output length in bytes
 * @param deriveFrom - Input key material (IKM)
 * @param salt - Optional salt (if empty, defaults to hash-length zeros)
 * @param context - Optional context/info string
 * @returns Derived key material of specified length
 *
 * Matches Python RNS: HKDF.hkdf(length, derive_from, salt, context)
 */
export function deriveKey(
  length: number,
  deriveFrom: Uint8Array,
  salt?: Uint8Array,
  context?: Uint8Array
): Uint8Array {
  return hkdf(
    sha256,
    deriveFrom,
    salt ?? new Uint8Array(0),
    context ?? new Uint8Array(0),
    length
  );
}
