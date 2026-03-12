/**
 * Hash functions: SHA-256 and SHA-512.
 * Direct wrappers around @noble/hashes for Reticulum compatibility.
 */

import { sha256 as _sha256 } from '@noble/hashes/sha256';
import { sha512 as _sha512 } from '@noble/hashes/sha512';

/** Compute SHA-256 hash (32 bytes) */
export function sha256(data: Uint8Array): Uint8Array {
  return _sha256(data);
}

/** Compute SHA-512 hash (64 bytes) */
export function sha512(data: Uint8Array): Uint8Array {
  return _sha512(data);
}

/**
 * Reticulum "full hash" - SHA-256 of input (32 bytes).
 * Used for destination hashing, packet dedup, etc.
 */
export function fullHash(data: Uint8Array): Uint8Array {
  return sha256(data);
}

/**
 * Reticulum "truncated hash" - SHA-256 truncated to 16 bytes (128 bits).
 * Used for destination addresses and routing.
 */
export function truncatedHash(data: Uint8Array): Uint8Array {
  return sha256(data).slice(0, 16);
}

/** Reticulum "name hash" - SHA-256 truncated to 10 bytes (80 bits). */
export function nameHash(data: Uint8Array): Uint8Array {
  return sha256(data).slice(0, 10);
}

/** Hash length constants matching Python RNS */
export const HASHLENGTH = 32;          // SHA-256 full output (256 bits)
export const TRUNCATED_HASHLENGTH = 16; // Truncated hash (128 bits)
export const NAME_HASH_LENGTH = 10;     // Name hash (80 bits)
