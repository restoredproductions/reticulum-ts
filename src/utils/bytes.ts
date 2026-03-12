/**
 * Uint8Array utility functions.
 *
 * All binary data in reticulum-ts uses Uint8Array (not Node.js Buffer)
 * for full React Native / Expo Go compatibility.
 */

/** Concatenate multiple Uint8Arrays into one */
export function concatBytes(...arrays: Uint8Array[]): Uint8Array {
  let totalLen = 0;
  for (const arr of arrays) totalLen += arr.length;
  const result = new Uint8Array(totalLen);
  let offset = 0;
  for (const arr of arrays) {
    result.set(arr, offset);
    offset += arr.length;
  }
  return result;
}

/** Constant-time comparison of two Uint8Arrays (timing-attack safe) */
export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff === 0;
}

/** Standard equality check (non-constant-time, use for non-secret data) */
export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

/** Convert Uint8Array to hex string */
export function toHex(bytes: Uint8Array): string {
  let hex = '';
  for (let i = 0; i < bytes.length; i++) {
    hex += bytes[i].toString(16).padStart(2, '0');
  }
  return hex;
}

/** Convert hex string to Uint8Array */
export function fromHex(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) throw new Error('Invalid hex string length');
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

/** Convert UTF-8 string to Uint8Array */
export function fromUtf8(str: string): Uint8Array {
  const encoder = new TextEncoder();
  return encoder.encode(str);
}

/** Convert Uint8Array to UTF-8 string */
export function toUtf8(bytes: Uint8Array): string {
  const decoder = new TextDecoder();
  return decoder.decode(bytes);
}

/** Truncate a hash to the specified number of bytes */
export function truncateHash(hash: Uint8Array, length: number): Uint8Array {
  return hash.slice(0, length);
}

/** XOR two Uint8Arrays (must be same length) */
export function xorBytes(a: Uint8Array, b: Uint8Array): Uint8Array {
  if (a.length !== b.length) throw new Error('XOR: arrays must be same length');
  const result = new Uint8Array(a.length);
  for (let i = 0; i < a.length; i++) {
    result[i] = a[i] ^ b[i];
  }
  return result;
}

/** Create a zero-filled Uint8Array of given length */
export function zeroBytes(length: number): Uint8Array {
  return new Uint8Array(length);
}

/** Get a truncated hex string for display (e.g., "ab3f...c219") */
export function shortHex(bytes: Uint8Array, showBytes: number = 4): string {
  const hex = toHex(bytes);
  if (hex.length <= showBytes * 4) return hex;
  return hex.slice(0, showBytes * 2) + '...' + hex.slice(-showBytes * 2);
}

/** Read a big-endian uint16 from bytes at offset */
export function readUint16BE(bytes: Uint8Array, offset: number = 0): number {
  return (bytes[offset] << 8) | bytes[offset + 1];
}

/** Write a big-endian uint16 to bytes at offset */
export function writeUint16BE(
  bytes: Uint8Array,
  value: number,
  offset: number = 0
): void {
  bytes[offset] = (value >> 8) & 0xff;
  bytes[offset + 1] = value & 0xff;
}

/** Read a big-endian uint32 from bytes at offset */
export function readUint32BE(bytes: Uint8Array, offset: number = 0): number {
  return (
    ((bytes[offset] << 24) |
      (bytes[offset + 1] << 16) |
      (bytes[offset + 2] << 8) |
      bytes[offset + 3]) >>>
    0
  );
}

/** Write a big-endian uint32 to bytes at offset */
export function writeUint32BE(
  bytes: Uint8Array,
  value: number,
  offset: number = 0
): void {
  bytes[offset] = (value >> 24) & 0xff;
  bytes[offset + 1] = (value >> 16) & 0xff;
  bytes[offset + 2] = (value >> 8) & 0xff;
  bytes[offset + 3] = value & 0xff;
}
