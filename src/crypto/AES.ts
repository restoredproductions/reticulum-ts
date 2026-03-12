/**
 * AES-CBC encryption (128-bit and 256-bit).
 * Uses @noble/ciphers for pure-JS, audited AES.
 * Matches Python Reticulum's AES_128_CBC and AES_256_CBC classes.
 */

import { cbc } from '@noble/ciphers/aes';
import { pad, unpad } from './PKCS7';
import { randomBytes } from './Random';
import { Logger, LogLevel } from '../log/Logger';

const TAG = 'Crypto.AES';
const IV_LENGTH = 16; // 128-bit IV for CBC mode

/**
 * AES-CBC encrypt with PKCS7 padding.
 * Returns: IV (16 bytes) || ciphertext
 */
export function encryptAES_CBC(
  plaintext: Uint8Array,
  key: Uint8Array
): Uint8Array {
  const iv = randomBytes(IV_LENGTH);
  const padded = pad(plaintext);

  const cipher = cbc(key, iv);
  const ciphertext = cipher.encrypt(padded);

  // Prepend IV to ciphertext (same format as Python RNS)
  const result = new Uint8Array(IV_LENGTH + ciphertext.length);
  result.set(iv, 0);
  result.set(ciphertext, IV_LENGTH);

  Logger.log(
    `AES-CBC encrypt: ${plaintext.length}B plain → ${result.length}B cipher (key=${key.length * 8}bit)`,
    LogLevel.EXTREME,
    TAG
  );
  return result;
}

/**
 * AES-CBC decrypt. Input: IV (16 bytes) || ciphertext.
 * Returns plaintext with PKCS7 padding removed.
 */
export function decryptAES_CBC(
  ivAndCiphertext: Uint8Array,
  key: Uint8Array
): Uint8Array {
  if (ivAndCiphertext.length < IV_LENGTH + 16) {
    throw new Error('AES-CBC: Ciphertext too short');
  }

  const iv = ivAndCiphertext.slice(0, IV_LENGTH);
  const ciphertext = ivAndCiphertext.slice(IV_LENGTH);

  const cipher = cbc(key, iv);
  const padded = cipher.decrypt(ciphertext);
  const plaintext = unpad(padded);

  Logger.log(
    `AES-CBC decrypt: ${ivAndCiphertext.length}B cipher → ${plaintext.length}B plain (key=${key.length * 8}bit)`,
    LogLevel.EXTREME,
    TAG
  );
  return plaintext;
}

/** Key length constants */
export const AES_128_KEY_LENGTH = 16; // 128-bit key
export const AES_256_KEY_LENGTH = 32; // 256-bit key
export const AES_BLOCK_SIZE = 16;
export { IV_LENGTH as AES_IV_LENGTH };
