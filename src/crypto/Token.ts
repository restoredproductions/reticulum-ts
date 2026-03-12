/**
 * Token - Modified Fernet-like encryption envelope.
 *
 * Format: IV (16B) || AES-CBC-ciphertext || HMAC-SHA256 (32B)
 *
 * Unlike standard Fernet, Reticulum's Token:
 * - Has no version byte or timestamp
 * - Uses AES-128-CBC or AES-256-CBC
 * - TOKEN_OVERHEAD = 48 bytes (16 IV + 32 HMAC)
 *
 * Key layout:
 *   AES-128: 32-byte key = 16B signing key + 16B encryption key
 *   AES-256: 64-byte key = 32B signing key + 32B encryption key
 */

import { cbc } from '@noble/ciphers/aes';
import { pad, unpad } from './PKCS7';
import { hmacSha256 } from './HMAC';
import { randomBytes } from './Random';
import { constantTimeEqual, concatBytes } from '../utils/bytes';
import { Logger, LogLevel } from '../log/Logger';

const TAG = 'Crypto.Token';

export const TOKEN_OVERHEAD = 48; // 16 IV + 32 HMAC
const IV_LENGTH = 16;
const HMAC_LENGTH = 32;

export class Token {
  private signingKey: Uint8Array;
  private encryptionKey: Uint8Array;

  /**
   * @param key - Combined key (32 bytes for AES-128, 64 bytes for AES-256)
   *   First half: signing key (HMAC)
   *   Second half: encryption key (AES)
   */
  constructor(key: Uint8Array) {
    if (key.length !== 32 && key.length !== 64) {
      throw new Error('Token key must be 32 bytes (AES-128) or 64 bytes (AES-256)');
    }
    const half = key.length / 2;
    this.signingKey = key.slice(0, half);
    this.encryptionKey = key.slice(half);
  }

  /** Generate a random key for AES-256 (default) or AES-128 */
  static generateKey(aes256: boolean = true): Uint8Array {
    return randomBytes(aes256 ? 64 : 32);
  }

  /**
   * Encrypt plaintext → Token envelope.
   * Output: IV (16B) || ciphertext || HMAC (32B)
   */
  encrypt(plaintext: Uint8Array): Uint8Array {
    const iv = randomBytes(IV_LENGTH);
    const padded = pad(plaintext);

    // Encrypt
    const cipher = cbc(this.encryptionKey, iv);
    const ciphertext = cipher.encrypt(padded);

    // HMAC over IV + ciphertext
    const ivAndCipher = concatBytes(iv, ciphertext);
    const mac = hmacSha256(this.signingKey, ivAndCipher);

    // Final token: IV || ciphertext || HMAC
    const token = concatBytes(ivAndCipher, mac);

    Logger.log(
      `Token encrypt: ${plaintext.length}B → ${token.length}B (overhead=${TOKEN_OVERHEAD}B)`,
      LogLevel.EXTREME,
      TAG
    );
    return token;
  }

  /**
   * Decrypt Token envelope → plaintext.
   * Input: IV (16B) || ciphertext || HMAC (32B)
   * Throws on HMAC mismatch or decryption failure.
   */
  decrypt(token: Uint8Array): Uint8Array {
    if (token.length < TOKEN_OVERHEAD + 16) {
      throw new Error('Token too short to contain valid data');
    }

    // Split: IV || ciphertext || HMAC
    const iv = token.slice(0, IV_LENGTH);
    const ciphertext = token.slice(IV_LENGTH, token.length - HMAC_LENGTH);
    const receivedMac = token.slice(token.length - HMAC_LENGTH);

    // Verify HMAC first (authenticate-then-decrypt)
    const ivAndCipher = token.slice(0, token.length - HMAC_LENGTH);
    const expectedMac = hmacSha256(this.signingKey, ivAndCipher);

    if (!constantTimeEqual(receivedMac, expectedMac)) {
      Logger.log('Token HMAC verification failed', LogLevel.ERROR, TAG);
      throw new Error('Token HMAC verification failed');
    }

    // Decrypt
    const cipher = cbc(this.encryptionKey, iv);
    const padded = cipher.decrypt(ciphertext);
    const plaintext = unpad(padded);

    Logger.log(
      `Token decrypt: ${token.length}B → ${plaintext.length}B`,
      LogLevel.EXTREME,
      TAG
    );
    return plaintext;
  }

  /**
   * Verify HMAC without decrypting (for proof validation).
   */
  verifyHmac(token: Uint8Array): boolean {
    if (token.length < TOKEN_OVERHEAD + 16) return false;

    const ivAndCipher = token.slice(0, token.length - HMAC_LENGTH);
    const receivedMac = token.slice(token.length - HMAC_LENGTH);
    const expectedMac = hmacSha256(this.signingKey, ivAndCipher);

    return constantTimeEqual(receivedMac, expectedMac);
  }
}
