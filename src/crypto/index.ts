/**
 * Crypto module - unified exports for all cryptographic primitives.
 *
 * All crypto in reticulum-ts uses @noble/* (pure JS, audited, tree-shakeable).
 * Wire-compatible with Python Reticulum's cryptographic operations.
 */

export { randomBytes, initRandom } from './Random';
export { sha256, sha512, fullHash, truncatedHash, nameHash, HASHLENGTH, TRUNCATED_HASHLENGTH, NAME_HASH_LENGTH } from './Hashes';
export { hmacSha256, HMACBuilder, HMAC_LENGTH } from './HMAC';
export { deriveKey } from './HKDF';
export { pad as pkcs7Pad, unpad as pkcs7Unpad } from './PKCS7';
export {
  encryptAES_CBC,
  decryptAES_CBC,
  AES_128_KEY_LENGTH,
  AES_256_KEY_LENGTH,
  AES_BLOCK_SIZE,
  AES_IV_LENGTH,
} from './AES';
export {
  X25519PrivateKey,
  X25519PublicKey,
  X25519_KEY_LENGTH,
} from './X25519';
export {
  Ed25519PrivateKey,
  Ed25519PublicKey,
  ED25519_SEED_LENGTH,
  ED25519_PUBKEY_LENGTH,
  ED25519_SIG_LENGTH,
} from './Ed25519';
export { Token, TOKEN_OVERHEAD } from './Token';

/** Identity key sizes matching Python Reticulum */
export const KEYSIZE = 32; // 256 bits per key (X25519 or Ed25519)
export const IDENTITY_KEY_LENGTH = 64; // 512 bits total = 256 X25519 + 256 Ed25519
