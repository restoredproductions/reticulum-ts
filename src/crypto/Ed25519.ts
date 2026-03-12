/**
 * Ed25519 digital signatures.
 * Matches Python Reticulum's Ed25519PrivateKey/Ed25519PublicKey API.
 */

import { ed25519 } from '@noble/curves/ed25519';
import { randomBytes } from './Random';
import { Logger, LogLevel } from '../log/Logger';
import { toHex } from '../utils/bytes';

const TAG = 'Crypto.Ed25519';

export const ED25519_SEED_LENGTH = 32;    // 256-bit seed (private key input)
export const ED25519_PUBKEY_LENGTH = 32;  // 256-bit public key
export const ED25519_SIG_LENGTH = 64;     // 512-bit signature

export class Ed25519PublicKey {
  private _publicBytes: Uint8Array;

  constructor(publicBytes: Uint8Array) {
    if (publicBytes.length !== ED25519_PUBKEY_LENGTH) {
      throw new Error(`Ed25519 public key must be ${ED25519_PUBKEY_LENGTH} bytes`);
    }
    this._publicBytes = new Uint8Array(publicBytes);
  }

  static fromPublicBytes(data: Uint8Array): Ed25519PublicKey {
    return new Ed25519PublicKey(data);
  }

  /** Verify a signature against this public key */
  verify(signature: Uint8Array, message: Uint8Array): boolean {
    try {
      const valid = ed25519.verify(signature, message, this._publicBytes);
      Logger.log(
        `Ed25519 verify: ${valid ? 'VALID' : 'INVALID'} (key=${toHex(this._publicBytes).slice(0, 12)}...)`,
        LogLevel.EXTREME,
        TAG
      );
      return valid;
    } catch (e) {
      Logger.log(
        `Ed25519 verify failed with error: ${e}`,
        LogLevel.DEBUG,
        TAG
      );
      return false;
    }
  }

  get publicBytes(): Uint8Array {
    return new Uint8Array(this._publicBytes);
  }
}

export class Ed25519PrivateKey {
  private _seed: Uint8Array;
  private _publicKey: Ed25519PublicKey | null = null;

  private constructor(seed: Uint8Array) {
    this._seed = new Uint8Array(seed);
  }

  /** Generate a new random Ed25519 key pair */
  static generate(): Ed25519PrivateKey {
    const seed = randomBytes(ED25519_SEED_LENGTH);
    const key = new Ed25519PrivateKey(seed);
    Logger.log('Generated new Ed25519 key pair', LogLevel.DEBUG, TAG);
    return key;
  }

  /** Load from existing seed bytes (32 bytes) */
  static fromPrivateBytes(seed: Uint8Array): Ed25519PrivateKey {
    if (seed.length !== ED25519_SEED_LENGTH) {
      throw new Error(`Ed25519 seed must be ${ED25519_SEED_LENGTH} bytes`);
    }
    return new Ed25519PrivateKey(seed);
  }

  /** Get the corresponding public key */
  publicKey(): Ed25519PublicKey {
    if (!this._publicKey) {
      const pubBytes = ed25519.getPublicKey(this._seed);
      this._publicKey = new Ed25519PublicKey(pubBytes);
    }
    return this._publicKey;
  }

  /** Sign a message */
  sign(message: Uint8Array): Uint8Array {
    const sig = ed25519.sign(message, this._seed);
    Logger.log(
      `Ed25519 sign: ${message.length}B message → ${sig.length}B signature`,
      LogLevel.EXTREME,
      TAG
    );
    return sig;
  }

  get seed(): Uint8Array {
    return new Uint8Array(this._seed);
  }
}
