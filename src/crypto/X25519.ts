/**
 * X25519 Elliptic Curve Diffie-Hellman key exchange.
 * Matches Python Reticulum's X25519PrivateKey/X25519PublicKey API.
 */

import { x25519 } from '@noble/curves/ed25519';
import { randomBytes } from './Random';
import { Logger, LogLevel } from '../log/Logger';
import { toHex } from '../utils/bytes';

const TAG = 'Crypto.X25519';

export const X25519_KEY_LENGTH = 32; // 256 bits

export class X25519PublicKey {
  private _publicBytes: Uint8Array;

  constructor(publicBytes: Uint8Array) {
    if (publicBytes.length !== X25519_KEY_LENGTH) {
      throw new Error(`X25519 public key must be ${X25519_KEY_LENGTH} bytes`);
    }
    this._publicBytes = new Uint8Array(publicBytes);
  }

  static fromPublicBytes(data: Uint8Array): X25519PublicKey {
    return new X25519PublicKey(data);
  }

  get publicBytes(): Uint8Array {
    return new Uint8Array(this._publicBytes);
  }
}

export class X25519PrivateKey {
  private _privateBytes: Uint8Array;
  private _publicKey: X25519PublicKey | null = null;

  private constructor(privateBytes: Uint8Array) {
    this._privateBytes = new Uint8Array(privateBytes);
  }

  /** Generate a new random X25519 key pair */
  static generate(): X25519PrivateKey {
    const privBytes = randomBytes(X25519_KEY_LENGTH);
    const key = new X25519PrivateKey(privBytes);
    Logger.log('Generated new X25519 key pair', LogLevel.DEBUG, TAG);
    return key;
  }

  /** Load from existing private key bytes */
  static fromPrivateBytes(data: Uint8Array): X25519PrivateKey {
    if (data.length !== X25519_KEY_LENGTH) {
      throw new Error(`X25519 private key must be ${X25519_KEY_LENGTH} bytes`);
    }
    return new X25519PrivateKey(data);
  }

  /** Get the corresponding public key */
  publicKey(): X25519PublicKey {
    if (!this._publicKey) {
      const pubBytes = x25519.getPublicKey(this._privateBytes);
      this._publicKey = new X25519PublicKey(pubBytes);
    }
    return this._publicKey;
  }

  /** Perform ECDH key exchange with a peer's public key */
  exchange(peerPublicKey: X25519PublicKey): Uint8Array {
    const shared = x25519.getSharedSecret(
      this._privateBytes,
      peerPublicKey.publicBytes
    );
    Logger.log(
      `X25519 exchange complete: shared=${toHex(shared).slice(0, 16)}...`,
      LogLevel.EXTREME,
      TAG
    );
    return shared;
  }

  get privateBytes(): Uint8Array {
    return new Uint8Array(this._privateBytes);
  }
}
