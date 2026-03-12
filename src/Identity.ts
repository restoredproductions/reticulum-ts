/**
 * Identity - Cryptographic identity management.
 *
 * An Identity is a 512-bit key pair:
 *   - 256-bit X25519 key for encryption (ECDH)
 *   - 256-bit Ed25519 key for signing
 *
 * The "address" of an identity is the SHA-256 hash of the public keys,
 * truncated to 128 bits (16 bytes).
 *
 * Wire-compatible with Python RNS Identity.
 */

import {
  X25519PrivateKey,
  X25519PublicKey,
  X25519_KEY_LENGTH,
  Ed25519PrivateKey,
  Ed25519PublicKey,
  ED25519_SEED_LENGTH,
  ED25519_SIG_LENGTH,
  sha256,
  truncatedHash,
  fullHash,
  nameHash,
  deriveKey,
  Token,
  TOKEN_OVERHEAD,
  KEYSIZE,
  IDENTITY_KEY_LENGTH,
  randomBytes,
  HASHLENGTH,
  TRUNCATED_HASHLENGTH,
  NAME_HASH_LENGTH,
} from './crypto';
import { concatBytes, toHex, shortHex, constantTimeEqual } from './utils/bytes';
import { Logger, LogLevel } from './log/Logger';

const TAG = 'Identity';

/** Size of a Reticulum announce signature */
export const ANNOUNCE_SIGNATURE_SIZE = ED25519_SIG_LENGTH; // 64 bytes

/** Ratchet management constants */
const RATCHET_COUNT = 512;
const RATCHET_EXPIRY_MS = 30 * 24 * 60 * 60 * 1000; // 30 days
const RATCHET_ROTATION_MS = 30 * 60 * 1000; // 30 minutes

/** Known destination storage (in-memory, persisted via Storage module) */
const knownDestinations: Map<string, Uint8Array> = new Map(); // hash_hex → public_key (64B)
const knownRatchets: Map<string, Uint8Array[]> = new Map(); // hash_hex → ratchet keys

export class Identity {
  // Key pairs
  private _encPrivKey: X25519PrivateKey | null = null;
  private _sigPrivKey: Ed25519PrivateKey | null = null;
  private _encPubKey: X25519PublicKey | null = null;
  private _sigPubKey: Ed25519PublicKey | null = null;

  // Derived addresses
  private _hash: Uint8Array | null = null;
  private _hexHash: string | null = null;

  // Ratchet state
  private _ratchets: Uint8Array[] = [];
  private _lastRatchetRotation: number = 0;

  /** Create a new identity (generates fresh keys) */
  constructor(createKeys: boolean = true) {
    if (createKeys) {
      this.createKeys();
    }
  }

  /** Generate new X25519 + Ed25519 key pairs */
  private createKeys(): void {
    this._encPrivKey = X25519PrivateKey.generate();
    this._sigPrivKey = Ed25519PrivateKey.generate();
    this._encPubKey = this._encPrivKey.publicKey();
    this._sigPubKey = this._sigPrivKey.publicKey();
    this._hash = null; // Force recalculation
    this._hexHash = null;

    Logger.info(`Identity created: ${this.hexHash.slice(0, 12)}...`, TAG);
  }

  /** Get the public key bytes (64 bytes: 32B enc + 32B sig) */
  getPublicKey(): Uint8Array {
    if (!this._encPubKey || !this._sigPubKey) {
      throw new Error('Identity has no public keys');
    }
    return concatBytes(this._encPubKey.publicBytes, this._sigPubKey.publicBytes);
  }

  /**
   * Load a public key from bytes (64 bytes).
   * Creates a receive-only identity (no private keys).
   */
  static fromPublicKey(publicKeyBytes: Uint8Array): Identity {
    if (publicKeyBytes.length !== IDENTITY_KEY_LENGTH) {
      throw new Error(`Public key must be ${IDENTITY_KEY_LENGTH} bytes, got ${publicKeyBytes.length}`);
    }
    const id = new Identity(false);
    id._encPubKey = X25519PublicKey.fromPublicBytes(publicKeyBytes.slice(0, X25519_KEY_LENGTH));
    id._sigPubKey = Ed25519PublicKey.fromPublicBytes(publicKeyBytes.slice(X25519_KEY_LENGTH));
    Logger.debug(`Identity loaded from public key: ${id.hexHash.slice(0, 12)}...`, TAG);
    return id;
  }

  /**
   * Load from private key bytes (64 bytes: 32B enc seed + 32B sig seed).
   */
  static fromPrivateKey(privateKeyBytes: Uint8Array): Identity {
    if (privateKeyBytes.length !== IDENTITY_KEY_LENGTH) {
      throw new Error(`Private key must be ${IDENTITY_KEY_LENGTH} bytes`);
    }
    const id = new Identity(false);
    id._encPrivKey = X25519PrivateKey.fromPrivateBytes(privateKeyBytes.slice(0, X25519_KEY_LENGTH));
    id._sigPrivKey = Ed25519PrivateKey.fromPrivateBytes(privateKeyBytes.slice(X25519_KEY_LENGTH));
    id._encPubKey = id._encPrivKey.publicKey();
    id._sigPubKey = id._sigPrivKey.publicKey();
    Logger.debug(`Identity loaded from private key: ${id.hexHash.slice(0, 12)}...`, TAG);
    return id;
  }

  /** Get private key bytes for storage (64 bytes) */
  getPrivateKey(): Uint8Array {
    if (!this._encPrivKey || !this._sigPrivKey) {
      throw new Error('Identity has no private keys');
    }
    return concatBytes(this._encPrivKey.privateBytes, this._sigPrivKey.seed);
  }

  /** Does this identity have private keys (can sign/decrypt)? */
  get hasPrivateKey(): boolean {
    return this._encPrivKey !== null && this._sigPrivKey !== null;
  }

  /** Get the identity hash (truncated SHA-256 of public keys, 16 bytes) */
  get hash(): Uint8Array {
    if (!this._hash) {
      this._hash = truncatedHash(this.getPublicKey());
    }
    return this._hash;
  }

  /** Get the hex-encoded identity hash */
  get hexHash(): string {
    if (!this._hexHash) {
      this._hexHash = toHex(this.hash);
    }
    return this._hexHash;
  }

  // ── Encryption ──────────────────────────────────────────────────

  /**
   * Encrypt plaintext for this identity using ephemeral X25519 ECDH.
   *
   * Format: ephemeral_pubkey (32B) || Token(ciphertext)
   *
   * This matches Python RNS: Identity.encrypt()
   */
  encrypt(plaintext: Uint8Array): Uint8Array {
    if (!this._encPubKey) {
      throw new Error('Cannot encrypt: no public key');
    }

    // Generate ephemeral X25519 key pair
    const ephemeralKey = X25519PrivateKey.generate();
    const ephemeralPub = ephemeralKey.publicKey();

    // ECDH to get shared secret
    const sharedSecret = ephemeralKey.exchange(this._encPubKey);

    // Derive encryption key via HKDF
    const derivedKey = deriveKey(64, sharedSecret); // 64 bytes for AES-256 Token

    // Encrypt with Token (modified Fernet)
    const token = new Token(derivedKey);
    const ciphertext = token.encrypt(plaintext);

    // Prepend ephemeral public key
    const result = concatBytes(ephemeralPub.publicBytes, ciphertext);

    Logger.log(
      `Encrypted ${plaintext.length}B → ${result.length}B for ${shortHex(this.hash)}`,
      LogLevel.DEBUG,
      TAG
    );
    return result;
  }

  /**
   * Decrypt ciphertext sent to this identity.
   *
   * Input: ephemeral_pubkey (32B) || Token(ciphertext)
   */
  decrypt(data: Uint8Array): Uint8Array {
    if (!this._encPrivKey) {
      throw new Error('Cannot decrypt: no private key');
    }

    if (data.length < X25519_KEY_LENGTH + TOKEN_OVERHEAD + 16) {
      throw new Error('Ciphertext too short');
    }

    // Extract ephemeral public key
    const ephemeralPub = X25519PublicKey.fromPublicBytes(data.slice(0, X25519_KEY_LENGTH));
    const tokenData = data.slice(X25519_KEY_LENGTH);

    // ECDH to recover shared secret
    const sharedSecret = this._encPrivKey.exchange(ephemeralPub);

    // Derive decryption key
    const derivedKey = deriveKey(64, sharedSecret);

    // Decrypt with Token
    const token = new Token(derivedKey);
    const plaintext = token.decrypt(tokenData);

    Logger.log(
      `Decrypted ${data.length}B → ${plaintext.length}B`,
      LogLevel.DEBUG,
      TAG
    );
    return plaintext;
  }

  // ── Signing ─────────────────────────────────────────────────────

  /** Sign a message with this identity's Ed25519 key */
  sign(message: Uint8Array): Uint8Array {
    if (!this._sigPrivKey) {
      throw new Error('Cannot sign: no private key');
    }
    return this._sigPrivKey.sign(message);
  }

  /** Verify a signature against this identity's public key */
  validate(signature: Uint8Array, message: Uint8Array): boolean {
    if (!this._sigPubKey) {
      throw new Error('Cannot validate: no public key');
    }
    return this._sigPubKey.verify(signature, message);
  }

  // ── Announce Handling ───────────────────────────────────────────

  /**
   * Create announce data for a destination.
   *
   * Announce format:
   *   public_key (64B) || name_hash (10B) || random_hash (10B) || signature (64B) || [app_data]
   *
   * The signature covers: dest_hash + public_key + name_hash + random_hash + [app_data]
   */
  createAnnounce(
    destinationHash: Uint8Array,
    nameHashBytes: Uint8Array,
    appData?: Uint8Array
  ): Uint8Array {
    if (!this.hasPrivateKey) {
      throw new Error('Cannot create announce: no private key');
    }

    const publicKey = this.getPublicKey();
    const randomHash = randomBytes(10);

    // Build message to sign
    const signedParts = [destinationHash, publicKey, nameHashBytes, randomHash];
    if (appData) signedParts.push(appData);
    const signedMessage = concatBytes(...signedParts);

    const signature = this.sign(signedMessage);

    // Build announce data
    const parts = [publicKey, nameHashBytes, randomHash, signature];
    if (appData) parts.push(appData);

    const announceData = concatBytes(...parts);
    Logger.info(
      `Created announce for ${shortHex(destinationHash)}: ${announceData.length}B`,
      TAG
    );
    return announceData;
  }

  /**
   * Validate an announce packet.
   *
   * Returns the Identity if valid, null if invalid.
   */
  static validateAnnounce(
    announceData: Uint8Array,
    destinationHash: Uint8Array
  ): Identity | null {
    // Minimum size: pubkey(64) + name_hash(10) + random_hash(10) + signature(64) = 148
    if (announceData.length < IDENTITY_KEY_LENGTH + NAME_HASH_LENGTH + 10 + ED25519_SIG_LENGTH) {
      Logger.warn('Announce data too short', TAG);
      return null;
    }

    let offset = 0;

    // Extract public key (64 bytes)
    const publicKey = announceData.slice(offset, offset + IDENTITY_KEY_LENGTH);
    offset += IDENTITY_KEY_LENGTH;

    // Extract name hash (10 bytes)
    const announcedNameHash = announceData.slice(offset, offset + NAME_HASH_LENGTH);
    offset += NAME_HASH_LENGTH;

    // Extract random hash (10 bytes)
    const announceRandomHash = announceData.slice(offset, offset + 10);
    offset += 10;

    // Extract signature (64 bytes)
    const signature = announceData.slice(offset, offset + ED25519_SIG_LENGTH);
    offset += ED25519_SIG_LENGTH;

    // Remaining bytes are app_data
    const appData = offset < announceData.length ? announceData.slice(offset) : undefined;

    // Build the signed message
    const signedParts = [destinationHash, publicKey, announcedNameHash, announceRandomHash];
    if (appData) signedParts.push(appData);
    const signedMessage = concatBytes(...signedParts);

    // Create identity from public key and verify signature
    try {
      const identity = Identity.fromPublicKey(publicKey);
      const valid = identity.validate(signature, signedMessage);

      if (!valid) {
        Logger.warn(`Announce signature invalid for ${shortHex(destinationHash)}`, TAG);
        return null;
      }

      // Verify that the announced destination hash matches the identity
      const expectedHash = truncatedHash(
        concatBytes(announcedNameHash, identity.hash)
      );
      if (!constantTimeEqual(expectedHash, destinationHash)) {
        Logger.warn(`Announce destination hash mismatch for ${shortHex(destinationHash)}`, TAG);
        return null;
      }

      // Remember this identity
      Identity.remember(destinationHash, publicKey, appData);

      Logger.info(`Announce validated for ${shortHex(destinationHash)}`, TAG);
      return identity;
    } catch (e) {
      Logger.error(`Announce validation error: ${e}`, TAG);
      return null;
    }
  }

  // ── Identity Storage ────────────────────────────────────────────

  /** Remember a known destination's public key */
  static remember(
    destinationHash: Uint8Array,
    publicKey: Uint8Array,
    appData?: Uint8Array
  ): void {
    const key = toHex(destinationHash);
    knownDestinations.set(key, new Uint8Array(publicKey));
    Logger.debug(`Remembered identity ${shortHex(destinationHash)}`, TAG);
  }

  /** Recall a known destination's Identity from its hash */
  static recall(destinationHash: Uint8Array): Identity | null {
    const key = toHex(destinationHash);
    const pubKey = knownDestinations.get(key);
    if (!pubKey) return null;
    return Identity.fromPublicKey(pubKey);
  }

  /** Check if we know a destination's identity */
  static isKnown(destinationHash: Uint8Array): boolean {
    return knownDestinations.has(toHex(destinationHash));
  }

  /** Get the full hash of data (SHA-256, 32 bytes) - static utility */
  static fullHash(data: Uint8Array): Uint8Array {
    return fullHash(data);
  }

  /** Get the truncated hash of data (16 bytes) - static utility */
  static truncatedHash(data: Uint8Array): Uint8Array {
    return truncatedHash(data);
  }

  // ── Ratchets ────────────────────────────────────────────────────

  /** Enable ratcheting for forward secrecy */
  enableRatchets(): void {
    if (this._ratchets.length === 0) {
      this.rotateRatchets();
    }
  }

  /** Rotate ratchet keys */
  rotateRatchets(): void {
    const now = Date.now();
    if (now - this._lastRatchetRotation < RATCHET_ROTATION_MS) return;

    const newKey = randomBytes(HASHLENGTH);
    this._ratchets.unshift(newKey);

    // Trim to max count
    if (this._ratchets.length > RATCHET_COUNT) {
      this._ratchets = this._ratchets.slice(0, RATCHET_COUNT);
    }

    this._lastRatchetRotation = now;
    Logger.debug(
      `Rotated ratchet for ${shortHex(this.hash)}, ${this._ratchets.length} keys`,
      TAG
    );
  }

  /** Get current ratchet key */
  getCurrentRatchet(): Uint8Array | null {
    return this._ratchets.length > 0 ? this._ratchets[0] : null;
  }

  toString(): string {
    return `<Identity ${this.hexHash.slice(0, 12)}...>`;
  }
}
