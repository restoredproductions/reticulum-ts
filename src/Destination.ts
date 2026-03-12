/**
 * Destination - Network endpoints in the Reticulum mesh.
 *
 * A Destination is defined by:
 *   - Type: SINGLE (encrypted), GROUP (shared key), PLAIN (unencrypted), LINK
 *   - Direction: IN (receive), OUT (send)
 *   - Identity: cryptographic identity for SINGLE destinations
 *   - App name + aspects: human-readable naming that hashes to an address
 *
 * The destination hash = truncated_hash(name_hash + identity_hash)
 * This is the 16-byte address used for routing.
 *
 * Wire-compatible with Python RNS Destination.
 */

import { Identity } from './Identity';
import {
  truncatedHash,
  nameHash,
  Token,
  randomBytes,
  HASHLENGTH,
} from './crypto';
import { concatBytes, toHex, shortHex, fromUtf8 } from './utils/bytes';
import { Logger } from './log/Logger';
import {
  Packet,
  PACKET_ANNOUNCE,
  PROPAGATION_BROADCAST,
  DESTINATION_SINGLE,
  DESTINATION_GROUP,
  DESTINATION_PLAIN,
  DESTINATION_LINK,
  CONTEXT_NONE,
  HEADER_1,
} from './Packet';

const TAG = 'Destination';

// Destination types (matching Python RNS)
export const DEST_SINGLE = DESTINATION_SINGLE; // 0x00
export const DEST_GROUP = DESTINATION_GROUP;    // 0x01
export const DEST_PLAIN = DESTINATION_PLAIN;    // 0x02
export const DEST_LINK = DESTINATION_LINK;      // 0x03

// Direction
export const IN = 0x00;
export const OUT = 0x01;

// Proof strategies
export const PROVE_NONE = 0x00;
export const PROVE_APP = 0x01;
export const PROVE_ALL = 0x02;

// Request policies
export const ALLOW_NONE = 0x00;
export const ALLOW_ALL = 0x01;
export const ALLOW_LIST = 0x02;

export type PacketCallback = (data: Uint8Array, packet: Packet) => void;
export type ProofCallback = (packet: Packet) => boolean;
export type LinkRequestCallback = (identity: Identity, data: Uint8Array) => boolean;
export type AnnounceHandler = (
  destinationHash: Uint8Array,
  announcedIdentity: Identity,
  appData: Uint8Array | null
) => void;

export class Destination {
  // Core properties
  readonly type: number;
  readonly direction: number;
  readonly identity: Identity | null;
  readonly appName: string;
  readonly aspects: string[];

  // Derived
  private _hash: Uint8Array | null = null;
  private _hexHash: string | null = null;
  private _nameHash: Uint8Array | null = null;

  // Callbacks
  private _packetCallback: PacketCallback | null = null;
  private _proofCallback: ProofCallback | null = null;
  private _linkRequestCallback: LinkRequestCallback | null = null;
  private _requestHandlers: Map<string, (path: string, data: any, requestId: Uint8Array, linkId: any) => any> = new Map();

  // Proof strategy
  proofStrategy: number = PROVE_NONE;

  // Link acceptance
  acceptsLinks: boolean = true;
  requestPolicy: number = ALLOW_ALL;
  allowedList: Uint8Array[] = [];

  // Group encryption key
  private _groupKey: Uint8Array | null = null;

  // Ratchets
  private _ratchetsEnabled: boolean = false;
  private _ratchetsEnforced: boolean = false;

  // Announce app data
  private _announceAppData: Uint8Array | null = null;
  private _announceAppDataCallback: (() => Uint8Array | null) | null = null;

  constructor(
    identity: Identity | null,
    direction: number,
    type: number,
    appName: string,
    ...aspects: string[]
  ) {
    this.identity = identity;
    this.direction = direction;
    this.type = type;
    this.appName = appName;
    this.aspects = aspects;

    // Validate combinations
    if (type === DEST_SINGLE && !identity) {
      throw new Error('SINGLE destination requires an Identity');
    }
    if (type === DEST_GROUP) {
      // Group destinations use a shared symmetric key
      this._groupKey = null; // Must be set explicitly
    }

    Logger.info(
      `Destination created: ${this.fullName} [${shortHex(this.hash)}] type=${type} dir=${direction === IN ? 'IN' : 'OUT'}`,
      TAG
    );
  }

  /** Full dotted name: appName.aspect1.aspect2 */
  get fullName(): string {
    if (this.aspects.length === 0) return this.appName;
    return this.appName + '.' + this.aspects.join('.');
  }

  /**
   * Compute the name hash (10 bytes).
   * nameHash = SHA-256(fullName UTF-8 bytes) truncated to 10 bytes
   */
  get nameHashBytes(): Uint8Array {
    if (!this._nameHash) {
      this._nameHash = nameHash(fromUtf8(this.fullName));
    }
    return this._nameHash;
  }

  /**
   * Compute the destination hash (16 bytes).
   * For SINGLE: truncatedHash(nameHash + identityHash)
   * For PLAIN:  truncatedHash(nameHash)
   * For GROUP:  truncatedHash(nameHash + groupKey)
   */
  get hash(): Uint8Array {
    if (!this._hash) {
      if (this.type === DEST_SINGLE && this.identity) {
        this._hash = truncatedHash(
          concatBytes(this.nameHashBytes, this.identity.hash)
        );
      } else if (this.type === DEST_PLAIN) {
        this._hash = truncatedHash(this.nameHashBytes);
      } else if (this.type === DEST_GROUP) {
        if (this._groupKey) {
          this._hash = truncatedHash(
            concatBytes(this.nameHashBytes, this._groupKey)
          );
        } else {
          this._hash = truncatedHash(this.nameHashBytes);
        }
      } else {
        this._hash = truncatedHash(this.nameHashBytes);
      }
    }
    return this._hash;
  }

  get hexHash(): string {
    if (!this._hexHash) {
      this._hexHash = toHex(this.hash);
    }
    return this._hexHash;
  }

  // ── Group Key Management ──────────────────────────────────────

  /** Set the group encryption key (for GROUP destinations) */
  setGroupKey(key: Uint8Array): void {
    if (this.type !== DEST_GROUP) {
      throw new Error('Group key can only be set on GROUP destinations');
    }
    this._groupKey = new Uint8Array(key);
    this._hash = null; // Force recalculation
    this._hexHash = null;
    Logger.debug(`Group key set for ${this.fullName}`, TAG);
  }

  /** Generate and set a random group key */
  createGroupKey(): Uint8Array {
    const key = randomBytes(HASHLENGTH);
    this.setGroupKey(key);
    return key;
  }

  // ── Encryption / Decryption ───────────────────────────────────

  /** Encrypt data for this destination */
  encrypt(plaintext: Uint8Array): Uint8Array {
    if (this.type === DEST_SINGLE && this.identity) {
      return this.identity.encrypt(plaintext);
    } else if (this.type === DEST_GROUP && this._groupKey) {
      const token = new Token(
        concatBytes(this._groupKey, this._groupKey) // 64 bytes: sign + encrypt
      );
      return token.encrypt(plaintext);
    } else if (this.type === DEST_PLAIN) {
      return plaintext; // No encryption
    }
    throw new Error(`Cannot encrypt for destination type ${this.type}`);
  }

  /** Decrypt data from this destination */
  decrypt(ciphertext: Uint8Array): Uint8Array {
    if (this.type === DEST_SINGLE && this.identity) {
      return this.identity.decrypt(ciphertext);
    } else if (this.type === DEST_GROUP && this._groupKey) {
      const token = new Token(
        concatBytes(this._groupKey, this._groupKey)
      );
      return token.decrypt(ciphertext);
    } else if (this.type === DEST_PLAIN) {
      return ciphertext;
    }
    throw new Error(`Cannot decrypt for destination type ${this.type}`);
  }

  // ── Announce ──────────────────────────────────────────────────

  /** Set static announce app data */
  setAnnounceAppData(data: Uint8Array | null): void {
    this._announceAppData = data;
  }

  /** Set dynamic announce app data callback */
  setAnnounceAppDataCallback(callback: (() => Uint8Array | null) | null): void {
    this._announceAppDataCallback = callback;
  }

  /** Get current app data for announce */
  getAnnounceAppData(): Uint8Array | undefined {
    if (this._announceAppDataCallback) {
      const data = this._announceAppDataCallback();
      return data ?? undefined;
    }
    return this._announceAppData ?? undefined;
  }

  /**
   * Create an announce packet for this destination.
   * Only valid for IN + SINGLE destinations.
   */
  announce(appData?: Uint8Array): Packet {
    if (this.direction !== IN) {
      throw new Error('Can only announce IN destinations');
    }
    if (this.type !== DEST_SINGLE || !this.identity) {
      throw new Error('Can only announce SINGLE destinations with an Identity');
    }

    const announceAppData = appData ?? this.getAnnounceAppData();
    const announceData = this.identity.createAnnounce(
      this.hash,
      this.nameHashBytes,
      announceAppData
    );

    const pkt = new Packet();
    pkt.headerType = HEADER_1;
    pkt.packetType = PACKET_ANNOUNCE;
    pkt.propagationType = PROPAGATION_BROADCAST;
    pkt.destinationType = DEST_SINGLE;
    pkt.context = CONTEXT_NONE;
    pkt.destinationHash = this.hash;
    pkt.data = announceData;

    Logger.info(`Announcing ${this.fullName} [${shortHex(this.hash)}]`, TAG);
    return pkt;
  }

  // ── Callbacks ─────────────────────────────────────────────────

  /** Set the packet received callback */
  onPacket(callback: PacketCallback): void {
    this._packetCallback = callback;
  }

  /** Set the proof requested callback */
  onProof(callback: ProofCallback): void {
    this._proofCallback = callback;
  }

  /** Set the link request callback */
  onLinkRequest(callback: LinkRequestCallback): void {
    this._linkRequestCallback = callback;
  }

  /** Register a request handler for named paths */
  registerRequestHandler(
    path: string,
    handler: (path: string, data: any, requestId: Uint8Array, linkId: any) => any,
    policy: number = ALLOW_ALL
  ): void {
    this._requestHandlers.set(path, handler);
    Logger.debug(`Registered request handler: ${path} on ${shortHex(this.hash)}`, TAG);
  }

  /** Called by Transport when a packet arrives for this destination */
  receive(packet: Packet): void {
    if (this._packetCallback) {
      try {
        let data = packet.data;
        // Decrypt if needed
        if (this.type === DEST_SINGLE || this.type === DEST_GROUP) {
          try {
            data = this.decrypt(data);
          } catch (e) {
            Logger.error(`Decryption failed for ${shortHex(this.hash)}: ${e}`, TAG);
            return;
          }
        }
        this._packetCallback(data, packet);
      } catch (e) {
        Logger.error(`Packet callback error for ${shortHex(this.hash)}: ${e}`, TAG);
      }
    }
  }

  // ── Ratchets ──────────────────────────────────────────────────

  /** Enable ratcheted forward secrecy */
  enableRatchets(): void {
    if (this.identity) {
      this.identity.enableRatchets();
      this._ratchetsEnabled = true;
      Logger.info(`Ratchets enabled for ${shortHex(this.hash)}`, TAG);
    }
  }

  /** Enforce ratchets (reject non-ratcheted communication) */
  enforceRatchets(): void {
    this._ratchetsEnforced = true;
    Logger.info(`Ratchets enforced for ${shortHex(this.hash)}`, TAG);
  }

  get ratchetsEnabled(): boolean {
    return this._ratchetsEnabled;
  }

  get ratchetsEnforced(): boolean {
    return this._ratchetsEnforced;
  }

  toString(): string {
    const types = ['SINGLE', 'GROUP', 'PLAIN', 'LINK'];
    return `<Destination ${this.fullName} [${shortHex(this.hash)}] ${types[this.type] ?? '?'}>`;
  }
}
