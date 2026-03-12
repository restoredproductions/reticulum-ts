/**
 * Link - Encrypted peer-to-peer communication over Reticulum.
 *
 * A Link provides a bidirectional encrypted tunnel between two Reticulum
 * endpoints, established via a 3-packet handshake:
 *   1. Link Request (initiator → destination)
 *   2. Link Proof (destination → initiator, via reverse path)
 *   3. Implicit confirmation (first data packet)
 *
 * Encryption: Ephemeral X25519 ECDH → HKDF → AES-256-CBC (Token)
 * Authentication: Ed25519 signatures
 *
 * Wire-compatible with Python RNS Link.
 */

import { Logger, LogLevel } from './log/Logger';
import {
  X25519PrivateKey,
  X25519PublicKey,
  X25519_KEY_LENGTH,
  Ed25519PrivateKey,
  Ed25519PublicKey,
  ED25519_SIG_LENGTH,
  Token,
  TOKEN_OVERHEAD,
  deriveKey,
  randomBytes,
  truncatedHash,
  fullHash,
  HASHLENGTH,
  TRUNCATED_HASHLENGTH,
} from './crypto';
import {
  Packet,
  PacketReceipt,
  MTU,
  PACKET_DATA,
  PACKET_LINKREQUEST,
  PACKET_PROOF,
  HEADER_1,
  HEADER_2,
  PROPAGATION_BROADCAST,
  DESTINATION_LINK,
  DESTINATION_SINGLE,
  CONTEXT_NONE,
  CONTEXT_KEEPALIVE,
  CONTEXT_LINKIDENTIFY,
  CONTEXT_LINKCLOSE,
  CONTEXT_LINKPROOF,
  CONTEXT_LRRTT,
  CONTEXT_CHANNEL,
  CONTEXT_REQUEST,
  CONTEXT_RESPONSE,
} from './Packet';
import { Destination, DEST_SINGLE, IN, OUT } from './Destination';
import { Identity } from './Identity';
import { Transport } from './Transport';
import { concatBytes, toHex, shortHex, constantTimeEqual } from './utils/bytes';

const TAG = 'Link';

// ── Link Constants ──────────────────────────────────────────────

export const CURVE = 'Curve25519';
export const KEYSIZE = X25519_KEY_LENGTH; // 32 bytes

/** Link keepalive (matching Python RNS) */
export const KEEPALIVE_DEFAULT_MS = 360 * 1000; // 6 minutes
export const KEEPALIVE_MIN_MS = 5 * 1000;
export const KEEPALIVE_MAX_MS = 360 * 1000;

/** Stale timeout */
export const STALE_TIME_MS = 720 * 1000; // 12 minutes
export const STALE_GRACE_MS = 2 * KEEPALIVE_DEFAULT_MS;

/** Establishment timeout per hop */
export const ESTABLISHMENT_TIMEOUT_PER_HOP_MS = 6000; // 6 seconds
export const ESTABLISHMENT_TIMEOUT_GRACE_MS = 10000;

/** Link status */
export enum LinkStatus {
  PENDING = 0x00,
  HANDSHAKE = 0x01,
  ACTIVE = 0x02,
  STALE = 0x03,
  CLOSED = 0x04,
}

/** Teardown reasons */
export enum TeardownReason {
  NONE = 0x00,
  TIMEOUT = 0x01,
  INITIATOR_CLOSED = 0x02,
  DESTINATION_CLOSED = 0x03,
  LINK_ERROR = 0x04,
  NOT_ACCEPTED = 0x05,
}

/** Link mode */
export enum LinkMode {
  DEFAULT = 0x00,
  NO_IMPLICIT_PROOF = 0x01,
}

// ── Callbacks ───────────────────────────────────────────────────

export type LinkEstablishedCallback = (link: Link) => void;
export type LinkClosedCallback = (link: Link) => void;
export type LinkPacketCallback = (data: Uint8Array, packet: Packet) => void;

export class Link {
  // Identity and addressing
  private _destination: Destination;
  private _identity: Identity | null = null;

  // Keys
  private _ephemeralKey: X25519PrivateKey;
  private _peerPubKey: X25519PublicKey | null = null;
  private _sharedSecret: Uint8Array | null = null;
  private _derivedKey: Uint8Array | null = null;
  private _token: Token | null = null;

  // Link state
  private _status: LinkStatus = LinkStatus.PENDING;
  private _initiator: boolean = false;
  private _linkId: Uint8Array;
  private _teardownReason: TeardownReason = TeardownReason.NONE;
  private _mode: LinkMode = LinkMode.DEFAULT;

  // Timing
  private _createdAt: number = Date.now();
  private _establishedAt: number = 0;
  private _lastActivity: number = Date.now();
  private _lastKeepAlive: number = 0;
  private _rtt: number = 0; // Round-trip time in ms

  // Keepalive
  private _keepaliveMs: number = KEEPALIVE_DEFAULT_MS;
  private _keepaliveTimer: ReturnType<typeof setInterval> | null = null;
  private _watchdogTimer: ReturnType<typeof setTimeout> | null = null;

  // Signal metrics
  private _rssi: number | null = null;
  private _snr: number | null = null;
  private _q: number | null = null;

  // Callbacks
  private _establishedCallback: LinkEstablishedCallback | null = null;
  private _closedCallback: LinkClosedCallback | null = null;
  private _packetCallback: LinkPacketCallback | null = null;

  // Channel
  private _channel: any = null; // Set by Channel module

  // Request handlers
  private _requestHandlers: Map<string, Function> = new Map();

  /**
   * Create a new outbound link to a destination.
   */
  constructor(destination: Destination) {
    this._destination = destination;
    this._initiator = true;

    // Generate ephemeral X25519 key pair for ECDH
    this._ephemeralKey = X25519PrivateKey.generate();

    // Link ID = truncated hash of ephemeral public key
    this._linkId = truncatedHash(this._ephemeralKey.publicKey().publicBytes);

    Logger.info(
      `Link created to ${shortHex(destination.hash)}, id=${shortHex(this._linkId)}`,
      TAG
    );
  }

  /** Create a link from an incoming link request (called by Transport) */
  static fromRequest(
    packet: Packet,
    destination: Destination,
    peerIdentity?: Identity
  ): Link {
    const link = new Link(destination);
    link._initiator = false;
    link._status = LinkStatus.HANDSHAKE;

    // Extract peer's ephemeral public key from request data
    if (packet.data.length >= X25519_KEY_LENGTH) {
      const peerPubBytes = packet.data.slice(0, X25519_KEY_LENGTH);
      link._peerPubKey = X25519PublicKey.fromPublicBytes(peerPubBytes);

      // Link ID is derived from the initiator's ephemeral key
      link._linkId = truncatedHash(peerPubBytes);

      Logger.info(
        `Link request received, id=${shortHex(link._linkId)}`,
        TAG
      );
    }

    return link;
  }

  // ── Handshake ─────────────────────────────────────────────────

  /**
   * Initiate the link handshake.
   * Sends a LINKREQUEST packet containing our ephemeral public key.
   */
  establish(): void {
    if (this._status !== LinkStatus.PENDING) {
      Logger.warn(`Cannot establish: link is ${LinkStatus[this._status]}`, TAG);
      return;
    }

    const pubBytes = this._ephemeralKey.publicKey().publicBytes;

    const pkt = new Packet();
    pkt.packetType = PACKET_LINKREQUEST;
    pkt.destinationType = DESTINATION_SINGLE;
    pkt.destinationHash = this._destination.hash;
    pkt.propagationType = PROPAGATION_BROADCAST;
    pkt.context = CONTEXT_NONE;
    pkt.data = pubBytes;

    this._status = LinkStatus.HANDSHAKE;

    const transport = Transport.getInstance();
    transport.outbound(pkt);

    // Set establishment timeout
    const hops = transport.hopsTo(this._destination.hash);
    const timeout = (Math.max(1, hops) * ESTABLISHMENT_TIMEOUT_PER_HOP_MS) + ESTABLISHMENT_TIMEOUT_GRACE_MS;

    this._watchdogTimer = setTimeout(() => {
      if (this._status === LinkStatus.HANDSHAKE) {
        this.teardown(TeardownReason.TIMEOUT);
      }
    }, timeout);

    Logger.info(
      `Link establishing to ${shortHex(this._destination.hash)} (timeout=${timeout}ms)`,
      TAG
    );
  }

  /**
   * Accept an incoming link request and complete the handshake.
   * Called by the destination when it decides to accept the link.
   */
  accept(): void {
    if (this._initiator || this._status !== LinkStatus.HANDSHAKE) return;
    if (!this._peerPubKey) return;

    // Perform ECDH key exchange
    this._sharedSecret = this._ephemeralKey.exchange(this._peerPubKey);

    // Derive symmetric encryption key (64 bytes for AES-256 Token)
    this._derivedKey = deriveKey(64, this._sharedSecret);
    this._token = new Token(this._derivedKey);

    // Send proof back to initiator
    const myPubBytes = this._ephemeralKey.publicKey().publicBytes;

    // Sign the proof with destination's identity key
    let proofData = myPubBytes;
    if (this._destination.identity && this._destination.identity.hasPrivateKey) {
      const signedData = concatBytes(this._linkId, myPubBytes);
      const signature = this._destination.identity.sign(signedData);
      proofData = concatBytes(myPubBytes, signature);
    }

    const proofPkt = new Packet();
    proofPkt.packetType = PACKET_PROOF;
    proofPkt.destinationType = DESTINATION_LINK;
    proofPkt.destinationHash = this._linkId;
    proofPkt.context = CONTEXT_LINKPROOF;
    proofPkt.data = proofData;

    Transport.getInstance().outbound(proofPkt);

    this._status = LinkStatus.ACTIVE;
    this._establishedAt = Date.now();
    this.startKeepalive();

    Logger.info(
      `Link accepted, id=${shortHex(this._linkId)}`,
      TAG
    );
  }

  /**
   * Handle a link proof (called on initiator when proof arrives).
   */
  handleProof(packet: Packet): void {
    if (!this._initiator || this._status !== LinkStatus.HANDSHAKE) return;

    // Extract peer's ephemeral public key from proof
    const peerPubBytes = packet.data.slice(0, X25519_KEY_LENGTH);
    this._peerPubKey = X25519PublicKey.fromPublicBytes(peerPubBytes);

    // Perform ECDH key exchange
    this._sharedSecret = this._ephemeralKey.exchange(this._peerPubKey);
    this._derivedKey = deriveKey(64, this._sharedSecret);
    this._token = new Token(this._derivedKey);

    // Verify signature if present
    if (packet.data.length > X25519_KEY_LENGTH) {
      const signature = packet.data.slice(X25519_KEY_LENGTH, X25519_KEY_LENGTH + ED25519_SIG_LENGTH);
      // Signature verification would go here with the destination's known identity
    }

    // Clear establishment timeout
    if (this._watchdogTimer) {
      clearTimeout(this._watchdogTimer);
      this._watchdogTimer = null;
    }

    this._status = LinkStatus.ACTIVE;
    this._establishedAt = Date.now();
    this._rtt = this._establishedAt - this._createdAt;
    this.startKeepalive();

    Logger.info(
      `Link established, id=${shortHex(this._linkId)} rtt=${this._rtt}ms`,
      TAG
    );

    if (this._establishedCallback) {
      this._establishedCallback(this);
    }
  }

  // ── Data Transmission ─────────────────────────────────────────

  /**
   * Send encrypted data over the link.
   */
  send(data: Uint8Array, context: number = CONTEXT_NONE): PacketReceipt | null {
    if (this._status !== LinkStatus.ACTIVE) {
      Logger.warn(`Cannot send: link is ${LinkStatus[this._status]}`, TAG);
      return null;
    }
    if (!this._token) {
      Logger.error('Cannot send: no encryption key', TAG);
      return null;
    }

    // Encrypt the data
    const encrypted = this._token.encrypt(data);

    const pkt = new Packet();
    pkt.packetType = PACKET_DATA;
    pkt.destinationType = DESTINATION_LINK;
    pkt.destinationHash = this._linkId;
    pkt.context = context;
    pkt.data = encrypted;

    Transport.getInstance().outbound(pkt);
    this._lastActivity = Date.now();

    Logger.log(
      `Link send: ${data.length}B → ${encrypted.length}B on ${shortHex(this._linkId)}`,
      LogLevel.VERBOSE,
      TAG
    );
    return pkt.receipt;
  }

  /**
   * Receive and decrypt a data packet on this link.
   */
  receive(packet: Packet): void {
    if (!this._token) return;

    this._lastActivity = Date.now();

    // Update signal metrics
    if (packet.rssi !== null) this._rssi = packet.rssi;
    if (packet.snr !== null) this._snr = packet.snr;
    if (packet.q !== null) this._q = packet.q;

    // Handle special contexts
    switch (packet.context) {
      case CONTEXT_KEEPALIVE:
        this.handleKeepalive(packet);
        return;
      case CONTEXT_LINKCLOSE:
        this.handleClose(packet);
        return;
      case CONTEXT_LRRTT:
        this.handleRttPacket(packet);
        return;
      case CONTEXT_LINKIDENTIFY:
        this.handleIdentify(packet);
        return;
    }

    // Decrypt the data
    try {
      const plaintext = this._token.decrypt(packet.data);

      if (this._packetCallback) {
        this._packetCallback(plaintext, packet);
      }

      // Also forward to channel if one is attached
      if (this._channel && packet.context === CONTEXT_CHANNEL) {
        this._channel.receive(plaintext, packet);
      }
    } catch (e) {
      Logger.error(`Link decrypt failed on ${shortHex(this._linkId)}: ${e}`, TAG);
    }
  }

  // ── Keepalive ─────────────────────────────────────────────────

  private startKeepalive(): void {
    this._keepaliveTimer = setInterval(() => {
      if (this._status === LinkStatus.ACTIVE) {
        this.sendKeepalive();
      }
    }, this._keepaliveMs);

    // Watchdog for stale detection
    this._watchdogTimer = setInterval(() => {
      const timeSinceActivity = Date.now() - this._lastActivity;
      if (timeSinceActivity > STALE_TIME_MS) {
        if (this._status === LinkStatus.ACTIVE) {
          this._status = LinkStatus.STALE;
          Logger.warn(`Link stale: ${shortHex(this._linkId)}`, TAG);
        }
        if (timeSinceActivity > STALE_TIME_MS + STALE_GRACE_MS) {
          this.teardown(TeardownReason.TIMEOUT);
        }
      } else if (this._status === LinkStatus.STALE) {
        this._status = LinkStatus.ACTIVE;
        Logger.info(`Link recovered: ${shortHex(this._linkId)}`, TAG);
      }
    }, this._keepaliveMs / 2);
  }

  private sendKeepalive(): void {
    const now = Date.now();
    this.send(new Uint8Array(0), CONTEXT_KEEPALIVE);
    this._lastKeepAlive = now;
    Logger.log(`Keepalive sent on ${shortHex(this._linkId)}`, LogLevel.EXTREME, TAG);
  }

  private handleKeepalive(packet: Packet): void {
    Logger.log(`Keepalive received on ${shortHex(this._linkId)}`, LogLevel.EXTREME, TAG);
  }

  // ── RTT Measurement ───────────────────────────────────────────

  private handleRttPacket(packet: Packet): void {
    // RTT measurement logic
    this._rtt = Date.now() - this._lastKeepAlive;
    Logger.debug(`Link RTT: ${this._rtt}ms on ${shortHex(this._linkId)}`, TAG);
  }

  // ── Identity ──────────────────────────────────────────────────

  /**
   * Identify yourself to the remote end of the link.
   * Sends your identity's public key + signature over the encrypted link.
   */
  identify(identity: Identity): void {
    if (!identity.hasPrivateKey) {
      throw new Error('Cannot identify without private key');
    }

    const publicKey = identity.getPublicKey();
    const signature = identity.sign(this._linkId);
    const identifyData = concatBytes(publicKey, signature);

    this.send(identifyData, CONTEXT_LINKIDENTIFY);
    Logger.info(`Identified as ${identity.hexHash.slice(0, 12)}... on ${shortHex(this._linkId)}`, TAG);
  }

  private handleIdentify(packet: Packet): void {
    // Peer is identifying themselves
    try {
      const plaintext = this._token!.decrypt(packet.data);
      if (plaintext.length >= 64 + 64) { // pubkey + signature
        const publicKey = plaintext.slice(0, 64);
        const signature = plaintext.slice(64, 128);
        const identity = Identity.fromPublicKey(publicKey);
        if (identity.validate(signature, this._linkId)) {
          this._identity = identity;
          Logger.info(
            `Peer identified as ${identity.hexHash.slice(0, 12)}... on ${shortHex(this._linkId)}`,
            TAG
          );
        }
      }
    } catch (e) {
      Logger.warn(`Identity verification failed on ${shortHex(this._linkId)}: ${e}`, TAG);
    }
  }

  // ── Teardown ──────────────────────────────────────────────────

  /** Close the link cleanly */
  teardown(reason: TeardownReason = TeardownReason.INITIATOR_CLOSED): void {
    if (this._status === LinkStatus.CLOSED) return;

    this._teardownReason = reason;

    // Send close packet if link was active
    if (this._status === LinkStatus.ACTIVE && this._token) {
      try {
        this.send(new Uint8Array([reason]), CONTEXT_LINKCLOSE);
      } catch {
        // Best effort
      }
    }

    this.cleanup();

    Logger.info(
      `Link torn down: ${shortHex(this._linkId)} reason=${TeardownReason[reason]}`,
      TAG
    );

    if (this._closedCallback) {
      this._closedCallback(this);
    }
  }

  private handleClose(packet: Packet): void {
    try {
      const plaintext = this._token!.decrypt(packet.data);
      const reason = plaintext.length > 0 ? plaintext[0] : TeardownReason.DESTINATION_CLOSED;
      this._teardownReason = reason;
    } catch {
      this._teardownReason = TeardownReason.DESTINATION_CLOSED;
    }
    this.cleanup();
    Logger.info(
      `Link closed by peer: ${shortHex(this._linkId)} reason=${TeardownReason[this._teardownReason]}`,
      TAG
    );
    if (this._closedCallback) {
      this._closedCallback(this);
    }
  }

  private cleanup(): void {
    this._status = LinkStatus.CLOSED;
    if (this._keepaliveTimer) {
      clearInterval(this._keepaliveTimer);
      this._keepaliveTimer = null;
    }
    if (this._watchdogTimer) {
      clearTimeout(this._watchdogTimer);
      this._watchdogTimer = null;
    }
    this._sharedSecret = null;
    this._derivedKey = null;
  }

  // ── Callbacks ─────────────────────────────────────────────────

  /** Set callback for when link is established */
  onEstablished(callback: LinkEstablishedCallback): void {
    this._establishedCallback = callback;
    if (this._status === LinkStatus.ACTIVE) callback(this);
  }

  /** Set callback for when link is closed */
  onClosed(callback: LinkClosedCallback): void {
    this._closedCallback = callback;
  }

  /** Set callback for received data packets */
  onPacket(callback: LinkPacketCallback): void {
    this._packetCallback = callback;
  }

  // ── Channel Access ────────────────────────────────────────────

  /** Get or create a Channel on this link */
  getChannel(): any {
    return this._channel;
  }

  /** Set the channel (called by Channel constructor) */
  setChannel(channel: any): void {
    this._channel = channel;
  }

  // ── Request/Response ──────────────────────────────────────────

  /** Register a request handler */
  registerRequestHandler(
    path: string,
    handler: (path: string, data: any, requestId: Uint8Array, link: Link) => any
  ): void {
    this._requestHandlers.set(path, handler);
  }

  // ── Accessors ─────────────────────────────────────────────────

  get linkId(): Uint8Array {
    return this._linkId;
  }

  get status(): LinkStatus {
    return this._status;
  }

  get isActive(): boolean {
    return this._status === LinkStatus.ACTIVE;
  }

  get isInitiator(): boolean {
    return this._initiator;
  }

  get destination(): Destination {
    return this._destination;
  }

  get peerIdentity(): Identity | null {
    return this._identity;
  }

  get rtt(): number {
    return this._rtt;
  }

  get age(): number {
    return Date.now() - this._createdAt;
  }

  get rssi(): number | null { return this._rssi; }
  get snr(): number | null { return this._snr; }
  get q(): number | null { return this._q; }

  get keepaliveMs(): number { return this._keepaliveMs; }
  set keepaliveMs(value: number) {
    this._keepaliveMs = Math.max(KEEPALIVE_MIN_MS, Math.min(KEEPALIVE_MAX_MS, value));
  }

  /** Maximum data unit for this link */
  get mdu(): number {
    return MTU - TOKEN_OVERHEAD - KEYSIZE;
  }

  toString(): string {
    return `<Link ${shortHex(this._linkId)} ${LinkStatus[this._status]} to ${shortHex(this._destination.hash)}>`;
  }
}
