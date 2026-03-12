/**
 * Interface - Base class for all Reticulum network interfaces.
 *
 * An Interface represents a physical or virtual transport that can
 * send and receive raw Reticulum packets. This base class provides
 * common functionality: IFAC (Interface Access Codes), announce queuing,
 * bandwidth tracking, and the EventEmitter-based data flow pattern.
 *
 * Concrete implementations: TCPInterface, WebSocketInterface, LocalInterface.
 *
 * Matches Python RNS Interface.py
 */

import { Logger, LogLevel } from '../log/Logger';
import { Transport } from '../Transport';
import { hmacSha256 } from '../crypto/HMAC';
import { truncatedHash } from '../crypto/Hashes';
import { fromUtf8, toHex, shortHex, concatBytes } from '../utils/bytes';

const TAG = 'Interface';

// ── Interface Mode Constants (matching Python RNS) ──────────────

export const MODE_FULL = 0x01;
export const MODE_POINT_TO_POINT = 0x02;
export const MODE_ACCESS_POINT = 0x03;
export const MODE_ROAMING = 0x04;
export const MODE_BOUNDARY = 0x05;
export const MODE_GATEWAY = 0x06;

// Direction flags
export const DIR_IN = 0x01;
export const DIR_OUT = 0x02;
export const DIR_FWD = 0x04;
export const DIR_RPT = 0x08;

// ── HDLC Framing (for TCP/Serial byte-stream interfaces) ───────

export const HDLC_FLAG = 0x7e;
export const HDLC_ESC = 0x7d;
export const HDLC_ESC_MASK = 0x20;

// ── IFAC Constants ──────────────────────────────────────────────

export const IFAC_MIN_SIZE = 1;

/** Configuration for creating an interface */
export interface InterfaceConfig {
  name: string;
  enabled?: boolean;
  mode?: number;
  ifacSize?: number;
  ifacNetName?: string;
  ifacNetKey?: string;
  announceCapPercent?: number;
  bitrate?: number;
}

/** Data received event */
export type InterfaceDataCallback = (data: Uint8Array, iface: InterfaceBase) => void;

/**
 * Base class for all Reticulum interfaces.
 */
export abstract class InterfaceBase {
  // Identity
  readonly name: string;
  protected _enabled: boolean = true;
  protected _online: boolean = false;
  protected _mode: number = MODE_FULL;
  protected _direction: number = DIR_IN | DIR_OUT;

  // IFAC (Interface Access Code)
  protected _ifacSize: number = 0;
  protected _ifacKey: Uint8Array | null = null;
  protected _ifacIdentity: Uint8Array | null = null;

  // Bandwidth tracking
  protected _bitrate: number = 0;
  protected _txBytes: number = 0;
  protected _rxBytes: number = 0;
  protected _txPackets: number = 0;
  protected _rxPackets: number = 0;

  // Announce management
  protected _announceCapPercent: number = 2; // 2% of bandwidth
  protected _announceQueue: Uint8Array[] = [];
  protected _maxHeldAnnounces: number = 256;

  // Callbacks
  private _dataCallbacks: InterfaceDataCallback[] = [];

  // HDLC frame assembly buffer (for stream-based interfaces)
  protected _frameBuffer: Uint8Array | null = null;
  protected _inFrame: boolean = false;
  protected _escape: boolean = false;

  constructor(config: InterfaceConfig) {
    this.name = config.name;
    this._enabled = config.enabled ?? true;
    this._mode = config.mode ?? MODE_FULL;
    this._ifacSize = config.ifacSize ?? 0;
    this._announceCapPercent = config.announceCapPercent ?? 2;
    this._bitrate = config.bitrate ?? 0;

    // Compute IFAC key if configured
    if (config.ifacNetName || config.ifacNetKey) {
      this.computeIfac(config.ifacNetName, config.ifacNetKey);
    }

    Logger.info(`Interface created: ${this.name} mode=${this._mode}`, TAG);
  }

  // ── Abstract Methods ──────────────────────────────────────────

  /** Start the interface (connect, bind, etc.) */
  abstract start(): Promise<void>;

  /** Stop the interface */
  abstract stop(): void;

  /** Send raw bytes over this interface */
  abstract sendRaw(data: Uint8Array): void;

  // ── Public API ────────────────────────────────────────────────

  /**
   * Send a Reticulum packet over this interface.
   * Applies IFAC if configured, then delegates to sendRaw().
   */
  send(data: Uint8Array): void {
    if (!this._enabled || !this._online) {
      Logger.warn(`Cannot send on ${this.name}: ${this._enabled ? 'offline' : 'disabled'}`, TAG);
      return;
    }

    let frame = data;

    // Apply IFAC if configured
    if (this._ifacSize > 0 && this._ifacKey) {
      frame = this.applyIfac(data);
    }

    this.sendRaw(frame);
    this._txBytes += frame.length;
    this._txPackets++;

    Logger.log(
      `TX ${this.name}: ${data.length}B`,
      LogLevel.EXTREME,
      TAG
    );
  }

  /** Subscribe to received data events */
  onData(callback: InterfaceDataCallback): void {
    this._dataCallbacks.push(callback);
  }

  // ── Protected: For Subclass Use ───────────────────────────────

  /**
   * Called by subclasses when raw data is received.
   * Processes IFAC, then delivers to Transport.
   */
  protected processIncoming(data: Uint8Array): void {
    if (!this._enabled) return;

    this._rxBytes += data.length;
    this._rxPackets++;

    let packet = data;

    // Strip and verify IFAC if configured
    if (this._ifacSize > 0 && this._ifacKey) {
      const result = this.verifyIfac(data);
      if (!result) {
        Logger.log(`IFAC verification failed on ${this.name}`, LogLevel.DEBUG, TAG);
        return;
      }
      packet = result;
    }

    // Deliver to registered callbacks
    for (const cb of this._dataCallbacks) {
      try {
        cb(packet, this);
      } catch (e) {
        Logger.error(`Interface data callback error: ${e}`, TAG);
      }
    }

    // Deliver to Transport engine
    try {
      Transport.getInstance().inbound(packet, this);
    } catch (e) {
      Logger.error(`Transport inbound error: ${e}`, TAG);
    }

    Logger.log(
      `RX ${this.name}: ${data.length}B → ${packet.length}B payload`,
      LogLevel.EXTREME,
      TAG
    );
  }

  // ── IFAC (Interface Access Codes) ─────────────────────────────

  private computeIfac(netName?: string, netKey?: string): void {
    const nameBytes = fromUtf8(netName ?? '');
    const keyBytes = fromUtf8(netKey ?? '');
    const combined = concatBytes(nameBytes, keyBytes);
    this._ifacKey = truncatedHash(combined);
    this._ifacIdentity = hmacSha256(this._ifacKey, fromUtf8(this.name));
    Logger.debug(`IFAC computed for ${this.name}`, TAG);
  }

  private applyIfac(data: Uint8Array): Uint8Array {
    if (!this._ifacKey) return data;
    const ifacTag = hmacSha256(this._ifacKey, data).slice(0, this._ifacSize);
    return concatBytes(ifacTag, data);
  }

  private verifyIfac(data: Uint8Array): Uint8Array | null {
    if (!this._ifacKey || data.length < this._ifacSize) return null;
    const receivedTag = data.slice(0, this._ifacSize);
    const payload = data.slice(this._ifacSize);
    const expectedTag = hmacSha256(this._ifacKey, payload).slice(0, this._ifacSize);

    // Constant-time comparison
    let diff = 0;
    for (let i = 0; i < receivedTag.length; i++) {
      diff |= receivedTag[i] ^ expectedTag[i];
    }
    return diff === 0 ? payload : null;
  }

  // ── HDLC Framing ─────────────────────────────────────────────

  /** Encode a packet with HDLC framing for stream interfaces */
  protected hdlcEncode(data: Uint8Array): Uint8Array {
    const parts: number[] = [HDLC_FLAG];
    for (let i = 0; i < data.length; i++) {
      if (data[i] === HDLC_FLAG || data[i] === HDLC_ESC) {
        parts.push(HDLC_ESC, data[i] ^ HDLC_ESC_MASK);
      } else {
        parts.push(data[i]);
      }
    }
    parts.push(HDLC_FLAG);
    return new Uint8Array(parts);
  }

  /** Process incoming bytes for HDLC framing. Calls processIncoming for each complete frame. */
  protected hdlcDecode(data: Uint8Array): void {
    for (let i = 0; i < data.length; i++) {
      const byte = data[i];

      if (byte === HDLC_FLAG) {
        if (this._inFrame && this._frameBuffer && this._frameBuffer.length > 0) {
          // End of frame
          this.processIncoming(this._frameBuffer);
        }
        // Start new frame
        this._frameBuffer = new Uint8Array(0);
        this._inFrame = true;
        this._escape = false;
      } else if (this._inFrame) {
        if (this._escape) {
          this._escape = false;
          const unescaped = byte ^ HDLC_ESC_MASK;
          this._frameBuffer = concatBytes(
            this._frameBuffer ?? new Uint8Array(0),
            new Uint8Array([unescaped])
          );
        } else if (byte === HDLC_ESC) {
          this._escape = true;
        } else {
          this._frameBuffer = concatBytes(
            this._frameBuffer ?? new Uint8Array(0),
            new Uint8Array([byte])
          );
        }
      }
    }
  }

  // ── Accessors ─────────────────────────────────────────────────

  get enabled(): boolean { return this._enabled; }
  get online(): boolean { return this._online; }
  get mode(): number { return this._mode; }
  get bitrate(): number { return this._bitrate; }
  get txBytes(): number { return this._txBytes; }
  get rxBytes(): number { return this._rxBytes; }
  get txPackets(): number { return this._txPackets; }
  get rxPackets(): number { return this._rxPackets; }

  get stats() {
    return {
      name: this.name,
      enabled: this._enabled,
      online: this._online,
      mode: this._mode,
      txBytes: this._txBytes,
      rxBytes: this._rxBytes,
      txPackets: this._txPackets,
      rxPackets: this._rxPackets,
      bitrate: this._bitrate,
    };
  }

  toString(): string {
    return `<Interface ${this.name} ${this._online ? 'ONLINE' : 'OFFLINE'}>`;
  }
}
