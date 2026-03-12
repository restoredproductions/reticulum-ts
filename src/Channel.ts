/**
 * Channel - Message-based bidirectional communication over a Link.
 *
 * Provides typed message passing over an encrypted Reticulum Link.
 * Messages are serialized with MessagePack for efficiency.
 *
 * Wire-compatible with Python RNS Channel.
 */

import { Logger, LogLevel } from './log/Logger';
import { Link } from './Link';
import { Packet, CONTEXT_CHANNEL } from './Packet';
import { encode as msgpackEncode, decode as msgpackDecode } from '@msgpack/msgpack';
import { concatBytes, toHex, shortHex, readUint16BE, writeUint16BE } from './utils/bytes';

const TAG = 'Channel';

// System message types (matching Python RNS)
export const SMT_STREAM_DATA = 0xff00;

/**
 * Base class for channel messages.
 * Extend this to define custom message types.
 */
export abstract class MessageBase {
  abstract readonly msgType: number;

  /** Serialize the message payload */
  abstract pack(): Uint8Array;

  /** Deserialize a message payload */
  abstract unpack(data: Uint8Array): void;
}

/**
 * Generic data message for simple byte payloads.
 */
export class DataMessage extends MessageBase {
  readonly msgType: number;
  data: Uint8Array;

  constructor(msgType: number = 0x0000, data: Uint8Array = new Uint8Array(0)) {
    super();
    this.msgType = msgType;
    this.data = data;
  }

  pack(): Uint8Array {
    return this.data;
  }

  unpack(data: Uint8Array): void {
    this.data = data;
  }
}

/**
 * Stream data message (for Buffer module).
 */
export class StreamDataMessage extends MessageBase {
  readonly msgType = SMT_STREAM_DATA;
  data: Uint8Array;
  streamId: number;
  isEof: boolean;

  constructor(streamId: number = 0, data: Uint8Array = new Uint8Array(0), isEof: boolean = false) {
    super();
    this.streamId = streamId;
    this.data = data;
    this.isEof = isEof;
  }

  pack(): Uint8Array {
    const header = new Uint8Array(3);
    writeUint16BE(header, this.streamId, 0);
    header[2] = this.isEof ? 1 : 0;
    return concatBytes(header, this.data);
  }

  unpack(rawData: Uint8Array): void {
    this.streamId = readUint16BE(rawData, 0);
    this.isEof = rawData[2] === 1;
    this.data = rawData.slice(3);
  }
}

export type MessageCallback = (message: MessageBase) => void;
export type MessageFactory = (msgType: number) => MessageBase | null;

/**
 * Channel provides message-based communication over a Link.
 */
export class Channel {
  private _link: Link;
  private _messageCallbacks: Map<number, MessageCallback> = new Map();
  private _messageFactories: Map<number, MessageFactory> = new Map();
  private _outboundQueue: MessageBase[] = [];
  private _inboundQueue: MessageBase[] = [];
  private _sequenceNumber: number = 0;
  private _peerSequenceNumber: number = 0;
  private _isReady: boolean = true;

  constructor(link: Link) {
    this._link = link;
    link.setChannel(this);
    Logger.debug(
      `Channel created on link ${shortHex(link.linkId)}`,
      TAG
    );
  }

  // ── Message Registration ──────────────────────────────────────

  /**
   * Register a callback for a specific message type.
   */
  onMessage(msgType: number, callback: MessageCallback): void {
    this._messageCallbacks.set(msgType, callback);
  }

  /**
   * Register a factory for creating message instances by type.
   */
  registerMessageType(msgType: number, factory: MessageFactory): void {
    this._messageFactories.set(msgType, factory);
  }

  // ── Sending ───────────────────────────────────────────────────

  /**
   * Send a message over the channel.
   */
  send(message: MessageBase): boolean {
    if (!this._link.isActive) {
      Logger.warn('Cannot send: link not active', TAG);
      return false;
    }

    // Pack message: type (2 bytes) + sequence (2 bytes) + payload
    const payload = message.pack();
    const header = new Uint8Array(4);
    writeUint16BE(header, message.msgType, 0);
    writeUint16BE(header, this._sequenceNumber & 0xffff, 2);
    this._sequenceNumber++;

    const channelData = concatBytes(header, payload);
    this._link.send(channelData, CONTEXT_CHANNEL);

    Logger.log(
      `Channel send: type=0x${message.msgType.toString(16)} seq=${this._sequenceNumber - 1} ${payload.length}B`,
      LogLevel.VERBOSE,
      TAG
    );
    return true;
  }

  // ── Receiving ─────────────────────────────────────────────────

  /**
   * Process received channel data from the link.
   */
  receive(data: Uint8Array, packet: Packet): void {
    if (data.length < 4) {
      Logger.warn('Channel data too short', TAG);
      return;
    }

    // Parse header
    const msgType = readUint16BE(data, 0);
    const seqNum = readUint16BE(data, 2);
    const payload = data.slice(4);

    Logger.log(
      `Channel recv: type=0x${msgType.toString(16)} seq=${seqNum} ${payload.length}B`,
      LogLevel.VERBOSE,
      TAG
    );

    this._peerSequenceNumber = seqNum;

    // Create message instance
    let message: MessageBase | null = null;

    // Check registered factories first
    const factory = this._messageFactories.get(msgType);
    if (factory) {
      message = factory(msgType);
    }

    // Fallback: system message types
    if (!message) {
      if (msgType === SMT_STREAM_DATA) {
        message = new StreamDataMessage();
      } else {
        message = new DataMessage(msgType);
      }
    }

    if (message) {
      message.unpack(payload);

      // Deliver to callback
      const callback = this._messageCallbacks.get(msgType);
      if (callback) {
        try {
          callback(message);
        } catch (e) {
          Logger.error(`Channel message callback error: ${e}`, TAG);
        }
      }
    }
  }

  // ── Accessors ─────────────────────────────────────────────────

  get link(): Link {
    return this._link;
  }

  get isReady(): boolean {
    return this._isReady && this._link.isActive;
  }
}
