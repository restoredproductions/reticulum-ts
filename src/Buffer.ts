/**
 * Buffer - Buffered stream I/O over a Channel.
 *
 * Provides a file-like read/write interface over a Reticulum Channel,
 * similar to Python RNS Buffer with RawChannelReader/RawChannelWriter.
 *
 * Wire-compatible with Python RNS Buffer.
 */

import { Logger, LogLevel } from './log/Logger';
import { Channel, StreamDataMessage, SMT_STREAM_DATA } from './Channel';
import { shortHex } from './utils/bytes';

const TAG = 'Buffer';

const DEFAULT_STREAM_ID = 0;

export type DataCallback = (data: Uint8Array) => void;

/**
 * Buffered writer - sends data as stream chunks over a Channel.
 */
export class BufferWriter {
  private _channel: Channel;
  private _streamId: number;
  private _closed: boolean = false;

  constructor(channel: Channel, streamId: number = DEFAULT_STREAM_ID) {
    this._channel = channel;
    this._streamId = streamId;
  }

  /** Write data to the stream */
  write(data: Uint8Array): boolean {
    if (this._closed) {
      Logger.warn('Cannot write: buffer closed', TAG);
      return false;
    }
    if (!this._channel.isReady) {
      Logger.warn('Cannot write: channel not ready', TAG);
      return false;
    }

    const msg = new StreamDataMessage(this._streamId, data, false);
    return this._channel.send(msg);
  }

  /** Close the stream (sends EOF) */
  close(): void {
    if (this._closed) return;

    const eof = new StreamDataMessage(this._streamId, new Uint8Array(0), true);
    this._channel.send(eof);
    this._closed = true;

    Logger.debug(`BufferWriter closed (stream ${this._streamId})`, TAG);
  }

  get isClosed(): boolean {
    return this._closed;
  }
}

/**
 * Buffered reader - receives stream data from a Channel.
 */
export class BufferReader {
  private _channel: Channel;
  private _streamId: number;
  private _buffer: Uint8Array[] = [];
  private _eof: boolean = false;
  private _dataCallback: DataCallback | null = null;
  private _eofCallback: (() => void) | null = null;

  constructor(channel: Channel, streamId: number = DEFAULT_STREAM_ID) {
    this._channel = channel;
    this._streamId = streamId;

    // Register for stream data messages
    channel.onMessage(SMT_STREAM_DATA, (msg) => {
      const streamMsg = msg as StreamDataMessage;
      if (streamMsg.streamId === this._streamId) {
        this.handleStreamData(streamMsg);
      }
    });
  }

  private handleStreamData(msg: StreamDataMessage): void {
    if (msg.isEof) {
      this._eof = true;
      Logger.debug(`BufferReader EOF (stream ${this._streamId})`, TAG);
      if (this._eofCallback) this._eofCallback();
      return;
    }

    if (msg.data.length > 0) {
      this._buffer.push(msg.data);
      if (this._dataCallback) {
        this._dataCallback(msg.data);
      }
    }
  }

  /** Read all buffered data */
  read(): Uint8Array | null {
    if (this._buffer.length === 0) return null;

    let totalLen = 0;
    for (const chunk of this._buffer) totalLen += chunk.length;
    const result = new Uint8Array(totalLen);
    let offset = 0;
    for (const chunk of this._buffer) {
      result.set(chunk, offset);
      offset += chunk.length;
    }
    this._buffer = [];
    return result;
  }

  /** Read up to `maxBytes` bytes */
  readUpTo(maxBytes: number): Uint8Array | null {
    if (this._buffer.length === 0) return null;

    // Flatten buffer
    const all = this.read();
    if (!all) return null;

    if (all.length <= maxBytes) return all;

    // Split: return requested amount, put rest back
    const result = all.slice(0, maxBytes);
    this._buffer.push(all.slice(maxBytes));
    return result;
  }

  /** Set callback for incoming data */
  onData(callback: DataCallback): void {
    this._dataCallback = callback;
  }

  /** Set callback for stream EOF */
  onEof(callback: () => void): void {
    this._eofCallback = callback;
    if (this._eof) callback();
  }

  get isEof(): boolean {
    return this._eof;
  }

  get available(): number {
    let total = 0;
    for (const chunk of this._buffer) total += chunk.length;
    return total;
  }
}

/**
 * Convenience: create a matched reader/writer pair on a channel.
 */
export function createBuffer(
  channel: Channel,
  streamId: number = DEFAULT_STREAM_ID
): { reader: BufferReader; writer: BufferWriter } {
  return {
    reader: new BufferReader(channel, streamId),
    writer: new BufferWriter(channel, streamId),
  };
}
