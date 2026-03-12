/**
 * WebSocketInterface - Primary mobile transport for Reticulum-TS.
 *
 * Connects to a WebSocket endpoint that bridges to a Reticulum TCP
 * transport node. WebSocket is ideal for mobile because:
 *   - Works natively in React Native (no extra packages)
 *   - Works in Expo Go without ejecting
 *   - Provides reliable framing (no HDLC needed)
 *   - Supports automatic reconnection
 *
 * The WebSocket bridge should relay raw Reticulum packets as binary frames.
 * A simple bridge server can be built with Python:
 *   websockets + RNS LocalInterface
 *
 * This is the recommended interface for RORK/Expo apps.
 */

import { InterfaceBase, InterfaceConfig, MODE_FULL } from './Interface';
import { Logger } from '../log/Logger';

const TAG = 'WebSocketInterface';

export interface WebSocketInterfaceConfig extends InterfaceConfig {
  /** WebSocket URL (e.g., "ws://192.168.1.100:4242") */
  url: string;
  /** Auto-reconnect on disconnect */
  reconnect?: boolean;
  /** Reconnect delay in ms */
  reconnectDelay?: number;
  /** Max reconnect attempts (0 = infinite) */
  maxReconnectAttempts?: number;
  /** Ping interval in ms (0 = disabled) */
  pingInterval?: number;
}

export class WebSocketInterface extends InterfaceBase {
  private _url: string;
  private _reconnect: boolean;
  private _reconnectDelay: number;
  private _maxReconnectAttempts: number;
  private _reconnectAttempts: number = 0;
  private _reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  private _pingInterval: number;
  private _pingTimer: ReturnType<typeof setInterval> | null = null;

  private _ws: WebSocket | null = null;
  private _intentionallyClosed: boolean = false;

  constructor(config: WebSocketInterfaceConfig) {
    super({
      ...config,
      mode: config.mode ?? MODE_FULL,
      bitrate: config.bitrate ?? 1_000_000, // 1 Mbps default for WebSocket
    });

    this._url = config.url;
    this._reconnect = config.reconnect ?? true;
    this._reconnectDelay = config.reconnectDelay ?? 3000;
    this._maxReconnectAttempts = config.maxReconnectAttempts ?? 0;
    this._pingInterval = config.pingInterval ?? 30000;

    Logger.info(
      `WebSocketInterface configured: ${this._url}`,
      TAG
    );
  }

  async start(): Promise<void> {
    this._intentionallyClosed = false;
    return this.connect();
  }

  stop(): void {
    this._intentionallyClosed = true;
    this._enabled = false;

    if (this._reconnectTimer) {
      clearTimeout(this._reconnectTimer);
      this._reconnectTimer = null;
    }
    if (this._pingTimer) {
      clearInterval(this._pingTimer);
      this._pingTimer = null;
    }
    if (this._ws) {
      try {
        this._ws.close(1000, 'Interface stopped');
      } catch {}
      this._ws = null;
    }

    this._online = false;
    Logger.info(`WebSocketInterface stopped: ${this.name}`, TAG);
  }

  sendRaw(data: Uint8Array): void {
    if (!this._ws || this._ws.readyState !== WebSocket.OPEN) {
      Logger.warn('WebSocket not connected, cannot send', TAG);
      return;
    }

    try {
      // Cast to any for React Native WebSocket compat (RN accepts
      // Uint8Array directly; browser DOM typing is more restrictive)
      const ws = this._ws as any;
      ws.send(data);
    } catch (e) {
      Logger.error('WebSocket send error: ' + String(e), TAG);
    }
  }

  // ── Connection ────────────────────────────────────────────────

  private connect(): Promise<void> {
    return new Promise<void>((resolve, reject) => {
      Logger.info(`Connecting to ${this._url}...`, TAG);

      try {
        this._ws = new WebSocket(this._url);
        this._ws.binaryType = 'arraybuffer';

        this._ws.onopen = () => {
          this._online = true;
          this._reconnectAttempts = 0;

          Logger.info(`Connected to ${this._url}`, TAG);

          // Start ping interval
          if (this._pingInterval > 0) {
            this._pingTimer = setInterval(() => {
              this.sendPing();
            }, this._pingInterval);
          }

          resolve();
        };

        this._ws.onmessage = (event: MessageEvent) => {
          let data: Uint8Array;

          if (event.data instanceof ArrayBuffer) {
            data = new Uint8Array(event.data);
          } else if (typeof event.data === 'string') {
            // Text frame - try to interpret as base64 or ignore
            Logger.warn('Received text WebSocket frame, expected binary', TAG);
            return;
          } else {
            Logger.warn('Unexpected WebSocket message type', TAG);
            return;
          }

          // Process as raw Reticulum packet (no HDLC needed for WebSocket)
          this.processIncoming(data);
        };

        this._ws.onclose = (event: CloseEvent) => {
          this._online = false;
          if (this._pingTimer) {
            clearInterval(this._pingTimer);
            this._pingTimer = null;
          }

          Logger.info(
            `WebSocket closed: code=${event.code} reason=${event.reason || 'none'}`,
            TAG
          );

          if (!this._intentionallyClosed && this._reconnect && this._enabled) {
            this.scheduleReconnect();
          }
        };

        this._ws.onerror = (event: Event) => {
          Logger.error(`WebSocket error on ${this.name}`, TAG);
          if (!this._online) {
            reject(new Error('WebSocket connection failed'));
          }
        };
      } catch (e) {
        Logger.error(`Failed to create WebSocket: ${e}`, TAG);
        reject(e);
        if (this._reconnect && this._enabled) {
          this.scheduleReconnect();
        }
      }
    });
  }

  private scheduleReconnect(): void {
    if (this._reconnectTimer || this._intentionallyClosed) return;
    if (
      this._maxReconnectAttempts > 0 &&
      this._reconnectAttempts >= this._maxReconnectAttempts
    ) {
      Logger.error(
        `Max reconnect attempts (${this._maxReconnectAttempts}) reached for ${this.name}`,
        TAG
      );
      return;
    }

    this._reconnectAttempts++;
    // Exponential backoff with jitter
    const backoff = Math.min(
      this._reconnectDelay * Math.pow(1.5, Math.min(this._reconnectAttempts - 1, 8)),
      60000
    );
    const jitter = Math.random() * backoff * 0.3;
    const delay = Math.round(backoff + jitter);

    Logger.info(
      `Reconnecting in ${delay}ms (attempt ${this._reconnectAttempts})...`,
      TAG
    );

    this._reconnectTimer = setTimeout(async () => {
      this._reconnectTimer = null;
      try {
        await this.connect();
      } catch {
        this.scheduleReconnect();
      }
    }, delay);
  }

  private sendPing(): void {
    // WebSocket ping is handled at protocol level, but we can send
    // a zero-length binary frame as an application-level keepalive
    if (this._ws && this._ws.readyState === WebSocket.OPEN) {
      try {
        const ws = this._ws as any;
        ws.send(new Uint8Array(0));
      } catch {
        // Ignore ping errors
      }
    }
  }

  // ── Accessors ─────────────────────────────────────────────────

  get url(): string { return this._url; }
  get isConnected(): boolean { return this._ws?.readyState === WebSocket.OPEN; }
  get reconnectAttempts(): number { return this._reconnectAttempts; }
}
