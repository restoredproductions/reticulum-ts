/**
 * TCPInterface - TCP client/server interface for Reticulum.
 *
 * Connects to a Reticulum TCP transport node or listens for connections.
 * Uses HDLC framing over TCP byte stream.
 *
 * In React Native, requires `react-native-tcp-socket` package.
 * In Node.js, uses built-in `net` module.
 *
 * Wire-compatible with Python RNS TCPInterface.
 */

import { InterfaceBase, InterfaceConfig, HDLC_FLAG, MODE_FULL } from './Interface';
import { Logger, LogLevel } from '../log/Logger';

const TAG = 'TCPInterface';

export interface TCPInterfaceConfig extends InterfaceConfig {
  host: string;
  port: number;
  /** 'client' (connect to remote) or 'server' (listen for connections) */
  role?: 'client' | 'server';
  /** Auto-reconnect on disconnect (client mode only) */
  reconnect?: boolean;
  /** Reconnect delay in ms */
  reconnectDelay?: number;
  /** Max reconnect attempts (0 = infinite) */
  maxReconnectAttempts?: number;
}

export class TCPInterface extends InterfaceBase {
  private _host: string;
  private _port: number;
  private _role: 'client' | 'server';
  private _reconnect: boolean;
  private _reconnectDelay: number;
  private _maxReconnectAttempts: number;
  private _reconnectAttempts: number = 0;
  private _reconnectTimer: ReturnType<typeof setTimeout> | null = null;

  // Socket references (type 'any' for cross-platform compatibility)
  private _socket: any = null;
  private _server: any = null;
  private _clients: any[] = [];

  constructor(config: TCPInterfaceConfig) {
    super({
      ...config,
      mode: config.mode ?? MODE_FULL,
      bitrate: config.bitrate ?? 10_000_000, // 10 Mbps default for TCP
    });

    this._host = config.host;
    this._port = config.port;
    this._role = config.role ?? 'client';
    this._reconnect = config.reconnect ?? true;
    this._reconnectDelay = config.reconnectDelay ?? 5000;
    this._maxReconnectAttempts = config.maxReconnectAttempts ?? 0;

    Logger.info(
      `TCPInterface configured: ${this._role} ${this._host}:${this._port}`,
      TAG
    );
  }

  async start(): Promise<void> {
    if (this._role === 'client') {
      await this.connectClient();
    } else {
      await this.startServer();
    }
  }

  stop(): void {
    this._enabled = false;
    this._online = false;

    if (this._reconnectTimer) {
      clearTimeout(this._reconnectTimer);
      this._reconnectTimer = null;
    }

    if (this._socket) {
      try { this._socket.destroy(); } catch {}
      this._socket = null;
    }

    if (this._server) {
      try { this._server.close(); } catch {}
      this._server = null;
    }

    for (const client of this._clients) {
      try { client.destroy(); } catch {}
    }
    this._clients = [];

    Logger.info(`TCPInterface stopped: ${this.name}`, TAG);
  }

  sendRaw(data: Uint8Array): void {
    const frame = this.hdlcEncode(data);

    if (this._role === 'client' && this._socket) {
      try {
        this._socket.write(frame);
      } catch (e) {
        Logger.error(`TCP send error: ${e}`, TAG);
        this.handleDisconnect();
      }
    } else if (this._role === 'server') {
      // Send to all connected clients
      for (const client of this._clients) {
        try {
          client.write(frame);
        } catch (e) {
          Logger.warn(`TCP send error to client: ${e}`, TAG);
        }
      }
    }
  }

  // ── Client Mode ───────────────────────────────────────────────

  private async connectClient(): Promise<void> {
    Logger.info(
      `Connecting to ${this._host}:${this._port}...`,
      TAG
    );

    try {
      // Try React Native tcp-socket first, then Node.js net
      let net: any;
      try {
        net = require('react-native-tcp-socket');
      } catch {
        net = require('net');
      }

      return new Promise<void>((resolve, reject) => {
        const socket = net.createConnection(
          { host: this._host, port: this._port },
          () => {
            this._socket = socket;
            this._online = true;
            this._reconnectAttempts = 0;

            Logger.info(
              `Connected to ${this._host}:${this._port}`,
              TAG
            );
            resolve();
          }
        );

        socket.on('data', (data: Uint8Array | Buffer) => {
          const bytes = data instanceof Uint8Array ? data : new Uint8Array(data);
          this.hdlcDecode(bytes);
        });

        socket.on('close', () => {
          Logger.warn(`TCP connection closed: ${this._host}:${this._port}`, TAG);
          this.handleDisconnect();
        });

        socket.on('error', (err: Error) => {
          Logger.error(`TCP error: ${err.message}`, TAG);
          if (!this._online) reject(err);
          this.handleDisconnect();
        });
      });
    } catch (e) {
      Logger.error(`Failed to create TCP connection: ${e}`, TAG);
      this.scheduleReconnect();
    }
  }

  private handleDisconnect(): void {
    this._online = false;
    this._socket = null;

    if (this._reconnect && this._enabled) {
      this.scheduleReconnect();
    }
  }

  private scheduleReconnect(): void {
    if (this._reconnectTimer) return;
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
    const delay = this._reconnectDelay * Math.min(this._reconnectAttempts, 10);

    Logger.info(
      `Reconnecting in ${delay}ms (attempt ${this._reconnectAttempts})...`,
      TAG
    );

    this._reconnectTimer = setTimeout(async () => {
      this._reconnectTimer = null;
      try {
        await this.connectClient();
      } catch {
        this.scheduleReconnect();
      }
    }, delay);
  }

  // ── Server Mode ───────────────────────────────────────────────

  private async startServer(): Promise<void> {
    Logger.info(
      `Starting TCP server on ${this._host}:${this._port}...`,
      TAG
    );

    let net: any;
    try {
      net = require('react-native-tcp-socket');
    } catch {
      net = require('net');
    }

    return new Promise<void>((resolve, reject) => {
      this._server = net.createServer((socket: any) => {
        this._clients.push(socket);
        Logger.info(
          `TCP client connected (${this._clients.length} total)`,
          TAG
        );

        socket.on('data', (data: Uint8Array | Buffer) => {
          const bytes = data instanceof Uint8Array ? data : new Uint8Array(data);
          this.hdlcDecode(bytes);
        });

        socket.on('close', () => {
          const idx = this._clients.indexOf(socket);
          if (idx >= 0) this._clients.splice(idx, 1);
          Logger.info(
            `TCP client disconnected (${this._clients.length} remaining)`,
            TAG
          );
        });

        socket.on('error', (err: Error) => {
          Logger.warn(`TCP client error: ${err.message}`, TAG);
        });
      });

      this._server.listen(this._port, this._host, () => {
        this._online = true;
        Logger.info(`TCP server listening on ${this._host}:${this._port}`, TAG);
        resolve();
      });

      this._server.on('error', (err: Error) => {
        Logger.error(`TCP server error: ${err.message}`, TAG);
        reject(err);
      });
    });
  }

  // ── Accessors ─────────────────────────────────────────────────

  get host(): string { return this._host; }
  get port(): number { return this._port; }
  get role(): string { return this._role; }
  get connectedClients(): number { return this._clients.length; }
}
