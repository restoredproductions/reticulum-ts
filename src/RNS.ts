/**
 * RNS - Main Reticulum singleton.
 *
 * Entry point for the Reticulum network stack.
 * Manages initialization, configuration, and the Transport engine.
 *
 * Usage:
 *   const rns = new Reticulum({ configPath: '/path/to/config' });
 *   await rns.start();
 *   // ... create destinations, links, etc.
 *   rns.stop();
 *
 * Mirrors Python RNS.Reticulum class.
 */

import { Logger, LogLevel } from './log/Logger';
import { Transport } from './Transport';
import { Identity } from './Identity';
import { initRandom } from './crypto/Random';
import { toHex } from './utils/bytes';
import { InterfaceBase } from './interfaces/Interface';

const TAG = 'Reticulum';

// Version info
export const VERSION = '0.1.0';
export const PROTOCOL_VERSION = 1;

// Target constants matching Python RNS
export const TARGET_MTU = 500;
export const MAX_QUEUED_ANNOUNCES = 16384;
export const ANNOUNCE_CAP = 0.02;

// Log level re-exports for convenience
export { LogLevel };

export interface ReticulumConfig {
  /** Enable transport mode (relay packets for others) */
  enableTransport?: boolean;

  /** Log level (default: NOTICE) */
  logLevel?: LogLevel;

  /** Custom storage path for identities, paths, etc. */
  storagePath?: string;

  /** Identity to use (auto-generated if not provided) */
  identity?: Identity;

  /** Interfaces to register and start on startup */
  interfaces?: InterfaceBase[];

  /** Panic on init failure */
  panicOnInitFail?: boolean;
}

export class Reticulum {
  private static _instance: Reticulum | null = null;

  private _config: ReticulumConfig;
  private _transport: Transport;
  private _identity: Identity | null = null;
  private _started: boolean = false;
  private _startedAt: number = 0;

  constructor(config: ReticulumConfig = {}) {
    this._config = {
      enableTransport: false,
      logLevel: LogLevel.NOTICE,
      storagePath: '.reticulum',
      panicOnInitFail: false,
      ...config,
    };

    // Initialize crypto CSPRNG
    initRandom();

    // Set log level
    Logger.level = this._config.logLevel!;

    this._transport = Transport.getInstance();

    Logger.info(`Reticulum v${VERSION} initializing`, TAG);
  }

  /** Get or create the singleton instance */
  static getInstance(config?: ReticulumConfig): Reticulum {
    if (!Reticulum._instance) {
      Reticulum._instance = new Reticulum(config);
    }
    return Reticulum._instance;
  }

  /** Start the Reticulum network stack */
  async start(): Promise<void> {
    if (this._started) {
      Logger.warn('Reticulum already started', TAG);
      return;
    }

    Logger.info('Starting Reticulum network stack...', TAG);

    // Create or use provided identity
    this._identity = this._config.identity ?? new Identity();

    Logger.info(
      `Local identity: ${this._identity.hexHash}`,
      TAG
    );

    // Start transport engine
    this._transport.start(this._identity);

    // Register and start provided interfaces
    if (this._config.interfaces) {
      for (const iface of this._config.interfaces) {
        this._transport.registerInterface(iface);
        try {
          await iface.start();
          Logger.info(`Interface started: ${iface.name}`, TAG);
        } catch (e) {
          Logger.error(`Interface failed to start: ${iface.name}: ${e}`, TAG);
          if (this._config.panicOnInitFail) {
            throw new Error(`Failed to start interface ${iface.name}: ${e}`);
          }
        }
      }
    }

    this._started = true;
    this._startedAt = Date.now();
    Logger.info(`Reticulum v${VERSION} started successfully`, TAG);
  }

  /** Stop the Reticulum network stack */
  stop(): void {
    if (!this._started) return;

    Logger.info('Stopping Reticulum...', TAG);

    // Stop all interfaces
    for (const iface of this._transport.getInterfaces()) {
      try {
        iface.stop();
      } catch (e) {
        Logger.warn(`Error stopping interface ${iface.name}: ${e}`, TAG);
      }
    }

    this._transport.stop();
    this._started = false;
    Logger.info('Reticulum stopped', TAG);
  }

  // ── Accessors ─────────────────────────────────────────────────

  get transport(): Transport {
    return this._transport;
  }

  get identity(): Identity | null {
    return this._identity;
  }

  get isStarted(): boolean {
    return this._started;
  }

  get uptime(): number {
    return this._started ? Date.now() - this._startedAt : 0;
  }

  // ── Convenience Methods ───────────────────────────────────────

  /** Register a destination with the transport engine */
  registerDestination(destination: any): void {
    this._transport.registerDestination(destination);
  }

  /** Check if a path exists to a destination */
  hasPath(destinationHash: Uint8Array): boolean {
    return this._transport.hasPath(destinationHash);
  }

  /** Request a path to a destination */
  requestPath(destinationHash: Uint8Array): Promise<boolean> {
    return this._transport.requestPath(destinationHash);
  }

  /** Get transport statistics */
  getStats(): object {
    return this._transport.stats;
  }

  // ── Logging Convenience ───────────────────────────────────────

  /** Set the global log level */
  static setLogLevel(level: LogLevel): void {
    Logger.level = level;
  }

  /** Subscribe to log events (for RORK debug UI) */
  static onLog(
    callback: (message: string, level: LogLevel, tag: string, timestamp: number) => void
  ): () => void {
    return Logger.onLog(callback);
  }

  /** Log a message through the Reticulum logging system */
  static log(message: string, level: LogLevel = LogLevel.NOTICE, tag?: string): void {
    Logger.log(message, level, tag);
  }
}
