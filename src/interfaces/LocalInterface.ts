/**
 * LocalInterface - IPC via TCP loopback for same-device communication.
 *
 * Connects to a local Reticulum instance via TCP on localhost.
 * This is used when a Python RNS transport node runs on the same device
 * and the TS app needs to communicate with it locally.
 *
 * Uses HDLC framing over TCP (same as Python RNS LocalInterface).
 *
 * Default port: 37428 (matching Python RNS)
 */

import { TCPInterface } from './TCPInterface';
import { Logger } from '../log/Logger';
import { MODE_FULL } from './Interface';

const TAG = 'LocalInterface';
const DEFAULT_LOCAL_PORT = 37428;

export interface LocalInterfaceConfig {
  name?: string;
  port?: number;
  enabled?: boolean;
}

export class LocalInterface extends TCPInterface {
  constructor(config: LocalInterfaceConfig = {}) {
    super({
      name: config.name ?? 'LocalInterface',
      host: '127.0.0.1',
      port: config.port ?? DEFAULT_LOCAL_PORT,
      role: 'client',
      reconnect: true,
      reconnectDelay: 2000,
      maxReconnectAttempts: 0, // infinite
      mode: MODE_FULL,
      bitrate: 1_000_000_000, // 1 Gbps (loopback)
      enabled: config.enabled ?? true,
    });

    Logger.info(
      `LocalInterface configured on port ${config.port ?? DEFAULT_LOCAL_PORT}`,
      TAG
    );
  }
}
