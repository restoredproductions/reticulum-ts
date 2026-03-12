/**
 * Configuration system for Reticulum-TS.
 *
 * Uses JSON instead of Python's INI (configobj) format.
 * Provides defaults that match Python RNS behavior.
 */

import { LogLevel } from '../log/Logger';

export interface InterfaceDefinition {
  type: 'tcp' | 'websocket' | 'local';
  name: string;
  enabled: boolean;

  // TCP-specific
  host?: string;
  port?: number;
  role?: 'client' | 'server';

  // WebSocket-specific
  url?: string;

  // Common
  reconnect?: boolean;
  reconnectDelay?: number;
  ifacNetName?: string;
  ifacNetKey?: string;
}

export interface ReticulumJsonConfig {
  /** Enable transport mode (relay for others) */
  enableTransport: boolean;

  /** Log level (0=CRITICAL ... 7=EXTREME) */
  logLevel: number;

  /** Storage path (relative to app data dir) */
  storagePath: string;

  /** Network interfaces to create */
  interfaces: InterfaceDefinition[];

  /** Share instance publicly (allow incoming connections) */
  shareInstance: boolean;

  /** Shared instance port (for local IPC) */
  sharedInstancePort: number;

  /** Panic on interface failure at startup */
  panicOnInterfaceError: boolean;
}

/** Default configuration matching Python RNS defaults */
export const DEFAULT_CONFIG: ReticulumJsonConfig = {
  enableTransport: false,
  logLevel: LogLevel.NOTICE,
  storagePath: '.reticulum',
  interfaces: [],
  shareInstance: false,
  sharedInstancePort: 37428,
  panicOnInterfaceError: false,
};

/** Merge user config with defaults */
export function mergeConfig(
  userConfig: Partial<ReticulumJsonConfig>
): ReticulumJsonConfig {
  return {
    ...DEFAULT_CONFIG,
    ...userConfig,
    interfaces: userConfig.interfaces ?? DEFAULT_CONFIG.interfaces,
  };
}

/**
 * Generate a sample configuration for first-time setup.
 */
export function generateSampleConfig(): ReticulumJsonConfig {
  return {
    ...DEFAULT_CONFIG,
    interfaces: [
      {
        type: 'websocket',
        name: 'WebSocket Gateway',
        enabled: true,
        url: 'ws://your-rns-gateway:4242',
        reconnect: true,
        reconnectDelay: 3000,
      },
    ],
  };
}
