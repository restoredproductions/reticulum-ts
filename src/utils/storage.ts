/**
 * Storage - Persistent storage abstraction for Reticulum-TS.
 *
 * Stores identity keys, path tables, known destinations, ratchet keys,
 * and cached packets. Uses expo-file-system on React Native or the
 * Node.js fs module on server.
 *
 * Storage structure:
 *   <basePath>/
 *     identity       - Local identity private key (64 bytes)
 *     config.json    - Configuration
 *     storage/
 *       destinations - Known destination identities
 *       paths        - Cached path table
 *       ratchets     - Ratchet keys
 *       cache/       - Packet cache
 */

import { Logger, LogLevel } from '../log/Logger';
import { getPlatform, Platform } from './platform';
import { toHex, fromHex } from './bytes';

const TAG = 'Storage';

export interface StorageProvider {
  read(path: string): Promise<Uint8Array | null>;
  write(path: string, data: Uint8Array): Promise<void>;
  readJson(path: string): Promise<any | null>;
  writeJson(path: string, data: any): Promise<void>;
  exists(path: string): Promise<boolean>;
  delete(path: string): Promise<void>;
  mkdir(path: string): Promise<void>;
}

/** Expo File System storage provider */
class ExpoFileSystemProvider implements StorageProvider {
  private _fs: any;
  private _basePath: string;

  constructor(basePath: string) {
    this._fs = require('expo-file-system');
    this._basePath = basePath;
  }

  private fullPath(path: string): string {
    return `${this._basePath}/${path}`;
  }

  async read(path: string): Promise<Uint8Array | null> {
    try {
      const content = await this._fs.readAsStringAsync(this.fullPath(path), {
        encoding: this._fs.EncodingType.Base64,
      });
      // Decode base64 to Uint8Array
      const binary = atob(content);
      const bytes = new Uint8Array(binary.length);
      for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
      return bytes;
    } catch {
      return null;
    }
  }

  async write(path: string, data: Uint8Array): Promise<void> {
    // Encode Uint8Array to base64
    let binary = '';
    for (let i = 0; i < data.length; i++) binary += String.fromCharCode(data[i]);
    const base64 = btoa(binary);
    await this._fs.writeAsStringAsync(this.fullPath(path), base64, {
      encoding: this._fs.EncodingType.Base64,
    });
  }

  async readJson(path: string): Promise<any | null> {
    try {
      const content = await this._fs.readAsStringAsync(this.fullPath(path));
      return JSON.parse(content);
    } catch {
      return null;
    }
  }

  async writeJson(path: string, data: any): Promise<void> {
    await this._fs.writeAsStringAsync(
      this.fullPath(path),
      JSON.stringify(data, null, 2)
    );
  }

  async exists(path: string): Promise<boolean> {
    const info = await this._fs.getInfoAsync(this.fullPath(path));
    return info.exists;
  }

  async delete(path: string): Promise<void> {
    try {
      await this._fs.deleteAsync(this.fullPath(path), { idempotent: true });
    } catch {}
  }

  async mkdir(path: string): Promise<void> {
    await this._fs.makeDirectoryAsync(this.fullPath(path), {
      intermediates: true,
    });
  }
}

/** Node.js filesystem provider */
class NodeFSProvider implements StorageProvider {
  private _basePath: string;

  constructor(basePath: string) {
    this._basePath = basePath;
  }

  private fullPath(path: string): string {
    return `${this._basePath}/${path}`;
  }

  async read(path: string): Promise<Uint8Array | null> {
    try {
      const fs = require('fs').promises;
      const data = await fs.readFile(this.fullPath(path));
      return new Uint8Array(data);
    } catch {
      return null;
    }
  }

  async write(path: string, data: Uint8Array): Promise<void> {
    const fs = require('fs').promises;
    const fspath = require('path');
    await fs.mkdir(fspath.dirname(this.fullPath(path)), { recursive: true });
    await fs.writeFile(this.fullPath(path), data);
  }

  async readJson(path: string): Promise<any | null> {
    try {
      const fs = require('fs').promises;
      const content = await fs.readFile(this.fullPath(path), 'utf-8');
      return JSON.parse(content);
    } catch {
      return null;
    }
  }

  async writeJson(path: string, data: any): Promise<void> {
    const fs = require('fs').promises;
    const fspath = require('path');
    await fs.mkdir(fspath.dirname(this.fullPath(path)), { recursive: true });
    await fs.writeFile(this.fullPath(path), JSON.stringify(data, null, 2));
  }

  async exists(path: string): Promise<boolean> {
    try {
      const fs = require('fs').promises;
      await fs.access(this.fullPath(path));
      return true;
    } catch {
      return false;
    }
  }

  async delete(path: string): Promise<void> {
    try {
      const fs = require('fs').promises;
      await fs.unlink(this.fullPath(path));
    } catch {}
  }

  async mkdir(path: string): Promise<void> {
    const fs = require('fs').promises;
    await fs.mkdir(this.fullPath(path), { recursive: true });
  }
}

/** In-memory fallback provider */
class MemoryProvider implements StorageProvider {
  private _store: Map<string, Uint8Array | string> = new Map();

  async read(path: string): Promise<Uint8Array | null> {
    const data = this._store.get(path);
    return data instanceof Uint8Array ? data : null;
  }

  async write(path: string, data: Uint8Array): Promise<void> {
    this._store.set(path, new Uint8Array(data));
  }

  async readJson(path: string): Promise<any | null> {
    const data = this._store.get(path);
    if (typeof data === 'string') return JSON.parse(data);
    return null;
  }

  async writeJson(path: string, data: any): Promise<void> {
    this._store.set(path, JSON.stringify(data));
  }

  async exists(path: string): Promise<boolean> {
    return this._store.has(path);
  }

  async delete(path: string): Promise<void> {
    this._store.delete(path);
  }

  async mkdir(_path: string): Promise<void> {
    // No-op for memory provider
  }
}

/**
 * Create the appropriate storage provider for the current platform.
 */
export function createStorageProvider(basePath: string): StorageProvider {
  const platform = getPlatform();

  // Try Expo File System first (React Native)
  try {
    if (platform === Platform.IOS || platform === Platform.ANDROID) {
      const provider = new ExpoFileSystemProvider(basePath);
      Logger.debug('Using Expo File System storage', TAG);
      return provider;
    }
  } catch {}

  // Try Node.js fs
  try {
    if (platform === Platform.NODE) {
      const provider = new NodeFSProvider(basePath);
      Logger.debug('Using Node.js filesystem storage', TAG);
      return provider;
    }
  } catch {}

  // Fallback to memory
  Logger.warn('Using in-memory storage (data will not persist)', TAG);
  return new MemoryProvider();
}

/**
 * High-level storage manager for Reticulum data.
 */
export class ReticulumStorage {
  private _provider: StorageProvider;

  constructor(provider: StorageProvider) {
    this._provider = provider;
  }

  async init(): Promise<void> {
    await this._provider.mkdir('storage');
    await this._provider.mkdir('storage/cache');
    Logger.debug('Storage initialized', TAG);
  }

  // Identity
  async saveIdentity(privateKey: Uint8Array): Promise<void> {
    await this._provider.write('identity', privateKey);
    Logger.debug('Identity saved', TAG);
  }

  async loadIdentity(): Promise<Uint8Array | null> {
    return this._provider.read('identity');
  }

  // Known destinations
  async saveKnownDestinations(
    destinations: Map<string, Uint8Array>
  ): Promise<void> {
    const obj: Record<string, string> = {};
    for (const [hash, pubkey] of destinations) {
      obj[hash] = toHex(pubkey);
    }
    await this._provider.writeJson('storage/destinations', obj);
  }

  async loadKnownDestinations(): Promise<Map<string, Uint8Array>> {
    const obj = await this._provider.readJson('storage/destinations');
    const map = new Map<string, Uint8Array>();
    if (obj) {
      for (const [hash, pubkeyHex] of Object.entries(obj)) {
        map.set(hash, fromHex(pubkeyHex as string));
      }
    }
    return map;
  }

  // Path table
  async savePathTable(paths: any): Promise<void> {
    await this._provider.writeJson('storage/paths', paths);
  }

  async loadPathTable(): Promise<any | null> {
    return this._provider.readJson('storage/paths');
  }

  // Config
  async saveConfig(config: any): Promise<void> {
    await this._provider.writeJson('config.json', config);
  }

  async loadConfig(): Promise<any | null> {
    return this._provider.readJson('config.json');
  }

  /** Get the raw storage provider for custom operations */
  get provider(): StorageProvider {
    return this._provider;
  }
}
