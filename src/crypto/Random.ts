/**
 * Cryptographically secure random bytes.
 *
 * Uses expo-crypto in React Native, or Node.js crypto, or Web Crypto API.
 * Provides a single consistent interface for all platforms.
 */

import { Logger } from '../log/Logger';

const TAG = 'Crypto.Random';

let _getRandomBytes: ((length: number) => Uint8Array) | null = null;

/** Initialize the random provider. Called once at startup. */
export function initRandom(): void {
  // Try expo-crypto first (React Native)
  try {
    const expoCrypto = require('expo-crypto');
    if (typeof expoCrypto.getRandomBytes === 'function') {
      _getRandomBytes = (len: number) => expoCrypto.getRandomBytes(len);
      Logger.debug('Using expo-crypto for CSPRNG', TAG);
      return;
    }
  } catch {
    // Not in Expo environment
  }

  // Try Node.js crypto
  try {
    const nodeCrypto = require('crypto');
    if (typeof nodeCrypto.randomBytes === 'function') {
      _getRandomBytes = (len: number) =>
        new Uint8Array(nodeCrypto.randomBytes(len));
      Logger.debug('Using Node.js crypto for CSPRNG', TAG);
      return;
    }
  } catch {
    // Not in Node.js
  }

  // Try Web Crypto API
  if (
    typeof globalThis !== 'undefined' &&
    globalThis.crypto &&
    typeof globalThis.crypto.getRandomValues === 'function'
  ) {
    _getRandomBytes = (len: number) => {
      const buf = new Uint8Array(len);
      globalThis.crypto.getRandomValues(buf);
      return buf;
    };
    Logger.debug('Using Web Crypto API for CSPRNG', TAG);
    return;
  }

  Logger.error('No CSPRNG provider available!', TAG);
}

/** Get cryptographically secure random bytes */
export function randomBytes(length: number): Uint8Array {
  if (_getRandomBytes === null) {
    initRandom();
  }
  if (_getRandomBytes === null) {
    throw new Error('No CSPRNG provider available. Cannot generate random bytes.');
  }
  return _getRandomBytes(length);
}
