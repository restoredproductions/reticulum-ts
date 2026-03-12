/**
 * Platform detection for Reticulum-TS.
 * Detects iOS, Android, web, and Node.js environments.
 */

export enum Platform {
  IOS = 'ios',
  ANDROID = 'android',
  WEB = 'web',
  NODE = 'node',
  UNKNOWN = 'unknown',
}

let _detected: Platform | null = null;

export function getPlatform(): Platform {
  if (_detected !== null) return _detected;

  // React Native detection
  if (
    typeof navigator !== 'undefined' &&
    typeof (navigator as any).product === 'string' &&
    (navigator as any).product === 'ReactNative'
  ) {
    // Check OS via React Native's Platform module if available
    try {
      // eslint-disable-next-line @typescript-eslint/no-var-requires
      const { Platform: RNPlatform } = require('react-native');
      if (RNPlatform.OS === 'ios') {
        _detected = Platform.IOS;
      } else if (RNPlatform.OS === 'android') {
        _detected = Platform.ANDROID;
      } else {
        _detected = Platform.UNKNOWN;
      }
    } catch {
      _detected = Platform.UNKNOWN;
    }
    return _detected;
  }

  // Node.js detection
  if (
    typeof process !== 'undefined' &&
    typeof process.versions !== 'undefined' &&
    typeof process.versions.node !== 'undefined'
  ) {
    _detected = Platform.NODE;
    return _detected;
  }

  // Browser/web detection
  if (typeof window !== 'undefined' && typeof document !== 'undefined') {
    _detected = Platform.WEB;
    return _detected;
  }

  _detected = Platform.UNKNOWN;
  return _detected;
}

export function isMobile(): boolean {
  const p = getPlatform();
  return p === Platform.IOS || p === Platform.ANDROID;
}

export function isNode(): boolean {
  return getPlatform() === Platform.NODE;
}
