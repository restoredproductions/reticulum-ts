/**
 * Reticulum-TS Logging System
 *
 * Mirrors Python RNS log levels (0-7) with callback-based output
 * so RORK can subscribe and expose logs in a debug UI.
 */

export enum LogLevel {
  NONE = -1,
  CRITICAL = 0,
  ERROR = 1,
  WARNING = 2,
  NOTICE = 3,
  INFO = 4,
  VERBOSE = 5,
  DEBUG = 6,
  EXTREME = 7,
}

const LEVEL_NAMES: Record<number, string> = {
  [LogLevel.CRITICAL]: 'CRIT',
  [LogLevel.ERROR]: 'ERRO',
  [LogLevel.WARNING]: 'WARN',
  [LogLevel.NOTICE]: 'NOTE',
  [LogLevel.INFO]: 'INFO',
  [LogLevel.VERBOSE]: 'VERB',
  [LogLevel.DEBUG]: 'DBUG',
  [LogLevel.EXTREME]: 'EXTR',
};

export type LogCallback = (
  message: string,
  level: LogLevel,
  tag: string,
  timestamp: number
) => void;

export class Logger {
  private static _level: LogLevel = LogLevel.NOTICE;
  private static _callbacks: LogCallback[] = [];
  private static _useConsole: boolean = true;

  static get level(): LogLevel {
    return Logger._level;
  }

  static set level(value: LogLevel) {
    Logger._level = value;
  }

  /** Subscribe to log events. Returns unsubscribe function. */
  static onLog(callback: LogCallback): () => void {
    Logger._callbacks.push(callback);
    return () => {
      const idx = Logger._callbacks.indexOf(callback);
      if (idx >= 0) Logger._callbacks.splice(idx, 1);
    };
  }

  /** Disable console.log output (useful when only using callbacks) */
  static set useConsole(value: boolean) {
    Logger._useConsole = value;
  }

  static log(
    message: string,
    level: LogLevel = LogLevel.NOTICE,
    tag: string = 'RNS'
  ): void {
    if (level > Logger._level) return;

    const now = Date.now();
    const levelName = LEVEL_NAMES[level] ?? 'UNKN';

    // Emit to callbacks first (RORK debug UI, etc.)
    for (const cb of Logger._callbacks) {
      try {
        cb(message, level, tag, now);
      } catch {
        // Never let a callback crash the logger
      }
    }

    // Console output
    if (Logger._useConsole) {
      const ts = new Date(now).toISOString().slice(11, 23);
      const formatted = `[${ts}] [${levelName}] [${tag}] ${message}`;

      if (level <= LogLevel.ERROR) {
        console.error(formatted);
      } else if (level <= LogLevel.WARNING) {
        console.warn(formatted);
      } else {
        console.log(formatted);
      }
    }
  }

  // Convenience methods
  static critical(message: string, tag?: string): void {
    Logger.log(message, LogLevel.CRITICAL, tag);
  }
  static error(message: string, tag?: string): void {
    Logger.log(message, LogLevel.ERROR, tag);
  }
  static warn(message: string, tag?: string): void {
    Logger.log(message, LogLevel.WARNING, tag);
  }
  static notice(message: string, tag?: string): void {
    Logger.log(message, LogLevel.NOTICE, tag);
  }
  static info(message: string, tag?: string): void {
    Logger.log(message, LogLevel.INFO, tag);
  }
  static verbose(message: string, tag?: string): void {
    Logger.log(message, LogLevel.VERBOSE, tag);
  }
  static debug(message: string, tag?: string): void {
    Logger.log(message, LogLevel.DEBUG, tag);
  }
  static extreme(message: string, tag?: string): void {
    Logger.log(message, LogLevel.EXTREME, tag);
  }
}
