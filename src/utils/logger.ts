import * as core from '@actions/core';

/**
 * Log levels
 */
export enum LogLevel {
  DEBUG = 'debug',
  INFO = 'info',
  WARNING = 'warning',
  ERROR = 'error',
}

/**
 * Enhanced logger for RSOLV action
 */
export class Logger {
  private debugMode: boolean;

  constructor(debugMode = false) {
    this.debugMode = debugMode;
  }

  /**
   * Log a debug message (only in debug mode)
   */
  debug(message: string): void {
    if (this.debugMode) {
      core.debug(message);
    }
  }

  /**
   * Log an informational message
   */
  info(message: string): void {
    core.info(message);
  }

  /**
   * Log a warning message
   */
  warning(message: string): void {
    core.warning(message);
  }

  /**
   * Log an error message
   */
  error(message: string, error?: Error): void {
    if (error) {
      core.error(`${message}: ${error.message}`);
      this.debug(`Stack trace: ${error.stack}`);
    } else {
      core.error(message);
    }
  }

  /**
   * Set debug mode
   */
  setDebugMode(enabled: boolean): void {
    this.debugMode = enabled;
  }
}

// Create a default logger instance
export const logger = new Logger();