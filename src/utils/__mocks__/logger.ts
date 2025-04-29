/**
 * Mock logger for testing
 */
export class Logger {
  debug(message: string): void {
    // Do nothing in tests
  }

  info(message: string): void {
    // Do nothing in tests
  }

  warning(message: string): void {
    // Do nothing in tests
  }

  error(message: string, error?: Error): void {
    // Do nothing in tests
  }

  setDebugMode(enabled: boolean): void {
    // Do nothing in tests
  }
}

// Create a default logger instance
export const logger = new Logger();