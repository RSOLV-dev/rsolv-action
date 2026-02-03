/**
 * Retry Utility with Exponential Backoff
 *
 * RFC-101 Iteration 15: Mitigation M4
 *
 * Provides retry functionality for transient failures like API overload (529),
 * rate limiting (429), and service unavailability (503/502).
 *
 * @example
 * ```typescript
 * const result = await withRetry(
 *   () => callApi(),
 *   { maxRetries: 3, baseDelayMs: 1000 }
 * );
 * ```
 */

import { logger } from './logger.js';

/**
 * HTTP status codes that indicate transient failures worth retrying.
 *
 * - 429: Rate limited
 * - 502: Bad gateway (upstream server issue)
 * - 503: Service unavailable
 * - 529: Overloaded (Anthropic-specific)
 */
const RETRYABLE_STATUS_CODES = new Set([429, 502, 503, 529]);

/**
 * Check if an HTTP status code indicates a retryable error.
 */
export function isRetryableStatusCode(statusCode: number): boolean {
  return RETRYABLE_STATUS_CODES.has(statusCode);
}

/**
 * Custom error class for retryable errors that includes the HTTP status code.
 */
export class RetryableError extends Error {
  public readonly statusCode: number;

  constructor(message: string, statusCode: number) {
    super(message);
    this.name = 'RetryableError';
    this.statusCode = statusCode;
  }

  /**
   * Check if this error should be retried based on its status code.
   */
  isRetryable(): boolean {
    return isRetryableStatusCode(this.statusCode);
  }
}

/**
 * Information passed to the onRetry callback.
 */
export interface RetryInfo {
  attempt: number;
  error: Error;
  delayMs: number;
}

/**
 * Configuration for retry behavior.
 */
export interface RetryConfig {
  /** Maximum number of retry attempts (default: 3) */
  maxRetries?: number;

  /** Base delay in milliseconds for exponential backoff (default: 1000) */
  baseDelayMs?: number;

  /** Maximum delay in milliseconds (default: 30000) */
  maxDelayMs?: number;

  /** Callback invoked before each retry attempt */
  onRetry?: (info: RetryInfo) => void;

  /**
   * Custom function to determine if an error should be retried.
   * Default: checks for RetryableError with retryable status code.
   */
  shouldRetry?: (error: unknown) => boolean;
}

const DEFAULT_CONFIG: Required<Omit<RetryConfig, 'onRetry' | 'shouldRetry'>> = {
  maxRetries: 3,
  baseDelayMs: 1000,
  maxDelayMs: 30000
};

/**
 * Sleep for a specified duration.
 */
function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Calculate delay for a given retry attempt using exponential backoff.
 *
 * @param attempt - The retry attempt number (1-based)
 * @param baseDelayMs - Base delay in milliseconds
 * @param maxDelayMs - Maximum delay cap
 * @returns Delay in milliseconds
 */
function calculateDelay(attempt: number, baseDelayMs: number, maxDelayMs: number): number {
  // Exponential backoff: base * 2^(attempt-1)
  const exponentialDelay = baseDelayMs * Math.pow(2, attempt - 1);
  return Math.min(exponentialDelay, maxDelayMs);
}

/**
 * Default function to determine if an error should be retried.
 */
function defaultShouldRetry(error: unknown): boolean {
  if (error instanceof RetryableError) {
    return error.isRetryable();
  }
  return false;
}

/**
 * Execute a function with automatic retry on transient failures.
 *
 * Uses exponential backoff between retries. Only retries errors that
 * are determined to be transient (e.g., 429, 529, 503, 502).
 *
 * @param fn - The async function to execute
 * @param config - Retry configuration
 * @returns The result of the function
 * @throws The last error if all retries are exhausted
 *
 * @example
 * ```typescript
 * // Basic usage
 * const result = await withRetry(() => fetchData());
 *
 * // With custom config
 * const result = await withRetry(
 *   () => callApi(),
 *   {
 *     maxRetries: 5,
 *     baseDelayMs: 500,
 *     onRetry: ({ attempt, delayMs }) => {
 *       console.log(`Retry ${attempt} after ${delayMs}ms`);
 *     }
 *   }
 * );
 * ```
 */
export async function withRetry<T>(
  fn: () => Promise<T>,
  config: RetryConfig = {}
): Promise<T> {
  const {
    maxRetries = DEFAULT_CONFIG.maxRetries,
    baseDelayMs = DEFAULT_CONFIG.baseDelayMs,
    maxDelayMs = DEFAULT_CONFIG.maxDelayMs,
    onRetry,
    shouldRetry = defaultShouldRetry
  } = config;

  let lastError: unknown;
  let attempt = 0;

  while (attempt <= maxRetries) {
    try {
      return await fn();
    } catch (error) {
      lastError = error;

      // Check if we should retry
      if (!shouldRetry(error)) {
        throw error;
      }

      // Check if we have retries left
      if (attempt >= maxRetries) {
        logger.warn(`All ${maxRetries} retry attempts exhausted`, {
          error: error instanceof Error ? error.message : String(error)
        });
        throw error;
      }

      // Calculate delay and wait
      attempt++;
      const delayMs = calculateDelay(attempt, baseDelayMs, maxDelayMs);

      logger.info(`Retryable error encountered, attempt ${attempt}/${maxRetries}`, {
        error: error instanceof Error ? error.message : String(error),
        statusCode: error instanceof RetryableError ? error.statusCode : undefined,
        delayMs
      });

      // Invoke callback if provided
      if (onRetry && error instanceof Error) {
        onRetry({ attempt, error, delayMs });
      }

      await sleep(delayMs);
    }
  }

  // This should never be reached, but TypeScript needs it
  throw lastError;
}

/**
 * Create a RetryableError from an HTTP response.
 * Useful when handling fetch responses.
 *
 * @param response - The HTTP response
 * @param message - Optional custom error message
 * @returns A RetryableError with the response status
 *
 * @example
 * ```typescript
 * const response = await fetch(url);
 * if (!response.ok) {
 *   throw createRetryableError(response, 'API call failed');
 * }
 * ```
 */
export function createRetryableError(
  response: { status: number; statusText: string },
  message?: string
): RetryableError {
  const errorMessage = message || `HTTP ${response.status}: ${response.statusText}`;
  return new RetryableError(errorMessage, response.status);
}
