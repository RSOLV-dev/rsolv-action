import { describe, test, expect, vi } from 'vitest';
import { withRetry, RetryConfig, RetryableError, isRetryableStatusCode } from '../retry.js';

describe('Retry Utility', () => {
  describe('isRetryableStatusCode', () => {
    test('should return true for 429 (rate limit)', () => {
      expect(isRetryableStatusCode(429)).toBe(true);
    });

    test('should return true for 529 (overloaded)', () => {
      expect(isRetryableStatusCode(529)).toBe(true);
    });

    test('should return true for 503 (service unavailable)', () => {
      expect(isRetryableStatusCode(503)).toBe(true);
    });

    test('should return true for 502 (bad gateway)', () => {
      expect(isRetryableStatusCode(502)).toBe(true);
    });

    test('should return false for 400 (bad request)', () => {
      expect(isRetryableStatusCode(400)).toBe(false);
    });

    test('should return false for 401 (unauthorized)', () => {
      expect(isRetryableStatusCode(401)).toBe(false);
    });

    test('should return false for 404 (not found)', () => {
      expect(isRetryableStatusCode(404)).toBe(false);
    });

    test('should return false for 500 (internal server error)', () => {
      // 500 is typically not retried as it indicates a bug
      expect(isRetryableStatusCode(500)).toBe(false);
    });
  });

  describe('RetryableError', () => {
    test('should create error with status code', () => {
      const error = new RetryableError('API overloaded', 529);
      expect(error.message).toBe('API overloaded');
      expect(error.statusCode).toBe(529);
      expect(error.name).toBe('RetryableError');
    });

    test('should identify as retryable based on status code', () => {
      const retryable = new RetryableError('Overloaded', 529);
      const nonRetryable = new RetryableError('Bad request', 400);

      expect(retryable.isRetryable()).toBe(true);
      expect(nonRetryable.isRetryable()).toBe(false);
    });
  });

  describe('withRetry', () => {
    test('should return result on first success', async () => {
      const fn = vi.fn().mockResolvedValue('success');

      const result = await withRetry(fn, { maxRetries: 3 });

      expect(result).toBe('success');
      expect(fn).toHaveBeenCalledTimes(1);
    });

    test('should retry on retryable error with exponential backoff', async () => {
      
      const delays: number[] = [];
      const fn = vi.fn()
        .mockRejectedValueOnce(new RetryableError('Overloaded', 529))
        .mockRejectedValueOnce(new RetryableError('Overloaded', 529))
        .mockResolvedValue('success');

      const config: RetryConfig = {
        maxRetries: 3,
        baseDelayMs: 10, // Short delays for faster test
        maxDelayMs: 100,
        onRetry: ({ delayMs }) => delays.push(delayMs)
      };

      const result = await withRetry(fn, config);

      expect(result).toBe('success');
      expect(fn).toHaveBeenCalledTimes(3);
      // Verify exponential backoff: 10ms, 20ms
      expect(delays).toEqual([10, 20]);
    });

    test('should throw after max retries exhausted', async () => {
      
      const fn = vi.fn().mockRejectedValue(new RetryableError('Overloaded', 529));

      const config: RetryConfig = {
        maxRetries: 2,  // Fewer retries for faster test
        baseDelayMs: 10, // Short delays
        maxDelayMs: 50
      };

      await expect(withRetry(fn, config)).rejects.toThrow('Overloaded');
      expect(fn).toHaveBeenCalledTimes(3); // 1 initial + 2 retries
    });

    test('should not retry non-retryable errors', async () => {
      const fn = vi.fn().mockRejectedValue(new Error('Bad request'));

      const config: RetryConfig = {
        maxRetries: 3,
        baseDelayMs: 1000
      };

      await expect(withRetry(fn, config)).rejects.toThrow('Bad request');
      expect(fn).toHaveBeenCalledTimes(1);
    });

    test('should not retry RetryableError with non-retryable status code', async () => {
      const fn = vi.fn().mockRejectedValue(new RetryableError('Bad request', 400));

      const config: RetryConfig = {
        maxRetries: 3,
        baseDelayMs: 1000
      };

      await expect(withRetry(fn, config)).rejects.toThrow('Bad request');
      expect(fn).toHaveBeenCalledTimes(1);
    });

    test('should cap delay at maxDelayMs', async () => {
      
      const delays: number[] = [];
      const fn = vi.fn()
        .mockRejectedValueOnce(new RetryableError('Overloaded', 529))
        .mockRejectedValueOnce(new RetryableError('Overloaded', 529))
        .mockRejectedValueOnce(new RetryableError('Overloaded', 529))
        .mockResolvedValue('success');

      const config: RetryConfig = {
        maxRetries: 4,
        baseDelayMs: 10,
        maxDelayMs: 15,  // Cap at 15ms (would be 10, 20, 40 without cap)
        onRetry: ({ delayMs }) => delays.push(delayMs)
      };

      const result = await withRetry(fn, config);

      expect(result).toBe('success');
      expect(fn).toHaveBeenCalledTimes(4);
      // Verify delays are capped: 10, 15 (capped from 20), 15 (capped from 40)
      expect(delays).toEqual([10, 15, 15]);
    });

    test('should call onRetry callback with attempt info', async () => {
      
      const onRetry = vi.fn();
      const fn = vi.fn()
        .mockRejectedValueOnce(new RetryableError('Overloaded', 529))
        .mockResolvedValue('success');

      const config: RetryConfig = {
        maxRetries: 3,
        baseDelayMs: 10,
        onRetry
      };

      await withRetry(fn, config);

      expect(onRetry).toHaveBeenCalledTimes(1);
      expect(onRetry).toHaveBeenCalledWith(
        expect.objectContaining({
          attempt: 1,
          error: expect.any(RetryableError),
          delayMs: 10
        })
      );
    });

    test('should use default config when not specified', async () => {
      
      // Override default with short delays for testing
      const fn = vi.fn()
        .mockRejectedValueOnce(new RetryableError('Overloaded', 529))
        .mockResolvedValue('success');

      // Test with explicit short config instead of defaults (defaults are 1000ms)
      const result = await withRetry(fn, { baseDelayMs: 10 });

      expect(result).toBe('success');
      expect(fn).toHaveBeenCalledTimes(2);
    });

    test('should handle async functions that throw Error with status property', async () => {
      
      // Some APIs throw Error objects with a status property
      const errorWithStatus = new Error('Overloaded') as Error & { status: number };
      errorWithStatus.status = 529;

      const fn = vi.fn()
        .mockRejectedValueOnce(errorWithStatus)
        .mockResolvedValue('success');

      const config: RetryConfig = {
        maxRetries: 3,
        baseDelayMs: 10,
        shouldRetry: (error) => {
          if (error instanceof Error && 'status' in error) {
            return isRetryableStatusCode((error as Error & { status: number }).status);
          }
          return false;
        }
      };

      const result = await withRetry(fn, config);
      expect(result).toBe('success');
      expect(fn).toHaveBeenCalledTimes(2);
    });
  });

  describe('withRetry edge cases', () => {
    test('should handle zero retries', async () => {
      const fn = vi.fn().mockRejectedValue(new RetryableError('Overloaded', 529));

      await expect(withRetry(fn, { maxRetries: 0 })).rejects.toThrow('Overloaded');
      expect(fn).toHaveBeenCalledTimes(1);
    });

    test('should handle functions that throw non-Error values', async () => {
      const fn = vi.fn().mockRejectedValue('string error');

      await expect(withRetry(fn, { maxRetries: 3 })).rejects.toBe('string error');
      expect(fn).toHaveBeenCalledTimes(1);
    });

    test('should pass through function arguments', async () => {
      const fn = vi.fn((a: number, b: string) => Promise.resolve(`${a}-${b}`));

      const wrappedFn = (a: number, b: string) => withRetry(() => fn(a, b));
      const result = await wrappedFn(42, 'test');

      expect(result).toBe('42-test');
      expect(fn).toHaveBeenCalledWith(42, 'test');
    });
  });
});

console.log('✅ Retry utility tests created');
