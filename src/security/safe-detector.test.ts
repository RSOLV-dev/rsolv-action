import { describe, it, expect, beforeEach, vi } from 'vitest';
import { SafeDetector } from './safe-detector.js';
import type { Vulnerability } from './types.js';

describe('SafeDetector', () => {
  let detector: SafeDetector;

  beforeEach(() => {
    detector = new SafeDetector();
  });

  describe('timeout handling', () => {
    it('should complete quickly for normal regex patterns', async () => {
      const code = `
        const password = "secretpass123";
        console.log(password);
      `;

      const start = Date.now();
      const result = await detector.detect(code, 'javascript');
      const duration = Date.now() - start;

      expect(duration).toBeLessThan(1000); // Should complete in under 1 second
      expect(result).toBeDefined();
      expect(Array.isArray(result)).toBe(true);
    });

    it('should timeout and return empty array for catastrophic backtracking regex', async () => {
      // This regex is known to cause catastrophic backtracking
      const problematicCode = 'a'.repeat(50) + 'X';
      const problematicPattern = {
        id: 'test-catastrophic',
        name: 'Catastrophic Pattern',
        type: 'test',
        severity: 'high',
        patterns: {
          regex: [/(a+)+b/] // This will cause exponential backtracking
        }
      };

      const start = Date.now();
      const result = await detector.detectWithPattern(problematicCode, 'javascript', problematicPattern, 1000);
      const duration = Date.now() - start;

      expect(duration).toBeLessThan(2000); // Should timeout at ~1 second
      expect(duration).toBeGreaterThan(900); // Should take close to timeout
      expect(result).toEqual([]); // Should return empty array on timeout
    });

    it('should handle infinite loop in pattern matching', async () => {
      // Simulate the user.rb hang scenario
      const userRbContent = `
        class User < ApplicationRecord
          def authenticate(email, password)
            if user.password == Digest::MD5.hexdigest(password)
              auth = user
            end
          end
        end
      `;

      // This simulates a pattern that causes infinite loop
      const infiniteLoopPattern = {
        id: 'infinite-loop-pattern',
        name: 'Infinite Loop Pattern',
        type: 'test',
        severity: 'high',
        patterns: {
          regex: [/(?:.*){1,1000}(?:.*){1,1000}/] // Nested quantifiers
        }
      };

      const result = await detector.detectWithPattern(userRbContent, 'ruby', infiniteLoopPattern, 2000);

      expect(result).toEqual([]); // Should return empty on timeout
    });

    it('should properly terminate worker thread on timeout', async () => {
      const code = 'test code';
      const hangingPattern = {
        id: 'hanging',
        name: 'Hanging Pattern',
        type: 'test',
        severity: 'high',
        patterns: {
          regex: [/(a+)+b/]
        }
      };

      // Spy on worker termination
      const terminateSpy = vi.fn();

      await detector.detectWithPattern('a'.repeat(100), 'javascript', hangingPattern, 500);

      // Worker should have been terminated
      // Note: We'll need to expose this for testing
      expect(detector.getLastWorkerTerminated()).toBe(true);
    });
  });

  describe('safe-regex pre-filtering', () => {
    it('should skip patterns identified as unsafe by safe-regex', async () => {
      const code = 'some code';

      // This pattern is known to be unsafe
      const unsafePattern = {
        id: 'unsafe',
        name: 'Unsafe Pattern',
        type: 'test',
        severity: 'high',
        patterns: {
          regex: [/(a+)+b/] // Nested quantifiers - unsafe
        }
      };

      const result = await detector.detectWithPattern(code, 'javascript', unsafePattern);

      // Should skip the unsafe pattern and return empty
      expect(result).toEqual([]);
      expect(detector.getSkippedPatterns()).toContain('unsafe');
    });

    it('should process patterns identified as safe by safe-regex', async () => {
      const code = 'const password = "secret123"';

      // Simple, safe pattern
      const safePattern = {
        id: 'safe-password',
        name: 'Safe Password Pattern',
        type: 'hardcoded-secret',
        severity: 'high',
        patterns: {
          regex: [/password\s*=\s*["'][^"']+["']/] // Simple, linear pattern
        }
      };

      const result = await detector.detectWithPattern(code, 'javascript', safePattern);

      // Should find the vulnerability
      expect(result.length).toBeGreaterThan(0);
      expect(result[0].type).toBe('hardcoded-secret');
    });
  });

  describe('worker thread management', () => {
    it('should create worker for each detection request', async () => {
      const code = 'test';

      await detector.detect(code, 'javascript');

      expect(detector.getWorkerCount()).toBe(0); // Worker should be cleaned up after use
    });

    it('should handle worker errors gracefully', async () => {
      const code = null as any; // This will cause an error in the worker

      const result = await detector.detect(code, 'javascript');

      expect(result).toEqual([]); // Should return empty array on error
      expect(detector.getLastError()).toBeDefined();
    });

    it('should handle multiple concurrent detections', async () => {
      const detections = [
        detector.detect('code1', 'javascript'),
        detector.detect('code2', 'python'),
        detector.detect('code3', 'ruby')
      ];

      const results = await Promise.all(detections);

      expect(results).toHaveLength(3);
      results.forEach(result => {
        expect(Array.isArray(result)).toBe(true);
      });
    });
  });

  describe('backwards compatibility', () => {
    it('should maintain compatibility with existing SecurityDetectorV2 interface', async () => {
      const code = 'console.log("test")';

      // Should work with the same interface as SecurityDetectorV2
      const result = await detector.detect(code, 'javascript');

      expect(Array.isArray(result)).toBe(true);
    });

    it('should return vulnerability objects with correct structure', async () => {
      const code = 'eval(userInput)';

      const result = await detector.detect(code, 'javascript');

      if (result.length > 0) {
        const vuln = result[0];
        expect(vuln).toHaveProperty('type');
        expect(vuln).toHaveProperty('severity');
        expect(vuln).toHaveProperty('line');
        expect(vuln).toHaveProperty('message');
        expect(vuln).toHaveProperty('description');
      }
    });
  });

  afterEach(() => {
    // Clean up any remaining workers
    detector.cleanup();
  });
});