import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { SafeDetector } from './safe-detector.js';

describe('SafeDetector', () => {
  let detector: SafeDetector;

  beforeEach(() => {
    detector = new SafeDetector();
  });

  afterEach(() => {
    detector.cleanup();
  });

  // Helper to create test patterns
  const createPattern = (id: string, regex: RegExp, type = 'test', severity = 'high') => ({
    id,
    name: `${id} pattern`,
    type,
    severity,
    patterns: { regex: [regex] }
  });

  // Known catastrophic backtracking pattern: (a+)+b with string of a's but no b
  const CATASTROPHIC_PATTERN = /(a+)+b/;
  const CATASTROPHIC_INPUT = (length: number) => 'a'.repeat(length) + 'X';

  describe('timeout handling', () => {
    it('completes quickly for normal patterns', async () => {
      const code = 'const password = "secretpass123";';
      const start = Date.now();

      const result = await detector.detect(code, 'javascript');

      expect(Date.now() - start).toBeLessThan(1000);
      expect(result).toBeInstanceOf(Array);
    });

    it('times out and returns empty array for catastrophic backtracking', async () => {
      const pattern = createPattern('catastrophic', CATASTROPHIC_PATTERN);
      const start = Date.now();

      const result = await detector.detectWithPattern(
        CATASTROPHIC_INPUT(50),
        'javascript',
        pattern,
        1000
      );
      const duration = Date.now() - start;

      expect(result).toEqual([]);
      expect(duration).toBeGreaterThan(900);
      expect(duration).toBeLessThan(2000);
    });

    it('handles catastrophic backtracking with longer input', async () => {
      const pattern = createPattern('infinite-loop', CATASTROPHIC_PATTERN);

      const result = await detector.detectWithPattern(
        CATASTROPHIC_INPUT(30),
        'ruby',
        pattern,
        2000
      );

      expect(result).toEqual([]);
    });

    it('terminates worker thread on timeout', async () => {
      const pattern = createPattern('hanging', CATASTROPHIC_PATTERN);

      await detector.detectWithPattern(
        CATASTROPHIC_INPUT(100),
        'javascript',
        pattern,
        500
      );

      expect(detector.getLastWorkerTerminated()).toBe(true);
    });
  });

  describe('safe-regex pre-filtering', () => {
    it('skips unsafe patterns', async () => {
      const pattern = createPattern('unsafe', CATASTROPHIC_PATTERN);

      const result = await detector.detectWithPattern('some code', 'javascript', pattern);

      expect(result).toEqual([]);
      expect(detector.getSkippedPatterns()).toContain('unsafe');
    });

    it('processes safe patterns', async () => {
      const pattern = createPattern(
        'safe-password',
        /password\s*=\s*["'][^"']+["']/,
        'hardcoded-secret'
      );

      const result = await detector.detectWithPattern(
        'const password = "secret123"',
        'javascript',
        pattern
      );

      expect(result.length).toBeGreaterThan(0);
      expect(result[0].type).toBe('hardcoded-secret');
    });
  });

  describe('worker thread management', () => {
    it('cleans up workers after use', async () => {
      await detector.detect('test', 'javascript');

      expect(detector.getWorkerCount()).toBe(0);
    });

    it('handles worker errors gracefully', async () => {
      const result = await detector.detect(null as any, 'javascript');

      expect(result).toEqual([]);
      expect(detector.getLastError()).toBeDefined();
    });

    it('handles concurrent detections', async () => {
      const results = await Promise.all([
        detector.detect('code1', 'javascript'),
        detector.detect('code2', 'python'),
        detector.detect('code3', 'ruby')
      ]);

      expect(results).toHaveLength(3);
      results.forEach(result => expect(result).toBeInstanceOf(Array));
    });
  });

  describe('backwards compatibility', () => {
    it('maintains SecurityDetectorV2 interface', async () => {
      const result = await detector.detect('console.log("test")', 'javascript');

      expect(result).toBeInstanceOf(Array);
    });

    it('returns correctly structured vulnerability objects', async () => {
      const result = await detector.detect('eval(userInput)', 'javascript');

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
});
