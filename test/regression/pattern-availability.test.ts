import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { createPatternSource } from '../../src/security/pattern-source.js';
import { VulnerabilityType } from '../../src/security/types.js';

/**
 * Regression tests ensuring pattern availability doesn't degrade.
 * Tests fail if patterns become unavailable or drop below production thresholds.
 */

const hasApiKey = () => !!process.env.RSOLV_API_KEY;

const restoreEnv = (key: string, original: string | undefined) => {
  if (original !== undefined) {
    process.env[key] = original;
  } else {
    delete process.env[key];
  }
};

describe('Pattern Availability Regression', () => {
  describe('API Pattern Coverage', () => {
    const skipIfNoKey = () => {
      if (!hasApiKey()) {
        console.warn('⚠️  RSOLV_API_KEY not set - skipping API tests');
        return true;
      }
      return false;
    };

    it('provides sufficient patterns per language', async () => {
      if (skipIfNoKey()) return;

      const source = createPatternSource();
      const languageMinimums = {
        javascript: 25,
        typescript: 25,
        python: 10,
        ruby: 15,
        php: 20,
        java: 15
      };

      for (const [language, minimum] of Object.entries(languageMinimums)) {
        const patterns = await source.getPatternsByLanguage(language);
        expect(patterns.length, `${language} patterns`).toBeGreaterThanOrEqual(minimum);
      }
    });

    it('covers all critical vulnerability types', async () => {
      if (skipIfNoKey()) return;

      const source = createPatternSource();
      const criticalTypes = [
        VulnerabilityType.SQL_INJECTION,
        VulnerabilityType.COMMAND_INJECTION,
        VulnerabilityType.XSS,
        VulnerabilityType.PATH_TRAVERSAL,
        VulnerabilityType.INSECURE_DESERIALIZATION
      ];

      for (const type of criticalTypes) {
        const patterns = await source.getPatternsByType(type);
        expect(patterns.length, `${type} patterns`).toBeGreaterThan(0);
      }
    });
  });

  describe('Local Pattern Baseline', () => {
    let originalEnv: string | undefined;

    beforeAll(() => {
      originalEnv = process.env.USE_LOCAL_PATTERNS;
      process.env.USE_LOCAL_PATTERNS = 'true';
    });

    afterAll(() => restoreEnv('USE_LOCAL_PATTERNS', originalEnv));

    it('provides minimal JavaScript pattern set', async () => {
      const source = createPatternSource();
      const patterns = await source.getPatternsByLanguage('javascript');

      expect(patterns.length).toBeGreaterThanOrEqual(10);
      expect(patterns.length).toBeLessThan(25);
    });

    it('maintains minimum total pattern count', async () => {
      const source = createPatternSource();
      const patterns = await source.getAllPatterns();
      const MINIMUM = 20;

      expect(patterns.length, `total patterns: ${patterns.length}`).toBeGreaterThanOrEqual(MINIMUM);
    });
  });

  describe('Pattern Quality', () => {
    let originalEnv: string | undefined;

    beforeAll(() => {
      originalEnv = process.env.USE_LOCAL_PATTERNS;
      delete process.env.USE_LOCAL_PATTERNS;

      if (!hasApiKey()) {
        console.warn('⚠️  RSOLV_API_KEY not set - skipping quality tests');
      }
    });

    afterAll(() => restoreEnv('USE_LOCAL_PATTERNS', originalEnv));

    it('validates regex patterns are well-formed', async () => {
      if (!hasApiKey()) return;

      const source = createPatternSource();
      const patterns = await source.getAllPatterns();

      for (const pattern of patterns) {
        expect(pattern.id, 'pattern.id').toBeDefined();
        expect(pattern.name, 'pattern.name').toBeDefined();
        expect(pattern.type, 'pattern.type').toBeDefined();
        expect(pattern.severity, 'pattern.severity').toBeDefined();

        if (pattern.patterns?.regex) {
          for (const regex of pattern.patterns.regex) {
            expect(regex).toBeInstanceOf(RegExp);
            expect(() => 'test'.match(regex)).not.toThrow();
          }
        }
      }
    });

    it('maintains reasonable ID uniqueness', async () => {
      if (!hasApiKey()) return;

      const source = createPatternSource();
      const patterns = await source.getAllPatterns();
      const uniqueIds = new Set(patterns.map(p => p.id));

      // Duplicate IDs across languages are acceptable (language-specific variants)
      expect(uniqueIds.size, 'unique pattern IDs').toBeGreaterThan(100);

      if (uniqueIds.size !== patterns.length) {
        const duplicates = patterns.length - uniqueIds.size;
        console.log(`INFO: ${patterns.length} total, ${uniqueIds.size} unique IDs (${duplicates} language variants)`);
      }
    });
  });
});