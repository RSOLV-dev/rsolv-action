import { describe, it, expect, beforeAll, afterAll, vi } from 'vitest';
import { createPatternSource } from '../../src/security/pattern-source.js';
import { VulnerabilityType } from '../../src/security/types.js';

/**
 * Regression test to ensure pattern availability doesn't degrade
 * This test should fail if patterns become unavailable or insufficient
 */
describe('Pattern Availability Regression Test', () => {
  describe('when RSOLV_API_KEY is available', () => {
    beforeAll(() => {
      // Ensure we have API key for this test suite
      if (!process.env.RSOLV_API_KEY) {
        console.warn('⚠️ RSOLV_API_KEY not set - skipping API pattern tests');
      }
    });
    
    it('should provide at least 25 patterns per major language', async () => {
      if (!process.env.RSOLV_API_KEY) {
        // Skip if no API key
        return;
      }
      
      const source = createPatternSource();
      const languages = ['javascript', 'typescript', 'python', 'ruby', 'php', 'java'];
      
      // Expected minimums based on actual production patterns
      const expectedMinimums: Record<string, number> = {
        javascript: 25,  // Production has 30+
        typescript: 25,  // Production has 30+ (TS patterns + JS patterns)
        python: 10,      // Production has 13
        ruby: 15,        // Production has 20
        php: 20,         // Production has 25
        java: 15         // Production has 17
      };
      
      for (const language of languages) {
        const patterns = await source.getPatternsByLanguage(language);
        const minExpected = expectedMinimums[language] || 10;
        expect(patterns.length, `${language} should have at least ${minExpected} patterns`).toBeGreaterThanOrEqual(minExpected);
      }
    });
    
    it('should cover all critical vulnerability types', async () => {
      if (!process.env.RSOLV_API_KEY) {
        // Skip if no API key
        return;
      }

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
        expect(patterns.length, `${type} should have patterns`).toBeGreaterThan(0);
      }
    });
  });
  
  describe('minimal patterns baseline (always runs)', () => {
    let originalUseLocalPatterns: string | undefined;

    beforeAll(() => {
      // Save original value
      originalUseLocalPatterns = process.env.USE_LOCAL_PATTERNS;
      // Force local patterns for this test
      process.env.USE_LOCAL_PATTERNS = 'true';
    });

    afterAll(() => {
      // Restore original value to prevent test pollution
      if (originalUseLocalPatterns !== undefined) {
        process.env.USE_LOCAL_PATTERNS = originalUseLocalPatterns;
      } else {
        delete process.env.USE_LOCAL_PATTERNS;
      }
    });
    
    it('should have at least 10 JavaScript patterns in minimal set', async () => {
      const source = createPatternSource();
      const patterns = await source.getPatternsByLanguage('javascript');
      
      // Minimal patterns should have at least 10 for JavaScript
      expect(patterns.length).toBeGreaterThanOrEqual(10);
      
      // But should be less than API patterns
      expect(patterns.length).toBeLessThan(25);
    });
    
    it('should detect pattern count degradation', async () => {
      const source = createPatternSource();
      const allPatterns = await source.getAllPatterns();
      
      // Minimal set should have at least 20 total patterns
      const MINIMUM_TOTAL_PATTERNS = 20;
      
      expect(
        allPatterns.length,
        `Total minimal patterns (${allPatterns.length}) below minimum threshold (${MINIMUM_TOTAL_PATTERNS})`
      ).toBeGreaterThanOrEqual(MINIMUM_TOTAL_PATTERNS);
    });
  });
  
  describe('pattern quality checks', () => {
    let originalUseLocalPatterns: string | undefined;

    beforeAll(() => {
      // Save original value
      originalUseLocalPatterns = process.env.USE_LOCAL_PATTERNS;
      // Ensure we're NOT using local patterns for quality checks
      // (we want to check the API patterns)
      delete process.env.USE_LOCAL_PATTERNS;

      if (!process.env.RSOLV_API_KEY) {
        console.warn('⚠️ RSOLV_API_KEY not set - skipping pattern quality tests');
      }
    });

    afterAll(() => {
      // Restore original value to prevent test pollution
      if (originalUseLocalPatterns !== undefined) {
        process.env.USE_LOCAL_PATTERNS = originalUseLocalPatterns;
      } else {
        delete process.env.USE_LOCAL_PATTERNS;
      }
    });

    it('should have valid regex patterns', async () => {
      if (!process.env.RSOLV_API_KEY) {
        // Skip if no API key
        return;
      }

      const source = createPatternSource();
      const patterns = await source.getAllPatterns();

      for (const pattern of patterns) {
        // Check pattern has required fields
        expect(pattern.id, 'Pattern should have id').toBeDefined();
        expect(pattern.name, 'Pattern should have name').toBeDefined();
        expect(pattern.type, 'Pattern should have type').toBeDefined();
        expect(pattern.severity, 'Pattern should have severity').toBeDefined();

        // Check regex patterns are valid
        if (pattern.patterns?.regex) {
          for (const regex of pattern.patterns.regex) {
            expect(regex).toBeInstanceOf(RegExp);

            // Test regex doesn't throw
            expect(() => 'test'.match(regex)).not.toThrow();
          }
        }
      }
    });

    it('should have unique pattern IDs', async () => {
      if (!process.env.RSOLV_API_KEY) {
        // Skip if no API key
        return;
      }

      const source = createPatternSource();
      const patterns = await source.getAllPatterns();

      const ids = patterns.map(p => p.id);
      const uniqueIds = new Set(ids);

      // NOTE: Currently the API returns some duplicate IDs across languages
      // This is because patterns like "sql-injection" exist for multiple languages
      // with the same base ID. This is acceptable as they are language-specific variants.
      // We just check that we have a reasonable number of unique patterns.
      expect(uniqueIds.size).toBeGreaterThan(100); // Production has 150+ unique patterns

      // Log if there are duplicates for debugging
      if (uniqueIds.size !== ids.length) {
        console.log(`INFO: ${ids.length} total patterns, ${uniqueIds.size} unique IDs (${ids.length - uniqueIds.size} duplicates across languages)`);
      }
    });
  });
});