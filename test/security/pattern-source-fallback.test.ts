import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { createPatternSource, LocalPatternSource, ApiPatternSource, HybridPatternSource } from '../../src/security/pattern-source.js';
import { logger } from '../../src/utils/logger.js';

describe('Pattern Source Fallback Detection', () => {
  const originalEnv = { ...process.env };
  let loggerErrorSpy: any;
  let loggerWarnSpy: any;
  
  beforeEach(() => {
    // Clear environment
    delete process.env.RSOLV_API_KEY;
    delete process.env.RSOLV_API_URL;
    delete process.env.USE_LOCAL_PATTERNS;
    
    // Spy on logger methods
    loggerErrorSpy = vi.spyOn(logger, 'error');
    loggerWarnSpy = vi.spyOn(logger, 'warn');
  });
  
  afterEach(() => {
    // Restore environment
    process.env = { ...originalEnv };
    vi.restoreAllMocks();
  });
  
  describe('Minimal Pattern Fallback', () => {
    it('should log ERROR when falling back to minimal patterns due to missing API key', () => {
      // When no API key is provided
      const source = createPatternSource();
      
      // Should create LocalPatternSource
      expect(source).toBeInstanceOf(LocalPatternSource);
      
      // Should log error about falling back
      expect(loggerErrorSpy).toHaveBeenCalledWith(
        '🚨 CRITICAL CONFIGURATION ERROR',
        expect.objectContaining({
          error: expect.objectContaining({
            problem: 'No RSOLV_API_KEY provided',
            impact: 'Scanner will use minimal patterns and miss most vulnerabilities'
          })
        })
      );
      
      // Should also warn
      expect(loggerWarnSpy).toHaveBeenCalledWith(
        expect.stringContaining('minimal fallback patterns')
      );
    });
    
    it('should track pattern source metrics', async () => {
      // Create local source (fallback)
      const localSource = new LocalPatternSource();
      const patterns = await localSource.getPatternsByLanguage('javascript');
      
      // Should log metrics about limited patterns
      expect(loggerWarnSpy).toHaveBeenCalledWith(
        '📊 PATTERN SOURCE METRICS',
        expect.objectContaining({
          source: 'local',
          language: 'javascript',
          patternCount: patterns.length,
          expectedMinimum: 25,
          coveragePercentage: expect.any(String)
        })
      );
      
      // Should warn if below threshold
      if (patterns.length < 25) {
        expect(loggerErrorSpy).toHaveBeenCalledWith(
          expect.stringContaining('INSUFFICIENT PATTERNS'),
          expect.objectContaining({
            error: expect.objectContaining({
              language: 'javascript',
              actual: patterns.length,
              required: 25
            })
          })
        );
      }
    });
    
    it('should fail CI/CD when USE_FAIL_ON_MINIMAL_PATTERNS is set', () => {
      process.env.USE_FAIL_ON_MINIMAL_PATTERNS = 'true';
      
      // Should throw when trying to use minimal patterns
      expect(() => createPatternSource()).toThrow(
        'Cannot proceed with minimal patterns when USE_FAIL_ON_MINIMAL_PATTERNS is set'
      );
    });
  });
  
  describe('API Pattern Source', () => {
    it('should log success metrics when using API patterns', async () => {
      process.env.RSOLV_API_KEY = 'test-key';
      
      // Mock successful API response
      vi.mock('../../src/security/pattern-api-client.js', () => ({
        PatternAPIClient: vi.fn().mockImplementation(() => ({
          fetchPatterns: vi.fn().mockResolvedValue(
            Array(30).fill(null).map((_, i) => ({
              id: `pattern-${i}`,
              name: `Pattern ${i}`,
              type: 'xss',
              severity: 'high',
              patterns: { regex: [/test/] },
              languages: ['javascript']
            }))
          )
        }))
      }));
      
      const source = createPatternSource();
      expect(source).toBeInstanceOf(HybridPatternSource);
      
      // Fetch patterns
      const patterns = await source.getPatternsByLanguage('javascript');
      
      // Should log success metrics
      expect(logger.info).toHaveBeenCalledWith(
        expect.stringContaining('PATTERN SOURCE SUCCESS'),
        expect.objectContaining({
          source: 'api',
          patternCount: 30,
          language: 'javascript'
        })
      );
    });
  });
  
  describe('Regression Guards', () => {
    it('should validate minimum pattern requirements per language', async () => {
      const minimumPatterns = {
        javascript: 25,
        typescript: 25,
        python: 20,
        ruby: 15,
        php: 15,
        java: 20
      };
      
      const source = new LocalPatternSource();
      
      for (const [language, minimum] of Object.entries(minimumPatterns)) {
        const patterns = await source.getPatternsByLanguage(language);
        
        // This should fail for local source, demonstrating the problem
        if (patterns.length < minimum) {
          expect(loggerErrorSpy).toHaveBeenCalledWith(
            expect.stringContaining(`${language} has insufficient patterns`),
            expect.objectContaining({
              actual: patterns.length,
              required: minimum
            })
          );
        }
      }
    });
    
    it('should validate critical vulnerability types are covered', async () => {
      const criticalTypes = [
        'sql_injection',
        'command_injection',
        'xss',
        'path_traversal',
        'insecure_deserialization'
      ];
      
      const source = new LocalPatternSource();
      const allPatterns = await source.getAllPatterns();
      
      for (const type of criticalTypes) {
        const typePatterns = allPatterns.filter(p => p.type === type);
        
        if (typePatterns.length === 0) {
          expect(loggerErrorSpy).toHaveBeenCalledWith(
            expect.stringContaining(`MISSING CRITICAL PATTERN TYPE: ${type}`),
            expect.any(Object)
          );
        }
      }
    });
  });
});