import { describe, it, expect } from 'bun:test';
import { PatternRegistry } from '../patterns.js';
import { VulnerabilityType } from '../types.js';

describe('PatternRegistry', () => {
  const registry = new PatternRegistry();

  describe('Pattern Management', () => {
    it('should return SQL injection patterns', () => {
      const patterns = registry.getPatterns(VulnerabilityType.SQL_INJECTION);
      
      expect(patterns).toHaveLength(2);
      expect(patterns[0].id).toBe('sql-injection-concat');
      expect(patterns[1].id).toBe('sql-injection-template');
    });

    it('should return XSS patterns', () => {
      const patterns = registry.getPatterns(VulnerabilityType.XSS);
      
      expect(patterns).toHaveLength(2);
      expect(patterns[0].id).toBe('xss-inner-html');
      expect(patterns[1].id).toBe('xss-document-write');
    });

    it('should return all patterns', () => {
      const allPatterns = registry.getAllPatterns();
      
      expect(allPatterns).toHaveLength(12); // 2 patterns for SQL injection, 2 for XSS, 1 for each other OWASP category
      expect(allPatterns.map(p => p.id)).toContain('sql-injection-concat');
      expect(allPatterns.map(p => p.id)).toContain('xss-inner-html');
      expect(allPatterns.map(p => p.id)).toContain('broken-access-control-no-auth');
    });

    it('should have patterns for all OWASP Top 10 vulnerabilities', () => {
      const owaspVulnerabilities = [
        VulnerabilityType.BROKEN_ACCESS_CONTROL,
        VulnerabilityType.SENSITIVE_DATA_EXPOSURE,
        VulnerabilityType.SQL_INJECTION,
        VulnerabilityType.INSECURE_DESERIALIZATION,
        VulnerabilityType.SECURITY_MISCONFIGURATION,
        VulnerabilityType.XSS,
        VulnerabilityType.XML_EXTERNAL_ENTITIES,
        VulnerabilityType.BROKEN_AUTHENTICATION,
        VulnerabilityType.VULNERABLE_COMPONENTS,
        VulnerabilityType.INSUFFICIENT_LOGGING
      ];

      for (const vulnType of owaspVulnerabilities) {
        const patterns = registry.getPatterns(vulnType);
        expect(patterns.length).toBeGreaterThan(0);
        expect(patterns[0].type).toBe(vulnType);
      }
    });

    it('should filter patterns by language', () => {
      const jsPatterns = registry.getPatternsByLanguage('javascript');
      const tsPatterns = registry.getPatternsByLanguage('typescript');
      const rubyPatterns = registry.getPatternsByLanguage('ruby');
      
      expect(jsPatterns).toHaveLength(12);
      expect(tsPatterns).toHaveLength(12);
      expect(rubyPatterns).toHaveLength(0);
    });
  });

  describe('Pattern Properties', () => {
    it('should have complete pattern metadata', () => {
      const patterns = registry.getAllPatterns();
      
      for (const pattern of patterns) {
        expect(pattern.id).toBeDefined();
        expect(pattern.type).toBeDefined();
        expect(pattern.name).toBeDefined();
        expect(pattern.description).toBeDefined();
        expect(pattern.severity).toBeDefined();
        expect(pattern.cweId).toBeDefined();
        expect(pattern.owaspCategory).toBeDefined();
        expect(pattern.languages).toBeDefined();
        expect(pattern.remediation).toBeDefined();
        expect(pattern.examples.vulnerable).toBeDefined();
        expect(pattern.examples.secure).toBeDefined();
      }
    });

    it('should have valid regex patterns', () => {
      const patterns = registry.getAllPatterns();
      
      for (const pattern of patterns) {
        expect(pattern.patterns.regex).toBeDefined();
        expect(pattern.patterns.regex!.length).toBeGreaterThan(0);
        
        for (const regex of pattern.patterns.regex!) {
          expect(regex).toBeInstanceOf(RegExp);
        }
      }
    });
  });

  describe('Safe Usage Detection', () => {
    it('should detect safe SQL usage', () => {
      const safeSql = 'const query = "SELECT * FROM users WHERE id = ?";';
      const unsafeSql = 'const query = "SELECT * FROM users WHERE id = " + userId;';
      
      expect(registry.isSafeUsage(safeSql, VulnerabilityType.SQL_INJECTION)).toBe(true);
      expect(registry.isSafeUsage(unsafeSql, VulnerabilityType.SQL_INJECTION)).toBe(false);
    });

    it('should detect safe XSS usage', () => {
      const safeXss = 'element.textContent = userInput;';
      const unsafeXss = 'element.innerHTML = userInput;';
      
      expect(registry.isSafeUsage(safeXss, VulnerabilityType.XSS)).toBe(true);
      expect(registry.isSafeUsage(unsafeXss, VulnerabilityType.XSS)).toBe(false);
    });
  });
});