import { describe, it, expect } from 'bun:test';
import { PatternRegistry } from '../patterns.js';
import { VulnerabilityType } from '../types.js';

describe('PatternRegistry', () => {
  const registry = new PatternRegistry();

  describe('Pattern Management', () => {
    it('should return SQL injection patterns', () => {
      const patterns = registry.getPatterns(VulnerabilityType.SQL_INJECTION);
      
      expect(patterns.length).toBeGreaterThan(2); // Now includes multi-language patterns
      const ids = patterns.map(p => p.id);
      expect(ids).toContain('sql-injection-concat');
      expect(ids).toContain('sql-injection-template');
    });

    it('should return XSS patterns', () => {
      const patterns = registry.getPatterns(VulnerabilityType.XSS);
      
      expect(patterns.length).toBeGreaterThan(2); // Now includes multi-language patterns
      const ids = patterns.map(p => p.id);
      expect(ids).toContain('xss-inner-html');
      expect(ids).toContain('xss-document-write');
    });

    it('should return all patterns', () => {
      const allPatterns = registry.getAllPatterns();
      
      expect(allPatterns.length).toBeGreaterThan(40); // Now includes Python, Ruby, and Java patterns
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
      const pythonPatterns = registry.getPatternsByLanguage('python');
      const javaPatterns = registry.getPatternsByLanguage('java');
      
      expect(jsPatterns.length).toBeGreaterThan(10); // Original JS patterns
      expect(tsPatterns.length).toBeGreaterThan(10); // Original TS patterns
      expect(rubyPatterns.length).toBeGreaterThan(0); // New Ruby patterns
      expect(pythonPatterns.length).toBeGreaterThan(0); // New Python patterns
      expect(javaPatterns.length).toBeGreaterThan(0); // New Java patterns
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