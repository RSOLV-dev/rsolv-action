import { describe, it, expect } from 'bun:test';
import { SecurityDetector } from '../detector.js';
import { VulnerabilityType } from '../types.js';

describe('SecurityDetector', () => {
  const detector = new SecurityDetector();

  describe('SQL Injection Detection', () => {
    it('should detect SQL injection in concatenated queries', () => {
      const code = `
        const query = "SELECT * FROM users WHERE id = " + userId;
        db.query(query);
      `;
      
      const vulnerabilities = detector.detect(code, 'javascript');
      
      expect(vulnerabilities).toHaveLength(1);
      expect(vulnerabilities[0].type).toBe(VulnerabilityType.SQL_INJECTION);
      expect(vulnerabilities[0].severity).toBe('high');
      expect(vulnerabilities[0].line).toBe(2);
    });

    it('should detect SQL injection in template literals', () => {
      const code = `
        const query = \`SELECT * FROM users WHERE name = '\${userName}'\`;
        db.query(query);
      `;
      
      const vulnerabilities = detector.detect(code, 'javascript');
      
      expect(vulnerabilities).toHaveLength(1);
      expect(vulnerabilities[0].type).toBe(VulnerabilityType.SQL_INJECTION);
    });

    it('should not flag parameterized queries', () => {
      const code = `
        const query = "SELECT * FROM users WHERE id = ?";
        db.query(query, [userId]);
      `;
      
      const vulnerabilities = detector.detect(code, 'javascript');
      
      expect(vulnerabilities).toHaveLength(0);
    });
  });

  describe('XSS Detection', () => {
    it('should detect XSS in innerHTML assignments', () => {
      const code = `
        element.innerHTML = userInput;
      `;
      
      const vulnerabilities = detector.detect(code, 'javascript');
      
      expect(vulnerabilities).toHaveLength(1);
      expect(vulnerabilities[0].type).toBe(VulnerabilityType.XSS);
      expect(vulnerabilities[0].severity).toBe('high');
    });

    it('should detect XSS in document.write', () => {
      const code = `
        document.write(userContent);
      `;
      
      const vulnerabilities = detector.detect(code, 'javascript');
      
      expect(vulnerabilities).toHaveLength(1);
      expect(vulnerabilities[0].type).toBe(VulnerabilityType.XSS);
    });

    it('should not flag sanitized content', () => {
      const code = `
        element.textContent = userInput;
      `;
      
      const vulnerabilities = detector.detect(code, 'javascript');
      
      expect(vulnerabilities).toHaveLength(0);
    });
  });

  describe('Language Support', () => {
    it('should support JavaScript and TypeScript', () => {
      const jsCode = `const query = "SELECT * FROM users WHERE id = " + id;`;
      const tsCode = `const query: string = "SELECT * FROM users WHERE id = " + id;`;
      
      const jsVulns = detector.detect(jsCode, 'javascript');
      const tsVulns = detector.detect(tsCode, 'typescript');
      
      expect(jsVulns).toHaveLength(1);
      expect(tsVulns).toHaveLength(1);
    });
  });
});