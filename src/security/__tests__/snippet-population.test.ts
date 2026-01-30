import { describe, it, expect, vi, beforeEach } from 'vitest';
import { SecurityDetectorV2 } from '../detector-v2.js';
import { createPatternSource } from '../pattern-source.js';

// Mock the logger
vi.mock('../../utils/logger.js', () => ({
  logger: {
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    debug: vi.fn(),
  }
}));

describe('Snippet Population', () => {
  let detector: SecurityDetectorV2;

  beforeEach(() => {
    detector = new SecurityDetectorV2(createPatternSource());
  });

  it('should populate snippet field with the vulnerable line content', async () => {
    const code = `const query = "SELECT * FROM users WHERE id = " + userId;`;
    const vulns = await detector.detect(code, 'javascript', 'app.js');

    const sqlVulns = vulns.filter(v => v.type === 'sql_injection' || v.type === 'sql-injection');
    if (sqlVulns.length > 0) {
      for (const vuln of sqlVulns) {
        expect(vuln.snippet).toBeDefined();
        expect(vuln.snippet).not.toBe('');
        expect(vuln.snippet).toContain('SELECT');
      }
    }
  });

  it('should populate snippet for XSS vulnerabilities', async () => {
    const code = `document.write(userInput);`;
    const vulns = await detector.detect(code, 'javascript', 'app.js');

    const xssVulns = vulns.filter(v => v.type === 'xss');
    if (xssVulns.length > 0) {
      for (const vuln of xssVulns) {
        expect(vuln.snippet).toBeDefined();
        expect(vuln.snippet).not.toBe('');
        expect(vuln.snippet).toContain('document.write');
      }
    }
  });

  it('should populate snippet for hardcoded secrets', async () => {
    const code = `const API_KEY = "sk-1234567890abcdef1234567890abcdef";`;
    const vulns = await detector.detect(code, 'javascript', 'config.js');

    const secretVulns = vulns.filter(v => v.type === 'hardcoded_secrets' || v.type === 'hardcoded-secret');
    if (secretVulns.length > 0) {
      for (const vuln of secretVulns) {
        expect(vuln.snippet).toBeDefined();
        expect(vuln.snippet).not.toBe('');
      }
    }
  });

  it('should populate snippet for code injection vulnerabilities', async () => {
    const code = `eval(userInput);`;
    const vulns = await detector.detect(code, 'javascript', 'app.js');

    const codeInjVulns = vulns.filter(v => v.type === 'code_injection' || v.type === 'code-injection');
    if (codeInjVulns.length > 0) {
      for (const vuln of codeInjVulns) {
        expect(vuln.snippet).toBeDefined();
        expect(vuln.snippet).not.toBe('');
        expect(vuln.snippet).toContain('eval');
      }
    }
  });

  it('should populate snippet with correct line for multi-line code', async () => {
    const code = [
      'function process(input) {',
      '  const safe = sanitize(input);',
      '  eval(input);',  // line 3 - vulnerable
      '  return safe;',
      '}'
    ].join('\n');

    const vulns = await detector.detect(code, 'javascript', 'app.js');
    const codeInjVulns = vulns.filter(v => v.type === 'code_injection' || v.type === 'code-injection');

    if (codeInjVulns.length > 0) {
      expect(codeInjVulns[0].snippet).toContain('eval');
      expect(codeInjVulns[0].snippet).not.toContain('function');
    }
  });

  it('should ensure all detected vulnerabilities have snippet field', async () => {
    const code = `
const query = "SELECT * FROM users WHERE name = '" + name + "'";
eval(userCode);
document.write(data);
`;
    const vulns = await detector.detect(code, 'javascript', 'app.js');

    // Every vulnerability should have a snippet
    for (const vuln of vulns) {
      expect(vuln.snippet).toBeDefined();
      expect(typeof vuln.snippet).toBe('string');
      expect(vuln.snippet!.length).toBeGreaterThan(0);
    }
  });
});
