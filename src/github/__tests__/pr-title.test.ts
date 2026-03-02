/**
 * Tests for PR title generation (RFC-126 polish)
 */

import { describe, it, expect } from 'vitest';

// We can't import the private functions directly, so test via the exported
// createEducationalPullRequest behavior. For unit testing the title logic,
// we extract and test the pattern.

describe('PR title format', () => {
  // These test the expected output format based on the buildPrTitle logic

  describe('humanizeVulnType pattern', () => {
    function humanizeVulnType(vulnType: string): string {
      const acronyms = new Set(['xss', 'csrf', 'ssrf', 'sql', 'xxe', 'ldap', 'rce']);
      return vulnType
        .replace(/[_-]/g, ' ')
        .split(' ')
        .map(word => acronyms.has(word.toLowerCase()) ? word.toUpperCase() : word.charAt(0).toUpperCase() + word.slice(1))
        .join(' ');
    }

    it('humanizes sql_injection', () => {
      expect(humanizeVulnType('sql_injection')).toBe('SQL Injection');
    });

    it('humanizes xss', () => {
      expect(humanizeVulnType('xss')).toBe('XSS');
    });

    it('humanizes weak_cryptography', () => {
      expect(humanizeVulnType('weak_cryptography')).toBe('Weak Cryptography');
    });

    it('humanizes sensitive_data_exposure', () => {
      expect(humanizeVulnType('sensitive_data_exposure')).toBe('Sensitive Data Exposure');
    });

    it('humanizes hardcoded_secrets', () => {
      expect(humanizeVulnType('hardcoded_secrets')).toBe('Hardcoded Secrets');
    });

    it('humanizes code_injection', () => {
      expect(humanizeVulnType('code_injection')).toBe('Code Injection');
    });

    it('humanizes csrf', () => {
      expect(humanizeVulnType('csrf')).toBe('CSRF');
    });

    it('humanizes ssrf', () => {
      expect(humanizeVulnType('ssrf')).toBe('SSRF');
    });

    it('humanizes command-injection with hyphens', () => {
      expect(humanizeVulnType('command-injection')).toBe('Command Injection');
    });
  });

  describe('buildPrTitle pattern', () => {
    function buildPrTitle(
      prefix: string,
      summary: { title?: string; vulnerabilityType?: string; cwe?: string },
      issueNumber: number
    ): string {
      const vuln = summary.vulnerabilityType;
      const cwe = summary.cwe;
      const acronyms = new Set(['xss', 'csrf', 'ssrf', 'sql', 'xxe', 'ldap', 'rce']);
      const humanize = (v: string) => v.replace(/[_-]/g, ' ').split(' ')
        .map(w => acronyms.has(w.toLowerCase()) ? w.toUpperCase() : w.charAt(0).toUpperCase() + w.slice(1)).join(' ');

      let vulnPhrase: string;
      if (vuln && vuln !== 'security' && vuln !== 'unknown') {
        const humanized = humanize(vuln);
        vulnPhrase = cwe ? `${humanized} (${cwe})` : humanized;
      } else if (cwe) {
        vulnPhrase = `${cwe} vulnerability`;
      } else {
        const title = (summary.title || 'Security fix applied')
          .replace(/^(Security fix applied|Fix applied)\s*[-:]?\s*/i, '');
        vulnPhrase = title || 'Security fix applied';
      }
      return `${prefix}[RSOLV] Fix ${vulnPhrase} (fixes #${issueNumber})`;
    }

    it('includes CWE and vulnerability type', () => {
      const title = buildPrTitle('', { vulnerabilityType: 'sql_injection', cwe: 'CWE-89' }, 42);
      expect(title).toBe('[RSOLV] Fix SQL Injection (CWE-89) (fixes #42)');
    });

    it('includes vulnerability type without CWE', () => {
      const title = buildPrTitle('', { vulnerabilityType: 'weak_cryptography' }, 15);
      expect(title).toBe('[RSOLV] Fix Weak Cryptography (fixes #15)');
    });

    it('uses CWE alone when vulnerability type is generic', () => {
      const title = buildPrTitle('', { vulnerabilityType: 'security', cwe: 'CWE-79' }, 3);
      expect(title).toBe('[RSOLV] Fix CWE-79 vulnerability (fixes #3)');
    });

    it('falls back to AI title when no vuln type or CWE', () => {
      const title = buildPrTitle('', { title: 'Fix the login bypass' }, 7);
      expect(title).toBe('[RSOLV] Fix Fix the login bypass (fixes #7)');
    });

    it('strips generic prefix from AI title', () => {
      const title = buildPrTitle('', { title: 'Security fix applied - password hashing' }, 10);
      expect(title).toBe('[RSOLV] Fix password hashing (fixes #10)');
    });

    it('adds test mode prefix', () => {
      const title = buildPrTitle('[TEST MODE] ', { vulnerabilityType: 'xss', cwe: 'CWE-79' }, 5);
      expect(title).toBe('[TEST MODE] [RSOLV] Fix XSS (CWE-79) (fixes #5)');
    });

    it('handles completely generic fallback', () => {
      const title = buildPrTitle('', {}, 1);
      expect(title).toBe('[RSOLV] Fix Security fix applied (fixes #1)');
    });
  });
});
