import { describe, it, expect } from 'vitest';
import { extractOwaspFromIssue } from '../utils/extract-owasp.js';

describe('extractOwaspFromIssue', () => {
  it('extracts OWASP category from issue body markdown link', () => {
    const body = '**OWASP:** [A03:2021 - Injection](https://owasp.org/Top10/A03_2021-Injection/)';
    expect(extractOwaspFromIssue(body)).toBe('A03:2021 - Injection');
  });

  it('extracts OWASP category from body with surrounding content', () => {
    const body = `Some text before
**OWASP:** [A07:2021 - Identification and Authentication Failures](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/)
More text after`;
    expect(extractOwaspFromIssue(body)).toBe('A07:2021 - Identification and Authentication Failures');
  });

  it('extracts OWASP category when no URL is present (plain text)', () => {
    const body = '**OWASP:** A01:2021 - Broken Access Control';
    expect(extractOwaspFromIssue(body)).toBe('A01:2021 - Broken Access Control');
  });

  it('returns undefined when no OWASP in body', () => {
    const body = 'No OWASP category here, just a regular issue.';
    expect(extractOwaspFromIssue(body)).toBeUndefined();
  });

  it('returns undefined for empty body', () => {
    expect(extractOwaspFromIssue('')).toBeUndefined();
  });

  it('returns undefined for null/undefined body', () => {
    expect(extractOwaspFromIssue(null)).toBeUndefined();
    expect(extractOwaspFromIssue(undefined)).toBeUndefined();
  });

  it('handles OWASP category with extra whitespace', () => {
    const body = '**OWASP:**   [A05:2021 - Security Misconfiguration](https://owasp.org/Top10/A05/)';
    expect(extractOwaspFromIssue(body)).toBe('A05:2021 - Security Misconfiguration');
  });
});
