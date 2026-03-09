import { describe, it, expect } from 'vitest';
import { formatOwaspLink } from '../../scanner/issue-creator';

describe('formatOwaspLink (exported)', () => {
  it('formats A03:2021 as clickable link', () => {
    const link = formatOwaspLink('A03:2021');
    expect(link).toContain('[A03:2021');
    expect(link).toContain('https://owasp.org/Top10/A03_2021-Injection/');
  });

  it('formats A01:2021 as clickable link', () => {
    const link = formatOwaspLink('A01:2021');
    expect(link).toContain('[A01:2021');
    expect(link).toContain('https://owasp.org/Top10/A01_2021-Broken_Access_Control/');
  });

  it('returns raw category for unknown code', () => {
    const link = formatOwaspLink('A99:2025');
    expect(link).toBe('A99:2025');
  });

  it('returns raw string for non-matching format', () => {
    const link = formatOwaspLink('not-an-owasp-code');
    expect(link).toBe('not-an-owasp-code');
  });
});
