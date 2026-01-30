import { describe, it, expect, vi, beforeEach } from 'vitest';
import { IssueCreator } from '../issue-creator.js';
import type { VulnerabilityGroup, ScanConfig } from '../types.js';

// Mock GitHub client
vi.mock('../../github/api.js', () => ({
  getGitHubClient: vi.fn(() => ({
    issues: {
      listForRepo: vi.fn().mockResolvedValue({ data: [] }),
      create: vi.fn().mockResolvedValue({ data: { number: 1, html_url: 'https://github.com/test/repo/issues/1' } }),
      update: vi.fn().mockResolvedValue({ data: {} }),
      addLabels: vi.fn().mockResolvedValue({ data: {} }),
    }
  }))
}));

vi.mock('../../utils/logger.js', () => ({
  logger: {
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    debug: vi.fn(),
  }
}));

describe('Issue Body Enrichment', () => {
  let issueCreator: IssueCreator;
  const config: ScanConfig = {
    repository: { owner: 'test', name: 'repo', defaultBranch: 'main' },
    createIssues: true,
    issueLabel: 'rsolv:detected',
  };

  beforeEach(() => {
    issueCreator = new IssueCreator();
  });

  function createGroup(overrides: Partial<VulnerabilityGroup> = {}): VulnerabilityGroup {
    return {
      type: 'sql_injection',
      severity: 'high',
      count: 1,
      files: ['app.js'],
      vulnerabilities: [{
        type: 'sql_injection' as never,
        severity: 'high',
        line: 10,
        message: 'SQL Injection detected',
        description: 'User input in SQL query',
        confidence: 85,
        cweId: 'CWE-89',
        owaspCategory: 'A03:2021 Injection',
        filePath: 'app.js',
        snippet: 'const query = "SELECT * FROM users WHERE id = " + userId;',
      }],
      ...overrides,
    };
  }

  // Access private method via bracket notation for testing
  function generateBody(group: VulnerabilityGroup): string {
    return (issueCreator as Record<string, unknown>)['generateIssueBody'].call(issueCreator, group, config) as string;
  }

  it('should include CWE ID when available', () => {
    const body = generateBody(createGroup());
    expect(body).toContain('CWE-89');
    expect(body).toContain('cwe.mitre.org');
  });

  it('should include OWASP category when available', () => {
    const body = generateBody(createGroup());
    expect(body).toContain('A03:2021 Injection');
  });

  it('should include confidence score', () => {
    const body = generateBody(createGroup());
    expect(body).toContain('85%');
  });

  it('should include Security Classification section', () => {
    const body = generateBody(createGroup());
    expect(body).toContain('### Security Classification');
  });

  it('should handle missing CWE gracefully', () => {
    const group = createGroup({
      vulnerabilities: [{
        type: 'xss' as never,
        severity: 'medium',
        line: 5,
        message: 'XSS detected',
        description: 'Cross-site scripting',
        confidence: 70,
        filePath: 'app.js',
      }],
    });
    const body = generateBody(group);
    // Should not crash, should not contain CWE section
    expect(body).toContain('Security Vulnerability Report');
    expect(body).not.toContain('cwe.mitre.org');
  });

  it('should handle missing OWASP gracefully', () => {
    const group = createGroup({
      vulnerabilities: [{
        type: 'xss' as never,
        severity: 'medium',
        line: 5,
        message: 'XSS detected',
        description: 'Cross-site scripting',
        confidence: 70,
        cweId: 'CWE-79',
        filePath: 'app.js',
      }],
    });
    const body = generateBody(group);
    expect(body).toContain('CWE-79');
    expect(body).not.toContain('**OWASP**');
  });

  it('should include code snippet in fenced code block', () => {
    const body = generateBody(createGroup());
    expect(body).toContain('```');
    expect(body).toContain('SELECT * FROM users');
  });

  it('should include dismissal label instructions in footer', () => {
    const body = generateBody(createGroup());
    expect(body).toContain('rsolv:false-positive');
    expect(body).toContain('rsolv:wont-fix');
    expect(body).toContain('rsolv:accepted-risk');
    expect(body).toContain('rsolv:deferred');
  });
});
