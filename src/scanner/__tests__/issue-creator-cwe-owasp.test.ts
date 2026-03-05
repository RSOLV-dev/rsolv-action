import { describe, it, expect, vi, beforeEach } from 'vitest';
import { IssueCreator } from '../issue-creator.js';
import type { ForgeAdapter } from '../../forge/forge-adapter.js';
import type { VulnerabilityGroup, ScanConfig } from '../types.js';

vi.mock('../../utils/logger.js', () => ({
  logger: {
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    debug: vi.fn(),
  }
}));

describe('CWE-Specific Issue Titles', () => {
  let issueCreator: IssueCreator;
  const config: ScanConfig = {
    repository: { owner: 'test', name: 'repo', defaultBranch: 'main' },
    createIssues: true,
    issueLabel: 'rsolv:detected',
  };

  beforeEach(() => {
    const mockForgeAdapter = {
      listIssues: vi.fn().mockResolvedValue([]),
      createIssue: vi.fn().mockResolvedValue({ number: 1, title: 'test', url: 'https://github.com/test/repo/issues/1', labels: [], state: 'open' }),
      updateIssue: vi.fn().mockResolvedValue(undefined),
      addLabels: vi.fn().mockResolvedValue(undefined),
      createComment: vi.fn().mockResolvedValue(undefined),
      removeLabel: vi.fn().mockResolvedValue(undefined),
      createPullRequest: vi.fn().mockResolvedValue({ number: 1, title: 'test', url: '', head: '', base: '' }),
      listPullRequests: vi.fn().mockResolvedValue([]),
      getFileTree: vi.fn().mockResolvedValue([]),
      getFileContent: vi.fn().mockResolvedValue(''),
    } as unknown as ForgeAdapter;
    issueCreator = new IssueCreator(mockForgeAdapter);
  });

  function createGroup(overrides: Partial<VulnerabilityGroup> = {}): VulnerabilityGroup {
    return {
      type: 'weak_cryptography',
      severity: 'high',
      count: 1,
      files: ['auth.py'],
      vulnerabilities: [{
        type: 'weak_cryptography' as never,
        severity: 'high',
        line: 10,
        message: 'Weak crypto detected',
        description: 'MD5 used for password hashing',
        confidence: 90,
        cweId: 'CWE-256',
        owaspCategory: 'A02:2021 Cryptographic Failures',
        filePath: 'auth.py',
      }],
      ...overrides,
    };
  }

  function generateTitle(group: VulnerabilityGroup): string {
    return (issueCreator as Record<string, unknown>)['generateIssueTitle'].call(issueCreator, group) as string;
  }

  function generateBody(group: VulnerabilityGroup): string {
    return (issueCreator as Record<string, unknown>)['generateIssueBody'].call(issueCreator, group, config) as string;
  }

  it('CWE-256 title says "Weak Password Storage" not "Weak Cryptography"', () => {
    const title = generateTitle(createGroup());
    expect(title).toContain('Weak Password Storage');
    expect(title).not.toContain('Weak Cryptography');
  });

  it('CWE-327 title says "Weak Cryptographic Algorithm"', () => {
    const group = createGroup({
      vulnerabilities: [{
        type: 'weak_cryptography' as never,
        severity: 'high',
        line: 10,
        message: 'Weak crypto',
        description: 'Using DES',
        confidence: 90,
        cweId: 'CWE-327',
        filePath: 'crypto.py',
      }],
    });
    const title = generateTitle(group);
    expect(title).toContain('Weak Cryptographic Algorithm');
  });

  it('falls back to pattern type name when no CWE ID', () => {
    const group = createGroup({
      vulnerabilities: [{
        type: 'weak_cryptography' as never,
        severity: 'high',
        line: 10,
        message: 'Weak crypto',
        description: 'MD5 usage',
        confidence: 90,
        filePath: 'crypto.py',
        // no cweId
      }],
    });
    const title = generateTitle(group);
    expect(title).toContain('Weak Cryptography');
  });

  it('falls back for unknown CWE IDs', () => {
    const group = createGroup({
      vulnerabilities: [{
        type: 'weak_cryptography' as never,
        severity: 'high',
        line: 10,
        message: 'Weak crypto',
        description: 'Unknown CWE',
        confidence: 90,
        cweId: 'CWE-99999',
        filePath: 'crypto.py',
      }],
    });
    const title = generateTitle(group);
    // Should fall back to pattern type name
    expect(title).toContain('Weak Cryptography');
  });

  it('body Type field also uses CWE name', () => {
    const body = generateBody(createGroup());
    expect(body).toContain('Weak Password Storage');
    expect(body).not.toMatch(/\*\*Type\*\*: Weak Cryptography/);
  });
});

describe('OWASP Clickable Links', () => {
  let issueCreator: IssueCreator;
  const config: ScanConfig = {
    repository: { owner: 'test', name: 'repo', defaultBranch: 'main' },
    createIssues: true,
    issueLabel: 'rsolv:detected',
  };

  beforeEach(() => {
    const mockForgeAdapter = {
      listIssues: vi.fn().mockResolvedValue([]),
      createIssue: vi.fn().mockResolvedValue({ number: 1, title: 'test', url: 'https://github.com/test/repo/issues/1', labels: [], state: 'open' }),
      updateIssue: vi.fn().mockResolvedValue(undefined),
      addLabels: vi.fn().mockResolvedValue(undefined),
      createComment: vi.fn().mockResolvedValue(undefined),
      removeLabel: vi.fn().mockResolvedValue(undefined),
      createPullRequest: vi.fn().mockResolvedValue({ number: 1, title: 'test', url: '', head: '', base: '' }),
      listPullRequests: vi.fn().mockResolvedValue([]),
      getFileTree: vi.fn().mockResolvedValue([]),
      getFileContent: vi.fn().mockResolvedValue(''),
    } as unknown as ForgeAdapter;
    issueCreator = new IssueCreator(mockForgeAdapter);
  });

  function createGroup(owaspCategory: string): VulnerabilityGroup {
    return {
      type: 'sql_injection',
      severity: 'high',
      count: 1,
      files: ['app.js'],
      vulnerabilities: [{
        type: 'sql_injection' as never,
        severity: 'high',
        line: 10,
        message: 'SQL Injection',
        description: 'User input in query',
        confidence: 85,
        cweId: 'CWE-89',
        owaspCategory,
        filePath: 'app.js',
      }],
    };
  }

  function generateBody(group: VulnerabilityGroup): string {
    return (issueCreator as Record<string, unknown>)['generateIssueBody'].call(issueCreator, group, config) as string;
  }

  it('OWASP A03:2021 renders as clickable link', () => {
    const body = generateBody(createGroup('A03:2021 Injection'));
    expect(body).toContain('[A03:2021 - Injection](https://owasp.org/Top10/A03_2021-Injection/)');
  });

  it('OWASP A02:2021 renders as clickable link', () => {
    const body = generateBody(createGroup('A02:2021 Cryptographic Failures'));
    expect(body).toContain('[A02:2021 - Cryptographic Failures](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/)');
  });

  it('handles trailing text in category ("A03:2021 Injection")', () => {
    const body = generateBody(createGroup('A03:2021 Injection'));
    expect(body).toContain('owasp.org/Top10/');
  });

  it('falls back to plain text for unknown OWASP codes', () => {
    const body = generateBody(createGroup('A99:2021 Unknown'));
    // Should contain the text but NOT as a link
    expect(body).toContain('A99:2021 Unknown');
    expect(body).not.toContain('owasp.org');
  });
});
