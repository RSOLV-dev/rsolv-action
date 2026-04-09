/**
 * RFC-142: Per-instance issue creation tests.
 * TDD — RED phase: these tests define the contract for per-finding issue creation.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { IssueCreator } from '../issue-creator.js';
import type { ForgeAdapter, ForgeIssue } from '../../forge/forge-adapter.js';
import type { ScanConfig } from '../types.js';
import type { Vulnerability } from '../../security/types.js';
import { VulnerabilityType } from '../../security/types.js';

vi.mock('../../utils/logger.js', () => ({
  logger: {
    info: vi.fn(),
    error: vi.fn(),
    warn: vi.fn(),
    debug: vi.fn()
  }
}));

function createMockForgeAdapter(): {
  [K in keyof ForgeAdapter]: ReturnType<typeof vi.fn>;
} {
  return {
    listIssues: vi.fn().mockResolvedValue([]),
    createIssue: vi.fn().mockImplementation(
      (_owner: string, _repo: string, params: { title: string; body: string; labels: string[] }) =>
        Promise.resolve({
          number: Math.floor(Math.random() * 1000) + 1,
          title: params.title,
          url: `https://github.com/test/repo/issues/${Math.floor(Math.random() * 1000)}`,
          labels: params.labels,
          state: 'open'
        } as ForgeIssue)
    ),
    updateIssue: vi.fn().mockResolvedValue(undefined),
    addLabels: vi.fn().mockResolvedValue(undefined),
    removeLabel: vi.fn().mockResolvedValue(undefined),
    createComment: vi.fn().mockResolvedValue(undefined),
    createPullRequest: vi.fn(),
    listPullRequests: vi.fn(),
    getFileTree: vi.fn(),
    getFileContent: vi.fn(),
  };
}

function makeFinding(overrides: Partial<Vulnerability> = {}): Vulnerability {
  return {
    type: VulnerabilityType.XSS,
    severity: 'high',
    line: 42,
    message: 'Unescaped user input',
    description: 'User input rendered without escaping',
    confidence: 85,
    cweId: 'CWE-79',
    owaspCategory: 'A03:2021',
    filePath: 'src/templates/admin.ejs',
    snippet: 'innerHTML = userInput',
    ...overrides,
  };
}

const baseConfig: ScanConfig = {
  repository: { owner: 'test', name: 'repo', defaultBranch: 'main' },
  createIssues: true,
};

describe('IssueCreator - Per-Instance Issue Creation (RFC-142)', () => {
  let issueCreator: IssueCreator;
  let mockForge: ReturnType<typeof createMockForgeAdapter>;

  beforeEach(() => {
    vi.clearAllMocks();
    mockForge = createMockForgeAdapter();
    issueCreator = new IssueCreator(mockForge as unknown as ForgeAdapter);
  });

  describe('createIssuesFromFindings', () => {
    it('creates one issue per finding instance', async () => {
      const findings: Vulnerability[] = [
        makeFinding({ filePath: 'a.js', line: 10, cweId: 'CWE-79' }),
        makeFinding({ filePath: 'b.js', line: 20, cweId: 'CWE-79' }),
        makeFinding({ filePath: 'c.js', line: 30, cweId: 'CWE-89', type: VulnerabilityType.SQL_INJECTION }),
      ];

      const result = await issueCreator.createIssuesFromFindings(findings, baseConfig);

      expect(result.issues).toHaveLength(3);
      expect(mockForge.createIssue).toHaveBeenCalledTimes(3);
    });

    it('respects maxIssues cap on individual findings', async () => {
      const findings: Vulnerability[] = [
        makeFinding({ filePath: 'a.js', line: 10 }),
        makeFinding({ filePath: 'b.js', line: 20 }),
        makeFinding({ filePath: 'c.js', line: 30 }),
        makeFinding({ filePath: 'd.js', line: 40 }),
      ];

      const result = await issueCreator.createIssuesFromFindings(
        findings,
        { ...baseConfig, maxIssues: 2 }
      );

      expect(result.issues).toHaveLength(2);
      expect(mockForge.createIssue).toHaveBeenCalledTimes(2);
    });

    it('returns empty when createIssues is false', async () => {
      const findings = [makeFinding()];
      const result = await issueCreator.createIssuesFromFindings(
        findings,
        { ...baseConfig, createIssues: false }
      );

      expect(result.issues).toHaveLength(0);
      expect(mockForge.createIssue).not.toHaveBeenCalled();
    });

    it('continues creating issues even if one fails', async () => {
      let callCount = 0;
      mockForge.createIssue.mockImplementation(
        (_o: string, _r: string, params: { title: string; body: string; labels: string[] }) => {
          callCount++;
          if (callCount === 2) return Promise.reject(new Error('API Error'));
          return Promise.resolve({
            number: callCount,
            title: params.title,
            url: `https://github.com/test/repo/issues/${callCount}`,
            labels: params.labels,
            state: 'open'
          } as ForgeIssue);
        }
      );

      const findings = [
        makeFinding({ filePath: 'a.js', line: 10 }),
        makeFinding({ filePath: 'b.js', line: 20 }),
        makeFinding({ filePath: 'c.js', line: 30 }),
      ];

      const result = await issueCreator.createIssuesFromFindings(findings, baseConfig);
      expect(result.issues).toHaveLength(2); // 1st and 3rd succeed
    });

    it('populates filePath and line on CreatedIssue', async () => {
      const findings = [makeFinding({ filePath: 'src/app.js', line: 77, cweId: 'CWE-89' })];

      const result = await issueCreator.createIssuesFromFindings(findings, baseConfig);

      expect(result.issues[0].filePath).toBe('src/app.js');
      expect(result.issues[0].line).toBe(77);
      expect(result.issues[0].cweId).toBe('CWE-89');
    });

    it('skips vendor findings', async () => {
      const findings = [
        makeFinding({ filePath: 'src/app.js', isVendor: false }),
        makeFinding({ filePath: 'vendor/lib.js', isVendor: true }),
      ];

      const result = await issueCreator.createIssuesFromFindings(findings, baseConfig);

      expect(result.issues).toHaveLength(1);
      expect(result.issues[0].filePath).toBe('src/app.js');
    });
  });

  describe('issue title format', () => {
    it('uses [CWE-ID] Name in file:line format', async () => {
      const findings = [makeFinding({
        cweId: 'CWE-79',
        filePath: 'src/templates/admin.ejs',
        line: 42,
      })];

      await issueCreator.createIssuesFromFindings(findings, baseConfig);

      const createCall = mockForge.createIssue.mock.calls[0];
      const title = createCall[2].title;
      expect(title).toBe('[CWE-79] Cross-Site Scripting (XSS) in src/templates/admin.ejs:42');
    });

    it('falls back to pattern type name when CWE unknown', async () => {
      const findings = [makeFinding({
        cweId: undefined,
        type: VulnerabilityType.XSS,
        filePath: 'page.js',
        line: 10,
      })];

      await issueCreator.createIssuesFromFindings(findings, baseConfig);

      const title = mockForge.createIssue.mock.calls[0][2].title;
      expect(title).toMatch(/Cross-Site Scripting.*in page\.js:10/);
    });
  });

  describe('issue body format', () => {
    it('focuses on single finding instance', async () => {
      const findings = [makeFinding({
        cweId: 'CWE-79',
        filePath: 'src/templates/admin.ejs',
        line: 42,
        description: 'User input rendered without escaping',
        snippet: 'innerHTML = userInput',
      })];

      await issueCreator.createIssuesFromFindings(findings, baseConfig);

      const body = mockForge.createIssue.mock.calls[0][2].body;
      expect(body).toContain('src/templates/admin.ejs');
      expect(body).toContain('Line 42');
      expect(body).toContain('innerHTML = userInput');
      // Should NOT contain "Total Instances" or "Affected Files" count
      expect(body).not.toContain('Total Instances');
    });
  });

  describe('labels', () => {
    it('includes rsolv:cwe-XXX label for Phase 1.5 dedup', async () => {
      const findings = [makeFinding({ cweId: 'CWE-79' })];

      await issueCreator.createIssuesFromFindings(findings, baseConfig);

      const labels: string[] = mockForge.createIssue.mock.calls[0][2].labels;
      expect(labels).toContain('rsolv:cwe-CWE-79');
      expect(labels).toContain('rsolv:detected');
      expect(labels).toContain('security');
    });

    it('includes rsolv:vuln-TYPE label for backward compat', async () => {
      const findings = [makeFinding({ type: VulnerabilityType.SQL_INJECTION, cweId: 'CWE-89' })];

      await issueCreator.createIssuesFromFindings(findings, baseConfig);

      const labels: string[] = mockForge.createIssue.mock.calls[0][2].labels;
      expect(labels).toContain('rsolv:vuln-sql_injection');
    });
  });

  describe('Phase 1.5: Temporal dedup by (cwe, file)', () => {
    it('skips finding when open issue exists for same (cwe, file)', async () => {
      // Simulate existing open issue for CWE-79 in admin.ejs
      mockForge.listIssues.mockResolvedValue([{
        number: 42,
        title: '[CWE-79] Cross-Site Scripting (XSS) in src/templates/admin.ejs:42',
        url: 'https://github.com/test/repo/issues/42',
        labels: ['rsolv:detected', 'rsolv:cwe-CWE-79'],
        state: 'open'
      }]);

      const findings = [makeFinding({
        cweId: 'CWE-79',
        filePath: 'src/templates/admin.ejs',
        line: 42,
      })];

      const result = await issueCreator.createIssuesFromFindings(findings, baseConfig);

      expect(result.issues).toHaveLength(0);
      expect(result.skippedDuplicate).toBe(1); // temporal dedup
      expect(result.skippedDismissed).toBe(0); // not dismissed, just deduped
      expect(mockForge.createIssue).not.toHaveBeenCalled();
    });

    it('creates new issue when existing issue is for different file', async () => {
      // Existing issue is for OTHER file with same CWE
      mockForge.listIssues.mockResolvedValue([{
        number: 42,
        title: '[CWE-79] Cross-Site Scripting (XSS) in src/other.ejs:10',
        url: 'https://github.com/test/repo/issues/42',
        labels: ['rsolv:detected', 'rsolv:cwe-CWE-79'],
        state: 'open'
      }]);

      const findings = [makeFinding({
        cweId: 'CWE-79',
        filePath: 'src/templates/admin.ejs',
        line: 42,
      })];

      const result = await issueCreator.createIssuesFromFindings(findings, baseConfig);

      expect(result.issues).toHaveLength(1);
      expect(mockForge.createIssue).toHaveBeenCalledTimes(1);
    });

    it('matches by file path regardless of line number drift', async () => {
      // Existing issue at line 42, new finding at line 45 in same file
      mockForge.listIssues.mockResolvedValue([{
        number: 42,
        title: '[CWE-79] Cross-Site Scripting (XSS) in src/templates/admin.ejs:42',
        url: 'https://github.com/test/repo/issues/42',
        labels: ['rsolv:detected', 'rsolv:cwe-CWE-79'],
        state: 'open'
      }]);

      const findings = [makeFinding({
        cweId: 'CWE-79',
        filePath: 'src/templates/admin.ejs',
        line: 45, // line shifted
      })];

      const result = await issueCreator.createIssuesFromFindings(findings, baseConfig);

      // Should still be deduped — same CWE + same file
      expect(result.issues).toHaveLength(0);
      expect(mockForge.createIssue).not.toHaveBeenCalled();
    });

    it('creates issue for same CWE when no open issue has matching file', async () => {
      // No open issues at all
      mockForge.listIssues.mockResolvedValue([]);

      const findings = [makeFinding({ cweId: 'CWE-79', filePath: 'new-file.js' })];

      const result = await issueCreator.createIssuesFromFindings(findings, baseConfig);

      expect(result.issues).toHaveLength(1);
    });

    it('respects validated/false-positive/dismissed labels', async () => {
      mockForge.listIssues.mockResolvedValue([{
        number: 42,
        title: '[CWE-79] Cross-Site Scripting (XSS) in src/templates/admin.ejs:42',
        url: 'https://github.com/test/repo/issues/42',
        labels: ['rsolv:validated', 'rsolv:cwe-CWE-79'],
        state: 'open'
      }]);

      const findings = [makeFinding({
        cweId: 'CWE-79',
        filePath: 'src/templates/admin.ejs',
        line: 42,
      })];

      const result = await issueCreator.createIssuesFromFindings(findings, baseConfig);

      expect(result.issues).toHaveLength(0);
      expect(result.skippedValidated).toBe(1);
    });
  });
});
