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

    describe('when the open issue for the same (cwe, file) is rsolv:unconfirmed', () => {
      it('does not file a duplicate and does not count it as skipped-false-positive', async () => {
        mockForge.listIssues.mockResolvedValue([{
          number: 42,
          title: '[CWE-79] Cross-Site Scripting (XSS) in src/templates/admin.ejs:42',
          url: 'https://github.com/test/repo/issues/42',
          labels: ['rsolv:detected', 'rsolv:unconfirmed', 'rsolv:cwe-CWE-79'],
          state: 'open'
        }]);

        const result = await issueCreator.createIssuesFromFindings([makeFinding()], baseConfig);

        expect(mockForge.createIssue).not.toHaveBeenCalled();
        expect(result.skippedDuplicate).toBe(1);
        expect(result.skippedFalsePositive).toBe(0);
      });
    });

    describe('when a legacy issue lost rsolv:detected', () => {
      // v4.8.1 and earlier swapped rsolv:detected for rsolv:false-positive or
      // rsolv:validated, so a rsolv:detected query never returns these issues.
      // Like GitHub: a label query returns the open issues carrying that label.
      const listOnlyUnder = (_label: string, issue: ForgeIssue) =>
        mockForge.listIssues.mockImplementation(
          (_owner: string, _repo: string, labels: string) => Promise.resolve(issue.labels.includes(labels) ? [issue] : [])
        );

      it('still honours rsolv:false-positive as a skip and files no duplicate', async () => {
        listOnlyUnder('rsolv:false-positive', {
          number: 42,
          title: '[CWE-79] Cross-Site Scripting (XSS) in src/templates/admin.ejs:42',
          url: 'https://github.com/test/repo/issues/42',
          labels: ['rsolv:false-positive', 'rsolv:cwe-CWE-79'],
          state: 'open'
        });

        const result = await issueCreator.createIssuesFromFindings([makeFinding()], baseConfig);

        expect(mockForge.createIssue).not.toHaveBeenCalled();
        expect(result.skippedFalsePositive).toBe(1);
      });

      it('still honours rsolv:validated as a skip and files no duplicate', async () => {
        listOnlyUnder('rsolv:validated', {
          number: 43,
          title: '[CWE-79] Cross-Site Scripting (XSS) in src/templates/admin.ejs:42',
          url: 'https://github.com/test/repo/issues/43',
          labels: ['rsolv:validated', 'rsolv:cwe-CWE-79'],
          state: 'open'
        });

        const result = await issueCreator.createIssuesFromFindings([makeFinding()], baseConfig);

        expect(mockForge.createIssue).not.toHaveBeenCalled();
        expect(result.skippedValidated).toBe(1);
      });
    });

    describe('when a decided issue tracks a different instance of the same CWE in the same file', () => {
      const issueAt = (line: number, labels: string[]): ForgeIssue => ({
        number: 42,
        title: `[CWE-79] Cross-Site Scripting (XSS) in src/templates/admin.ejs:${line}`,
        url: 'https://github.com/test/repo/issues/42',
        labels: [...labels, 'rsolv:cwe-CWE-79'],
        state: 'open'
      });

      it.each([
        ['validated', ['rsolv:validated']],
        ['dismissed', ['rsolv:detected', 'rsolv:wont-fix']],
        ['false-positive', ['rsolv:false-positive']],
      ])('files the other instance when the %s issue is on a different line', async (_kind, labels) => {
        mockForge.listIssues.mockResolvedValue([issueAt(42, labels)]);

        const result = await issueCreator.createIssuesFromFindings([makeFinding({ line: 90 })], baseConfig);

        expect(mockForge.createIssue).toHaveBeenCalledTimes(1);
        expect(result.issues).toHaveLength(1);
      });

      it('still skips the same instance of a validated issue', async () => {
        mockForge.listIssues.mockResolvedValue([issueAt(42, ['rsolv:validated'])]);

        const result = await issueCreator.createIssuesFromFindings([makeFinding({ line: 42 })], baseConfig);

        expect(mockForge.createIssue).not.toHaveBeenCalled();
        expect(result.skippedValidated).toBe(1);
      });

      it('does not treat an issue for a different CWE at the same location as a match', async () => {
        mockForge.listIssues.mockResolvedValue([{
          number: 41,
          title: '[CWE-89] SQL Injection in src/templates/admin.ejs:42',
          url: 'https://github.com/test/repo/issues/41',
          labels: ['rsolv:detected', 'rsolv:cwe-CWE-89'],
          state: 'open'
        }]);

        await issueCreator.createIssuesFromFindings([makeFinding({ line: 42 })], baseConfig);

        expect(mockForge.createIssue).toHaveBeenCalledTimes(1);
      });

      it('still dedups line drift against an open unconfirmed issue', async () => {
        mockForge.listIssues.mockResolvedValue([issueAt(42, ['rsolv:detected', 'rsolv:unconfirmed'])]);

        const result = await issueCreator.createIssuesFromFindings([makeFinding({ line: 45 })], baseConfig);

        expect(mockForge.createIssue).not.toHaveBeenCalled();
        expect(result.skippedDuplicate).toBe(1);
      });
    });

    describe('when the forge refuses one label query', () => {
      it('still uses the answers for the other labels', async () => {
        const legacyFalsePositive: ForgeIssue = {
          number: 42,
          title: '[CWE-79] Cross-Site Scripting (XSS) in src/templates/admin.ejs:42',
          url: 'https://github.com/test/repo/issues/42',
          labels: ['rsolv:false-positive', 'rsolv:cwe-CWE-79'],
          state: 'open'
        };
        mockForge.listIssues.mockImplementation((_o: string, _r: string, label: string) =>
          label === 'rsolv:cwe-CWE-89'
            ? Promise.reject(new Error('label not allowed'))
            : Promise.resolve(legacyFalsePositive.labels.includes(label) ? [legacyFalsePositive] : []));

        const result = await issueCreator.createIssuesFromFindings(
          [makeFinding({ cweId: 'CWE-89', filePath: 'src/db.js' }), makeFinding()],
          baseConfig
        );

        expect(result.skippedFalsePositive).toBe(1);
        expect(mockForge.createIssue).toHaveBeenCalledTimes(1);
        expect(mockForge.createIssue.mock.calls[0][2].title).toContain('src/db.js');
      });
    });

    describe('when one open issue could stand for several findings', () => {
      const unconfirmedAt = (number: number, line: number): ForgeIssue => ({
        number,
        title: `[CWE-79] Cross-Site Scripting (XSS) in src/templates/admin.ejs:${line}`,
        url: `https://github.com/test/repo/issues/${number}`,
        labels: ['rsolv:detected', 'rsolv:unconfirmed', 'rsolv:cwe-CWE-79'],
        state: 'open'
      });

      it('lets the exact instance claim the issue and files the other finding', async () => {
        mockForge.listIssues.mockResolvedValue([unconfirmedAt(1, 10)]);

        const result = await issueCreator.createIssuesFromFindings(
          [makeFinding({ line: 90 }), makeFinding({ line: 10 })],
          baseConfig
        );

        expect(mockForge.createIssue).toHaveBeenCalledTimes(1);
        expect(mockForge.createIssue.mock.calls[0][2].title).toContain('admin.ejs:90');
        expect(result.skippedDuplicate).toBe(1);
      });

      it('still dedups a single drifted finding', async () => {
        mockForge.listIssues.mockResolvedValue([unconfirmedAt(1, 10)]);

        const result = await issueCreator.createIssuesFromFindings([makeFinding({ line: 12 })], baseConfig);

        expect(mockForge.createIssue).not.toHaveBeenCalled();
        expect(result.skippedDuplicate).toBe(1);
      });

      it('lets each issue absorb at most one drifted finding', async () => {
        mockForge.listIssues.mockResolvedValue([unconfirmedAt(1, 10)]);

        await issueCreator.createIssuesFromFindings([makeFinding({ line: 12 }), makeFinding({ line: 14 })], baseConfig);

        expect(mockForge.createIssue).toHaveBeenCalledTimes(1);
        expect(mockForge.createIssue.mock.calls[0][2].title).toContain('admin.ejs:14');
      });

      it('gives a drifted issue to the nearest finding', async () => {
        mockForge.listIssues.mockResolvedValue([unconfirmedAt(1, 10)]);

        await issueCreator.createIssuesFromFindings([makeFinding({ line: 40 }), makeFinding({ line: 12 })], baseConfig);

        expect(mockForge.createIssue).toHaveBeenCalledTimes(1);
        expect(mockForge.createIssue.mock.calls[0][2].title).toContain('admin.ejs:40');
      });

      it.each([
        ['has no status label', [] as string[]],
        ['is mitigated', ['rsolv:mitigated']],
      ])('does not let an open issue that %s absorb a drifted finding', async (_kind, status) => {
        mockForge.listIssues.mockResolvedValue([{
          ...unconfirmedAt(1, 10),
          labels: [...status, 'rsolv:cwe-CWE-79'],
        }]);

        await issueCreator.createIssuesFromFindings([makeFinding({ line: 90 })], baseConfig);

        expect(mockForge.createIssue).toHaveBeenCalledTimes(1);
      });

      it.each([
        ['rsolv:detected'],
        ['rsolv:unconfirmed'],
      ])('lets an open issue carrying only %s absorb a drifted finding', async (status) => {
        mockForge.listIssues.mockResolvedValue([{ ...unconfirmedAt(1, 10), labels: [status, 'rsolv:cwe-CWE-79'] }]);

        const result = await issueCreator.createIssuesFromFindings([makeFinding({ line: 12 })], baseConfig);

        expect(mockForge.createIssue).not.toHaveBeenCalled();
        expect(result.skippedDuplicate).toBe(1);
      });

      it('lets one issue claim only one of two findings at the same coordinates', async () => {
        mockForge.listIssues.mockResolvedValue([unconfirmedAt(1, 10)]);

        const result = await issueCreator.createIssuesFromFindings(
          [makeFinding({ line: 10 }), makeFinding({ line: 10 })],
          baseConfig
        );

        expect(result.skippedDuplicate).toBe(1);
        expect(mockForge.createIssue).toHaveBeenCalledTimes(1);
      });

      it('matches two findings at the same coordinates to two issues there', async () => {
        mockForge.listIssues.mockResolvedValue([unconfirmedAt(1, 10), unconfirmedAt(2, 10)]);

        const result = await issueCreator.createIssuesFromFindings(
          [makeFinding({ line: 10 }), makeFinding({ line: 10 })],
          baseConfig
        );

        expect(result.skippedDuplicate).toBe(2);
        expect(mockForge.createIssue).not.toHaveBeenCalled();
      });

      it('dedups two shifted findings against two issues', async () => {
        mockForge.listIssues.mockResolvedValue([unconfirmedAt(1, 10), unconfirmedAt(2, 50)]);

        const result = await issueCreator.createIssuesFromFindings(
          [makeFinding({ line: 53 }), makeFinding({ line: 12 })],
          baseConfig
        );

        expect(mockForge.createIssue).not.toHaveBeenCalled();
        expect(result.skippedDuplicate).toBe(2);
      });
    });

    describe('when listing open issues', () => {
      it('queries each finding CWE label, which every matchable issue carries', async () => {
        await issueCreator.createIssuesFromFindings(
          [makeFinding(), makeFinding({ cweId: 'CWE-89', filePath: 'src/db.js' }), makeFinding({ line: 7 })],
          baseConfig
        );

        const labels = mockForge.listIssues.mock.calls.map(call => call[2]);
        expect(labels).toEqual(expect.arrayContaining(['rsolv:cwe-CWE-79', 'rsolv:cwe-CWE-89']));
      });
    });

    describe('when max_issues is set and some findings already have open issues', () => {
      it('spends the cap on new findings, not on already-tracked ones', async () => {
        const tracked = (n: number, file: string): ForgeIssue => ({
          number: n,
          title: `[CWE-79] Cross-Site Scripting (XSS) in ${file}:1`,
          url: `https://github.com/test/repo/issues/${n}`,
          labels: ['rsolv:detected', 'rsolv:cwe-CWE-79'],
          state: 'open'
        });
        mockForge.listIssues.mockResolvedValue([tracked(1, 'a.ejs'), tracked(2, 'b.ejs')]);

        const findings = [
          makeFinding({ filePath: 'a.ejs' }),
          makeFinding({ filePath: 'b.ejs' }),
          makeFinding({ filePath: 'c.ejs' }),
        ];

        const result = await issueCreator.createIssuesFromFindings(findings, { ...baseConfig, maxIssues: 2 });

        expect(mockForge.createIssue).toHaveBeenCalledTimes(1);
        expect(mockForge.createIssue.mock.calls[0][2].title).toContain(' in c.ejs:');
        expect(result.skippedDuplicate).toBe(2);
      });

      it('still caps the number of new issues', async () => {
        const findings = ['a.ejs', 'b.ejs', 'c.ejs'].map(filePath => makeFinding({ filePath }));

        await issueCreator.createIssuesFromFindings(findings, { ...baseConfig, maxIssues: 2 });

        expect(mockForge.createIssue).toHaveBeenCalledTimes(2);
      });
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
