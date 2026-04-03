import { describe, it, expect, vi, beforeEach } from 'vitest';
import { IssueCreator } from '../issue-creator.js';
import type { ForgeAdapter, ForgeIssue } from '../../forge/forge-adapter.js';
import type { VulnerabilityGroup, ScanConfig } from '../types.js';

vi.mock('../../utils/logger.js');

function createMockForgeAdapter(): {
  [K in keyof ForgeAdapter]: ReturnType<typeof vi.fn>;
} {
  return {
    listIssues: vi.fn(),
    createIssue: vi.fn(),
    updateIssue: vi.fn(),
    addLabels: vi.fn().mockResolvedValue(undefined),
    removeLabel: vi.fn().mockResolvedValue(undefined),
    createComment: vi.fn().mockResolvedValue(undefined),
    createPullRequest: vi.fn(),
    listPullRequests: vi.fn(),
    getFileTree: vi.fn(),
    getFileContent: vi.fn(),
  };
}

describe('IssueCreator - Duplicate Detection', () => {
  let issueCreator: IssueCreator;
  let mockForgeAdapter: ReturnType<typeof createMockForgeAdapter>;

  beforeEach(() => {
    mockForgeAdapter = createMockForgeAdapter();
    issueCreator = new IssueCreator(mockForgeAdapter as unknown as ForgeAdapter);
  });

  describe('findExistingIssue', () => {
    it('should find existing issue with matching vulnerability type label', async () => {
      const existingForgeIssue: ForgeIssue = {
        number: 123,
        title: '🔒 Cross-Site Scripting (XSS) vulnerabilities found in 2 files',
        url: 'https://github.com/test/repo/issues/123',
        labels: ['rsolv:detected', 'rsolv:vuln-xss', 'security'],
        state: 'open'
      };

      mockForgeAdapter.listIssues.mockResolvedValue([existingForgeIssue]);

      const group: VulnerabilityGroup = {
        type: 'xss',
        severity: 'high',
        count: 3,
        files: ['file1.js', 'file2.js', 'file3.js'],
        vulnerabilities: []
      };

      const config: ScanConfig = {
        repository: { owner: 'test', name: 'repo' },
        branch: 'main',
        createIssues: true
      };

      // @ts-ignore - accessing private method for testing
      const result = await issueCreator.findExistingIssue(group, config);

      expect(result).toBeDefined();
      expect(result.number).toBe(123);
      expect(mockForgeAdapter.listIssues).toHaveBeenCalledWith(
        'test',
        'repo',
        'rsolv:vuln-xss',
        'open'
      );
    });

    it('should return null when no existing issue found', async () => {
      mockForgeAdapter.listIssues.mockResolvedValue([]);

      const group: VulnerabilityGroup = {
        type: 'sql-injection',
        severity: 'critical',
        count: 1,
        files: ['db.js'],
        vulnerabilities: []
      };

      const config: ScanConfig = {
        repository: { owner: 'test', name: 'repo' },
        branch: 'main',
        createIssues: true
      };

      // @ts-ignore - accessing private method for testing
      const result = await issueCreator.findExistingIssue(group, config);

      expect(result).toBeNull();
    });
  });

  describe('updateExistingIssue', () => {
    it('should update existing issue with new scan results', async () => {
      const existingIssue = {
        number: 123,
        title: '🔒 Cross-Site Scripting (XSS) vulnerabilities found in 2 files',
        body: 'Old body content',
        labels: [{ name: 'rsolv:detected' }, { name: 'rsolv:vuln-xss' }],
        html_url: 'https://github.com/test/repo/issues/123'
      };

      const group: VulnerabilityGroup = {
        type: 'xss',
        severity: 'high',
        count: 3,
        files: ['file1.js', 'file2.js', 'file3.js'],
        vulnerabilities: [{
          type: 'xss',
          severity: 'high',
          filePath: 'file3.js',
          line: 42,
          description: 'New XSS vulnerability',
          snippet: 'innerHTML = userInput'
        }]
      };

      const config: ScanConfig = {
        repository: { owner: 'test', name: 'repo' },
        branch: 'main',
        createIssues: true
      };

      mockForgeAdapter.updateIssue.mockResolvedValue(undefined);
      mockForgeAdapter.createComment.mockResolvedValue(undefined);

      // @ts-ignore - accessing private method for testing
      const result = await issueCreator.updateExistingIssue(existingIssue, group, config);

      expect(result).toBeDefined();
      expect(mockForgeAdapter.updateIssue).toHaveBeenCalledWith(
        'test',
        'repo',
        123,
        {
          title: '🔒 Cross-Site Scripting (XSS) vulnerabilities found in 3 files',
          body: expect.stringContaining('**Total Instances**: 3')
        }
      );

      expect(mockForgeAdapter.createComment).toHaveBeenCalledWith(
        'test',
        'repo',
        123,
        expect.stringContaining('Scan Update')
      );

      // Should NOT call addLabels since rsolv:detected is already present
      expect(mockForgeAdapter.addLabels).not.toHaveBeenCalled();
    });

    it('should add rsolv:detected label when missing from reused issue', async () => {
      // Issue from an earlier run that lacks the rsolv:detected label
      const existingIssue = {
        number: 1107,
        title: '🔒 SQL Injection vulnerabilities found in 2 files',
        body: 'Old body content',
        labels: [
          { name: 'security' },
          { name: 'automated-scan' },
          { name: 'critical' },
          { name: 'rsolv:vuln-sql_injection' }
        ],
        html_url: 'https://github.com/test/repo/issues/1107'
      };

      const group: VulnerabilityGroup = {
        type: 'sql_injection',
        severity: 'critical',
        count: 2,
        files: ['profile-dao.js', 'user-dao.js'],
        vulnerabilities: [{
          type: 'sql_injection',
          severity: 'critical',
          filePath: 'profile-dao.js',
          line: 28,
          description: 'SQL injection via string concatenation',
          snippet: "var q = \"SELECT * FROM users WHERE id = '\" + userId + \"'\""
        }]
      };

      const config: ScanConfig = {
        repository: { owner: 'test', name: 'repo' },
        branch: 'main',
        createIssues: true
      };

      mockForgeAdapter.updateIssue.mockResolvedValue(undefined);
      mockForgeAdapter.createComment.mockResolvedValue(undefined);

      // @ts-ignore - accessing private method for testing
      await issueCreator.updateExistingIssue(existingIssue, group, config);

      // Should call addLabels to ensure rsolv:detected is present for phase handoff
      expect(mockForgeAdapter.addLabels).toHaveBeenCalledWith(
        'test',
        'repo',
        1107,
        ['rsolv:detected']
      );
    });
  });

  describe('createIssuesFromGroups with duplicate detection', () => {
    it('should update existing issue instead of creating new one', async () => {
      const existingForgeIssue: ForgeIssue = {
        number: 123,
        title: '🔒 Cross-Site Scripting (XSS) vulnerabilities found in 1 file',
        url: 'https://github.com/test/repo/issues/123',
        labels: ['rsolv:detected', 'rsolv:vuln-xss'],
        state: 'open'
      };

      mockForgeAdapter.listIssues.mockResolvedValue([existingForgeIssue]);
      mockForgeAdapter.updateIssue.mockResolvedValue(undefined);
      mockForgeAdapter.createComment.mockResolvedValue(undefined);

      const group: VulnerabilityGroup = {
        type: 'xss',
        severity: 'high',
        count: 2,
        files: ['file1.js', 'file2.js'],
        vulnerabilities: []
      };

      const config: ScanConfig = {
        repository: { owner: 'test', name: 'repo', defaultBranch: 'main' },
        createIssues: true,
        issueLabel: 'rsolv:detected',
        batchSimilar: true
      };

      const result = await issueCreator.createIssuesFromGroups([group], config);

      expect(result.issues).toHaveLength(1);
      expect(result.issues[0].number).toBe(123);
      expect(result.skippedValidated).toBe(0);
      expect(result.skippedFalsePositive).toBe(0);
      expect(mockForgeAdapter.createIssue).not.toHaveBeenCalled();
      expect(mockForgeAdapter.updateIssue).toHaveBeenCalled();
    });

    it('should create new issue when no duplicate exists', async () => {
      mockForgeAdapter.listIssues.mockResolvedValue([]);
      mockForgeAdapter.createIssue.mockResolvedValue({
        number: 456,
        title: '🔒 SQL Injection vulnerabilities found in 1 file',
        url: 'https://github.com/test/repo/issues/456',
        labels: ['rsolv:detected', 'rsolv:vuln-sql-injection', 'security', 'critical', 'automated-scan'],
        state: 'open'
      } as ForgeIssue);

      const group: VulnerabilityGroup = {
        type: 'sql-injection',
        severity: 'critical',
        count: 1,
        files: ['db.js'],
        vulnerabilities: []
      };

      const config: ScanConfig = {
        repository: { owner: 'test', name: 'repo', defaultBranch: 'main' },
        createIssues: true,
        issueLabel: 'rsolv:detected',
        batchSimilar: true
      };

      const result = await issueCreator.createIssuesFromGroups([group], config);

      expect(result.issues).toHaveLength(1);
      expect(result.issues[0].number).toBe(456);
      expect(result.skippedValidated).toBe(0);
      expect(result.skippedFalsePositive).toBe(0);
      expect(mockForgeAdapter.createIssue).toHaveBeenCalled();
      expect(mockForgeAdapter.updateIssue).not.toHaveBeenCalled();
    });
  });

  describe('RFC-081: Issue Lifecycle State Management', () => {
    it('should skip issues with rsolv:validated label', async () => {
      const validatedIssue: ForgeIssue = {
        number: 100,
        title: '🔒 SQL Injection vulnerabilities found in 1 file',
        url: 'https://github.com/test/repo/issues/100',
        labels: ['rsolv:validated', 'rsolv:vuln-sql-injection', 'security'],
        state: 'open'
      };

      mockForgeAdapter.listIssues.mockResolvedValue([validatedIssue]);

      const group: VulnerabilityGroup = {
        type: 'sql-injection',
        severity: 'critical',
        count: 1,
        files: ['db.js'],
        vulnerabilities: []
      };

      const config: ScanConfig = {
        repository: { owner: 'test', name: 'repo', defaultBranch: 'main' },
        createIssues: true,
        issueLabel: 'rsolv:detected',
        batchSimilar: true
      };

      const result = await issueCreator.createIssuesFromGroups([group], config);

      expect(result.issues).toHaveLength(0);
      expect(result.skippedValidated).toBe(1);
      expect(result.skippedFalsePositive).toBe(0);
      expect(mockForgeAdapter.createIssue).not.toHaveBeenCalled();
      expect(mockForgeAdapter.updateIssue).not.toHaveBeenCalled();
    });

    it('should skip issues with rsolv:false-positive label', async () => {
      const falsePositiveIssue: ForgeIssue = {
        number: 101,
        title: '🔒 XSS vulnerabilities found in 2 files',
        url: 'https://github.com/test/repo/issues/101',
        labels: ['rsolv:false-positive', 'rsolv:vuln-xss', 'security'],
        state: 'open'
      };

      mockForgeAdapter.listIssues.mockResolvedValue([falsePositiveIssue]);

      const group: VulnerabilityGroup = {
        type: 'xss',
        severity: 'high',
        count: 2,
        files: ['page1.js', 'page2.js'],
        vulnerabilities: []
      };

      const config: ScanConfig = {
        repository: { owner: 'test', name: 'repo', defaultBranch: 'main' },
        createIssues: true,
        issueLabel: 'rsolv:detected',
        batchSimilar: true
      };

      const result = await issueCreator.createIssuesFromGroups([group], config);

      expect(result.issues).toHaveLength(0);
      expect(result.skippedValidated).toBe(0);
      expect(result.skippedFalsePositive).toBe(1);
      expect(mockForgeAdapter.createIssue).not.toHaveBeenCalled();
      expect(mockForgeAdapter.updateIssue).not.toHaveBeenCalled();
    });

    it('should update issues with only rsolv:detected label', async () => {
      const detectedIssue: ForgeIssue = {
        number: 102,
        title: '🔒 Command Injection vulnerabilities found in 1 file',
        url: 'https://github.com/test/repo/issues/102',
        labels: ['rsolv:detected', 'rsolv:vuln-command-injection', 'security'],
        state: 'open'
      };

      mockForgeAdapter.listIssues.mockResolvedValue([detectedIssue]);
      mockForgeAdapter.updateIssue.mockResolvedValue(undefined);
      mockForgeAdapter.createComment.mockResolvedValue(undefined);

      const group: VulnerabilityGroup = {
        type: 'command-injection',
        severity: 'critical',
        count: 2,
        files: ['exec.js', 'shell.js'],
        vulnerabilities: []
      };

      const config: ScanConfig = {
        repository: { owner: 'test', name: 'repo', defaultBranch: 'main' },
        createIssues: true,
        issueLabel: 'rsolv:detected',
        batchSimilar: true
      };

      const result = await issueCreator.createIssuesFromGroups([group], config);

      expect(result.issues).toHaveLength(1);
      expect(result.issues[0].number).toBe(102);
      expect(result.skippedValidated).toBe(0);
      expect(result.skippedFalsePositive).toBe(0);
      expect(mockForgeAdapter.createIssue).not.toHaveBeenCalled();
      expect(mockForgeAdapter.updateIssue).toHaveBeenCalled();
    });

    it('should handle mixed state transitions correctly', async () => {
      // listIssues is called once per group with the vuln-type label
      mockForgeAdapter.listIssues.mockImplementation(
        (_owner: string, _repo: string, labels: string, _state: string) => {
          if (labels === 'rsolv:vuln-sql-injection') {
            return Promise.resolve([{
              number: 200,
              title: '🔒 SQL Injection',
              url: 'https://github.com/test/repo/issues/200',
              labels: ['rsolv:validated', 'rsolv:vuln-sql-injection'],
              state: 'open'
            }] as ForgeIssue[]);
          }
          if (labels === 'rsolv:vuln-xss') {
            return Promise.resolve([{
              number: 201,
              title: '🔒 XSS',
              url: 'https://github.com/test/repo/issues/201',
              labels: ['rsolv:false-positive', 'rsolv:vuln-xss'],
              state: 'open'
            }] as ForgeIssue[]);
          }
          if (labels === 'rsolv:vuln-command-injection') {
            return Promise.resolve([{
              number: 202,
              title: '🔒 Command Injection',
              url: 'https://github.com/test/repo/issues/202',
              labels: ['rsolv:detected', 'rsolv:vuln-command-injection'],
              state: 'open'
            }] as ForgeIssue[]);
          }
          if (labels === 'rsolv:vuln-path-traversal') {
            return Promise.resolve([] as ForgeIssue[]);
          }
          return Promise.resolve([] as ForgeIssue[]);
        }
      );

      mockForgeAdapter.updateIssue.mockResolvedValue(undefined);
      mockForgeAdapter.createComment.mockResolvedValue(undefined);
      mockForgeAdapter.createIssue.mockResolvedValue({
        number: 203,
        title: '🔒 Path Traversal vulnerabilities found in 1 file',
        url: 'https://github.com/test/repo/issues/203',
        labels: ['rsolv:detected', 'rsolv:vuln-path-traversal', 'security', 'high', 'automated-scan'],
        state: 'open'
      } as ForgeIssue);

      const groups: VulnerabilityGroup[] = [
        {
          type: 'sql-injection',
          severity: 'critical',
          count: 1,
          files: ['db.js'],
          vulnerabilities: []
        },
        {
          type: 'xss',
          severity: 'high',
          count: 1,
          files: ['page.js'],
          vulnerabilities: []
        },
        {
          type: 'command-injection',
          severity: 'critical',
          count: 1,
          files: ['exec.js'],
          vulnerabilities: []
        },
        {
          type: 'path-traversal',
          severity: 'high',
          count: 1,
          files: ['file.js'],
          vulnerabilities: []
        }
      ];

      const config: ScanConfig = {
        repository: { owner: 'test', name: 'repo', defaultBranch: 'main' },
        createIssues: true,
        issueLabel: 'rsolv:detected',
        batchSimilar: true
      };

      const result = await issueCreator.createIssuesFromGroups(groups, config);

      expect(result.issues).toHaveLength(2);
      expect(result.skippedValidated).toBe(1);
      expect(result.skippedFalsePositive).toBe(1);
      expect(mockForgeAdapter.updateIssue).toHaveBeenCalledTimes(1);
      expect(mockForgeAdapter.createIssue).toHaveBeenCalledTimes(1);
    });
  });
});
