import { describe, it, expect, vi, beforeEach } from 'vitest';
import { IssueCreator } from '../issue-creator.js';
import { getGitHubClient } from '../../github/api.js';
import type { VulnerabilityGroup, ScanConfig } from '../types.js';

vi.mock('../../github/api.js');
vi.mock('../../utils/logger.js');

describe('IssueCreator - Duplicate Detection', () => {
  let issueCreator: IssueCreator;
  let mockGitHub: any;

  beforeEach(() => {
    mockGitHub = {
      issues: {
        create: vi.fn(),
        update: vi.fn(),
        createComment: vi.fn(),
        listForRepo: vi.fn(),
        addLabels: vi.fn().mockResolvedValue({ data: [] })
      }
    };

    vi.mocked(getGitHubClient).mockReturnValue(mockGitHub);
    issueCreator = new IssueCreator();
  });

  describe('findExistingIssue', () => {
    it('should find existing issue with matching vulnerability type label', async () => {
      const existingIssue = {
        number: 123,
        title: '🔒 Cross-Site Scripting (XSS) vulnerabilities found in 2 files',
        labels: [
          { name: 'rsolv:detected' },
          { name: 'rsolv:vuln-xss' },
          { name: 'security' }
        ],
        state: 'open'
      };

      mockGitHub.issues.listForRepo.mockResolvedValue({
        data: [existingIssue]
      });

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
      expect(mockGitHub.issues.listForRepo).toHaveBeenCalledWith({
        owner: 'test',
        repo: 'repo',
        labels: 'rsolv:vuln-xss',
        state: 'open'
      });
    });

    it('should return null when no existing issue found', async () => {
      mockGitHub.issues.listForRepo.mockResolvedValue({
        data: []
      });

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
        labels: [{ name: 'rsolv:detected' }, { name: 'rsolv:vuln-xss' }]
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

      mockGitHub.issues.update.mockResolvedValue({ data: { ...existingIssue } });
      mockGitHub.issues.createComment.mockResolvedValue({ data: {} });

      // @ts-ignore - accessing private method for testing
      const result = await issueCreator.updateExistingIssue(existingIssue, group, config);

      expect(result).toBeDefined();
      expect(mockGitHub.issues.update).toHaveBeenCalledWith({
        owner: 'test',
        repo: 'repo',
        issue_number: 123,
        title: '🔒 Cross-Site Scripting (XSS) vulnerabilities found in 3 files',
        body: expect.stringContaining('**Total Instances**: 3')
      });

      expect(mockGitHub.issues.createComment).toHaveBeenCalledWith({
        owner: 'test',
        repo: 'repo',
        issue_number: 123,
        body: expect.stringContaining('📊 Scan Update')
      });

      // Should NOT call addLabels since rsolv:detected is already present
      expect(mockGitHub.issues.addLabels).not.toHaveBeenCalled();
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

      mockGitHub.issues.update.mockResolvedValue({ data: { ...existingIssue } });
      mockGitHub.issues.createComment.mockResolvedValue({ data: {} });

      // @ts-ignore - accessing private method for testing
      await issueCreator.updateExistingIssue(existingIssue, group, config);

      // Should call addLabels to ensure rsolv:detected is present for phase handoff
      expect(mockGitHub.issues.addLabels).toHaveBeenCalledWith({
        owner: 'test',
        repo: 'repo',
        issue_number: 1107,
        labels: ['rsolv:detected']
      });
    });
  });

  describe('createIssuesFromGroups with duplicate detection', () => {
    it('should update existing issue instead of creating new one', async () => {
      const existingIssue = {
        number: 123,
        title: '🔒 Cross-Site Scripting (XSS) vulnerabilities found in 1 file',
        labels: [
          { name: 'rsolv:detected' },
          { name: 'rsolv:vuln-xss' }
        ],
        html_url: 'https://github.com/test/repo/issues/123'
      };

      mockGitHub.issues.listForRepo.mockResolvedValue({
        data: [existingIssue]
      });
      mockGitHub.issues.update.mockResolvedValue({
        data: { ...existingIssue, title: '🔒 Cross-Site Scripting (XSS) vulnerabilities found in 2 files' }
      });
      mockGitHub.issues.createComment.mockResolvedValue({ data: {} });

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
      expect(mockGitHub.issues.create).not.toHaveBeenCalled();
      expect(mockGitHub.issues.update).toHaveBeenCalled();
    });

    it('should create new issue when no duplicate exists', async () => {
      mockGitHub.issues.listForRepo.mockResolvedValue({
        data: []
      });
      mockGitHub.issues.create.mockResolvedValue({
        data: {
          number: 456,
          title: '🔒 SQL Injection vulnerabilities found in 1 file',
          html_url: 'https://github.com/test/repo/issues/456'
        }
      });

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
      expect(mockGitHub.issues.create).toHaveBeenCalled();
      expect(mockGitHub.issues.update).not.toHaveBeenCalled();
    });
  });

  describe('RFC-081: Issue Lifecycle State Management', () => {
    it('should skip issues with rsolv:validated label', async () => {
      const validatedIssue = {
        number: 100,
        title: '🔒 SQL Injection vulnerabilities found in 1 file',
        labels: [
          { name: 'rsolv:validated' },
          { name: 'rsolv:vuln-sql-injection' },
          { name: 'security' }
        ],
        html_url: 'https://github.com/test/repo/issues/100'
      };

      mockGitHub.issues.listForRepo.mockResolvedValue({
        data: [validatedIssue]
      });

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
      expect(mockGitHub.issues.create).not.toHaveBeenCalled();
      expect(mockGitHub.issues.update).not.toHaveBeenCalled();
    });

    it('should skip issues with rsolv:false-positive label', async () => {
      const falsePositiveIssue = {
        number: 101,
        title: '🔒 XSS vulnerabilities found in 2 files',
        labels: [
          { name: 'rsolv:false-positive' },
          { name: 'rsolv:vuln-xss' },
          { name: 'security' }
        ],
        html_url: 'https://github.com/test/repo/issues/101'
      };

      mockGitHub.issues.listForRepo.mockResolvedValue({
        data: [falsePositiveIssue]
      });

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
      expect(mockGitHub.issues.create).not.toHaveBeenCalled();
      expect(mockGitHub.issues.update).not.toHaveBeenCalled();
    });

    it('should update issues with only rsolv:detected label', async () => {
      const detectedIssue = {
        number: 102,
        title: '🔒 Command Injection vulnerabilities found in 1 file',
        labels: [
          { name: 'rsolv:detected' },
          { name: 'rsolv:vuln-command-injection' },
          { name: 'security' }
        ],
        html_url: 'https://github.com/test/repo/issues/102'
      };

      mockGitHub.issues.listForRepo.mockResolvedValue({
        data: [detectedIssue]
      });
      mockGitHub.issues.update.mockResolvedValue({
        data: { ...detectedIssue }
      });
      mockGitHub.issues.createComment.mockResolvedValue({ data: {} });

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
      expect(mockGitHub.issues.create).not.toHaveBeenCalled();
      expect(mockGitHub.issues.update).toHaveBeenCalled();
    });

    it('should handle mixed state transitions correctly', async () => {
      // First group: validated (skip)
      const validatedIssue = {
        number: 200,
        labels: [
          { name: 'rsolv:validated' },
          { name: 'rsolv:vuln-sql-injection' }
        ]
      };

      // Second group: false-positive (skip)
      const falsePositiveIssue = {
        number: 201,
        labels: [
          { name: 'rsolv:false-positive' },
          { name: 'rsolv:vuln-xss' }
        ]
      };

      // Third group: detected (update)
      const detectedIssue = {
        number: 202,
        labels: [
          { name: 'rsolv:detected' },
          { name: 'rsolv:vuln-command-injection' }
        ],
        html_url: 'https://github.com/test/repo/issues/202'
      };

      // Fourth group: no existing issue (create new)
      mockGitHub.issues.listForRepo.mockImplementation(({ labels }: any) => {
        if (labels === 'rsolv:vuln-sql-injection') {
          return Promise.resolve({ data: [validatedIssue] });
        }
        if (labels === 'rsolv:vuln-xss') {
          return Promise.resolve({ data: [falsePositiveIssue] });
        }
        if (labels === 'rsolv:vuln-command-injection') {
          return Promise.resolve({ data: [detectedIssue] });
        }
        if (labels === 'rsolv:vuln-path-traversal') {
          return Promise.resolve({ data: [] });
        }
        return Promise.resolve({ data: [] });
      });

      mockGitHub.issues.update.mockResolvedValue({
        data: { ...detectedIssue }
      });
      mockGitHub.issues.createComment.mockResolvedValue({ data: {} });
      mockGitHub.issues.create.mockResolvedValue({
        data: {
          number: 203,
          title: '🔒 Path Traversal vulnerabilities found in 1 file',
          html_url: 'https://github.com/test/repo/issues/203'
        }
      });

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
      expect(mockGitHub.issues.update).toHaveBeenCalledTimes(1);
      expect(mockGitHub.issues.create).toHaveBeenCalledTimes(1);
    });
  });
});