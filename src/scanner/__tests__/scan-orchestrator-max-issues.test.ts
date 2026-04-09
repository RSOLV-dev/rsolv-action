import { describe, it, expect, beforeEach, vi } from 'vitest';
import { ScanOrchestrator } from '../scan-orchestrator.js';
import { logger } from '../../utils/logger.js';
import type { ScanConfig, VulnerabilityGroup } from '../types.js';

// Mock dependencies
vi.mock('../../utils/logger.js', () => ({
  logger: {
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    debug: vi.fn()
  }
}));
vi.mock('../../forge/github-adapter.js', () => ({
  GitHubAdapter: class {
    constructor() {}
    async listIssues() { return []; }
    async createIssue(params: { title: string }) {
      return {
        number: Math.floor(Math.random() * 1000),
        title: params.title,
        url: `https://github.com/test/repo/issues/${Math.floor(Math.random() * 1000)}`,
        labels: [],
        state: 'open',
      };
    }
    async updateIssue() {}
    async addLabels() {}
    async createComment() {}
    async removeLabel() {}
  },
}));
vi.mock('../../github/api.js', () => ({
  getGitHubClient: vi.fn(() => ({
    issues: {
      create: vi.fn().mockResolvedValue({
        data: {
          number: 123,
          title: 'Test Issue',
          html_url: 'https://github.com/test/test/issues/123'
        }
      })
    }
  }))
}));
vi.mock('../../github/label-manager.js', () => ({
  ensureLabelsExist: vi.fn(),
}));
vi.mock('../finding-prioritizer.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../finding-prioritizer.js')>();
  return {
    ...actual,
    fetchSeverityTiers: vi.fn().mockResolvedValue({
      'CWE-89': 'critical',
      'CWE-78': 'critical',
      'CWE-94': 'critical',
      'CWE-502': 'critical',
      'CWE-79': 'high',
      'CWE-22': 'high',
      'CWE-327': 'medium',
      'CWE-798': 'low',
    }),
  };
});

describe('ScanOrchestrator - max_issues bug', () => {
  let orchestrator: ScanOrchestrator;
  const mockLogger = logger as any;

  beforeEach(() => {
    vi.clearAllMocks();
    // fetchTiers reads env vars; mock them to avoid throwing
    process.env.RSOLV_API_URL = 'https://api.test.com';
    process.env.RSOLV_API_KEY = 'test-key';
    orchestrator = new ScanOrchestrator();
  });

  describe('RED - Shows the bug existed before fix', () => {
    it.skip('BEFORE FIX: would pass all groups to createIssuesFromGroups ignoring max_issues', async () => {
      const config: ScanConfig = {
        repository: {
          owner: 'test',
          name: 'repo',
          defaultBranch: 'main'
        },
        createIssues: true,
        maxIssues: 2, // Limit to 2 issues
        scanDirectory: '.',
        excludePaths: []
      };

      // Create 8 vulnerability groups (like in the real scenario)
      const groups: VulnerabilityGroup[] = Array.from({ length: 8 }, (_, i) => ({
        type: `vuln-type-${i}`,
        severity: 'high',
        count: 1,
        files: [`file${i}.js`],
        vulnerabilities: [{
          type: `vuln-type-${i}`,
          severity: 'high',
          confidence: 'high',
          message: `Vulnerability ${i}`,
          filePath: `file${i}.js`,
          line: 10,
          column: 5,
          snippet: 'vulnerable code',
          description: `Description ${i}`
        }]
      }));

      // Mock the scanner to return 8 groups
      orchestrator['scanner'].scan = vi.fn().mockResolvedValue({
        vulnerabilities: groups.flatMap(g => g.vulnerabilities),
        groupedVulnerabilities: groups,
        stats: {
          totalFiles: 8,
          scannedFiles: 8,
          vulnerabilities: 8
        }
      });

      // Spy on createIssuesFromGroups to see what it's called with
      const createIssuesSpy = vi.spyOn(orchestrator['issueCreator'], 'createIssuesFromGroups')
        .mockResolvedValue({
          issues: [
            { number: 1, title: 'Issue 1', url: 'url1', vulnerabilityType: 'vuln-type-0', fileCount: 1 },
            { number: 2, title: 'Issue 2', url: 'url2', vulnerabilityType: 'vuln-type-1', fileCount: 1 }
          ],
          skippedValidated: 0,
          skippedFalsePositive: 0
        });

      await orchestrator.performScan(config);

      // BUG: createIssuesFromGroups is called with ALL 8 groups, not just 2
      expect(createIssuesSpy).toHaveBeenCalledWith(
        expect.anything(), // This will be all 8 groups - BUG!
        config
      );

      // This test PASSES showing the bug - it gets all 8 groups
      const passedGroups = createIssuesSpy.mock.calls[0][0];
      expect(passedGroups).toHaveLength(8); // Bug: should be 2!
    });
  });

  describe('GREEN - After the fix', () => {
    it('should only pass limited findings to createIssuesFromFindings (RFC-142)', async () => {
      const config: ScanConfig = {
        repository: {
          owner: 'test',
          name: 'repo',
          defaultBranch: 'main'
        },
        createIssues: true,
        maxIssues: 2,
        scanDirectory: '.',
        excludePaths: []
      };

      // Create 8 vulnerability groups (each with 1 finding)
      const groups: VulnerabilityGroup[] = Array.from({ length: 8 }, (_, i) => ({
        type: `vuln-type-${i}`,
        severity: 'high',
        count: 1,
        files: [`file${i}.js`],
        vulnerabilities: [{
          type: `vuln-type-${i}`,
          severity: 'high',
          confidence: 'high',
          message: `Vulnerability ${i}`,
          filePath: `file${i}.js`,
          line: 10,
          column: 5,
          snippet: 'vulnerable code',
          description: `Description ${i}`
        }]
      }));

      orchestrator['scanner'].scan = vi.fn().mockResolvedValue({
        vulnerabilities: groups.flatMap(g => g.vulnerabilities),
        groupedVulnerabilities: groups,
        stats: {
          totalFiles: 8,
          scannedFiles: 8,
          vulnerabilities: 8
        }
      });

      // RFC-142: Spy on createIssuesFromFindings (per-instance, not per-group)
      const createIssuesSpy = vi.spyOn(orchestrator['issueCreator'], 'createIssuesFromFindings')
        .mockResolvedValue({
          issues: [
            { number: 1, title: 'Issue 1', url: 'url1', vulnerabilityType: 'vuln-type-0', fileCount: 1 },
            { number: 2, title: 'Issue 2', url: 'url2', vulnerabilityType: 'vuln-type-1', fileCount: 1 }
          ],
          skippedValidated: 0,
          skippedFalsePositive: 0
        });

      await orchestrator.performScan(config);

      // RFC-142: createIssuesFromFindings receives ALL prioritized findings;
      // max_issues cap is applied inside createIssuesFromFindings
      expect(createIssuesSpy).toHaveBeenCalledTimes(1);
      const passedFindings = createIssuesSpy.mock.calls[0][0];
      expect(passedFindings).toHaveLength(8); // All findings passed; capping is internal
    });

    it('should only create number of issues specified by max_issues', async () => {
      const config: ScanConfig = {
        repository: {
          owner: 'test',
          name: 'repo',
          defaultBranch: 'main'
        },
        createIssues: true,
        maxIssues: 2,
        scanDirectory: '.',
        excludePaths: []
      };

      const groups: VulnerabilityGroup[] = Array.from({ length: 8 }, (_, i) => ({
        type: `vuln-type-${i}`,
        severity: 'high',
        count: 1,
        files: [`file${i}.js`],
        vulnerabilities: [{
          type: `vuln-type-${i}`,
          severity: 'high',
          confidence: 'high',
          message: `Vulnerability ${i}`,
          filePath: `file${i}.js`,
          line: 10,
          column: 5,
          snippet: 'vulnerable code',
          description: `Description ${i}`
        }]
      }));

      orchestrator['scanner'].scan = vi.fn().mockResolvedValue({
        vulnerabilities: groups.flatMap(g => g.vulnerabilities),
        groupedVulnerabilities: groups,
        stats: {
          totalFiles: 8,
          scannedFiles: 8,
          vulnerabilities: 8
        },
        createdIssues: []
      });

      const result = await orchestrator.performScan(config);

      // Should only create 2 issues despite having 8 groups
      expect(result.createdIssues).toHaveLength(2);
    });
  });

  describe('REFACTOR - Maintain functionality', () => {
    it('should still create all issues when no max_issues limit', async () => {
      const config: ScanConfig = {
        repository: {
          owner: 'test',
          name: 'repo',
          defaultBranch: 'main'
        },
        createIssues: true,
        // No maxIssues set
        scanDirectory: '.',
        excludePaths: []
      };

      const groups: VulnerabilityGroup[] = Array.from({ length: 5 }, (_, i) => ({
        type: `vuln-type-${i}`,
        severity: 'high',
        count: 1,
        files: [`file${i}.js`],
        vulnerabilities: [{
          type: `vuln-type-${i}`,
          severity: 'high',
          confidence: 'high',
          message: `Vulnerability ${i}`,
          filePath: `file${i}.js`,
          line: 10,
          column: 5,
          snippet: 'vulnerable code',
          description: `Description ${i}`
        }]
      }));

      orchestrator['scanner'].scan = vi.fn().mockResolvedValue({
        vulnerabilities: groups.flatMap(g => g.vulnerabilities),
        groupedVulnerabilities: groups,
        stats: {
          totalFiles: 5,
          scannedFiles: 5,
          vulnerabilities: 5
        },
        createdIssues: []
      });

      const result = await orchestrator.performScan(config);

      // Should create all 5 issues when no limit
      expect(result.createdIssues).toHaveLength(5);
    });

    it('should prioritize findings by CWE severity tier (RFC-142)', async () => {
      const config: ScanConfig = {
        repository: {
          owner: 'test',
          name: 'repo',
          defaultBranch: 'main'
        },
        createIssues: true,
        maxIssues: 2,
        scanDirectory: '.',
        excludePaths: []
      };

      // Findings in insertion order: low-tier CWE first, critical-tier CWE last
      const groups: VulnerabilityGroup[] = [
        {
          type: 'hardcoded_secrets',
          severity: 'high',
          count: 3,
          files: ['config.py'],
          vulnerabilities: [{
            type: 'hardcoded_secrets',
            severity: 'high',
            confidence: 90,
            message: 'Hardcoded secret',
            filePath: 'config.py',
            line: 10,
            column: 5,
            snippet: 'SECRET = "abc"',
            description: 'Hardcoded credential',
            cweId: 'CWE-798',
          }]
        },
        {
          type: 'weak_cryptography',
          severity: 'medium',
          count: 1,
          files: ['crypto.py'],
          vulnerabilities: [{
            type: 'weak_cryptography',
            severity: 'medium',
            confidence: 80,
            message: 'Weak crypto',
            filePath: 'crypto.py',
            line: 20,
            column: 5,
            snippet: 'md5()',
            description: 'Weak hash',
            cweId: 'CWE-327',
          }]
        },
        {
          type: 'sql_injection',
          severity: 'critical',
          count: 2,
          files: ['db.py'],
          vulnerabilities: [{
            type: 'sql_injection',
            severity: 'critical',
            confidence: 85,
            message: 'SQL injection',
            filePath: 'db.py',
            line: 30,
            column: 5,
            snippet: 'query(user_input)',
            description: 'SQL injection via user input',
            cweId: 'CWE-89',
          }]
        },
      ];

      orchestrator['scanner'].scan = vi.fn().mockResolvedValue({
        vulnerabilities: groups.flatMap(g => g.vulnerabilities),
        groupedVulnerabilities: groups,
        stats: { totalFiles: 3, scannedFiles: 3, vulnerabilities: 6 },
        createdIssues: []
      });

      // RFC-142: spy on createIssuesFromFindings — receives prioritized individual findings
      const createIssuesSpy = vi.spyOn(orchestrator['issueCreator'], 'createIssuesFromFindings')
        .mockResolvedValue({
          issues: [
            { number: 1, title: 'SQLi', url: 'url1', vulnerabilityType: 'sql_injection', fileCount: 1 },
            { number: 2, title: 'Weak crypto', url: 'url2', vulnerabilityType: 'weak_cryptography', fileCount: 1 }
          ],
          skippedValidated: 0,
          skippedFalsePositive: 0
        });

      await orchestrator.performScan(config);

      // Findings should be sorted by CWE severity tier:
      // 1. sql_injection (CWE-89 = Critical)
      // 2. weak_cryptography (CWE-327 = Medium)
      // 3. hardcoded_secrets (CWE-798 = Low) — last despite insertion-first
      const passedFindings = createIssuesSpy.mock.calls[0][0];
      expect(passedFindings).toHaveLength(3);
      expect(passedFindings[0].type).toBe('sql_injection');
      expect(passedFindings[1].type).toBe('weak_cryptography');
      expect(passedFindings[2].type).toBe('hardcoded_secrets');
    });

    it('should handle edge cases correctly', async () => {
      const config: ScanConfig = {
        repository: {
          owner: 'test',
          name: 'repo',
          defaultBranch: 'main'
        },
        createIssues: true,
        maxIssues: 10, // Limit higher than actual groups
        scanDirectory: '.',
        excludePaths: []
      };

      const groups: VulnerabilityGroup[] = Array.from({ length: 3 }, (_, i) => ({
        type: `vuln-type-${i}`,
        severity: 'high',
        count: 1,
        files: [`file${i}.js`],
        vulnerabilities: [{
          type: `vuln-type-${i}`,
          severity: 'high',
          confidence: 'high',
          message: `Vulnerability ${i}`,
          filePath: `file${i}.js`,
          line: 10,
          column: 5,
          snippet: 'vulnerable code',
          description: `Description ${i}`
        }]
      }));

      orchestrator['scanner'].scan = vi.fn().mockResolvedValue({
        vulnerabilities: groups.flatMap(g => g.vulnerabilities),
        groupedVulnerabilities: groups,
        stats: {
          totalFiles: 3,
          scannedFiles: 3,
          vulnerabilities: 3
        },
        createdIssues: []
      });

      const result = await orchestrator.performScan(config);

      // Should create all 3 issues when limit is higher
      expect(result.createdIssues).toHaveLength(3);
    });
  });
});