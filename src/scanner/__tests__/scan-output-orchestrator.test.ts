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
      'CWE-798': 'low',
    }),
  };
});

function makeGroups(count: number): VulnerabilityGroup[] {
  return Array.from({ length: count }, (_, i) => ({
    type: `vuln-type-${i}`,
    severity: 'high' as const,
    count: 1,
    files: [`file${i}.js`],
    vulnerabilities: [{
      type: `vuln-type-${i}`,
      severity: 'high' as const,
      confidence: 'high' as unknown as number,
      message: `Vulnerability ${i}`,
      filePath: `file${i}.js`,
      line: 10,
      column: 5,
      snippet: 'vulnerable code',
      description: `Description ${i}`
    }]
  }));
}

describe('ScanOrchestrator - scan_output (RFC-133 Phase 2)', () => {
  let orchestrator: ScanOrchestrator;

  beforeEach(() => {
    vi.clearAllMocks();
    process.env.RSOLV_API_URL = 'https://api.test.com';
    process.env.RSOLV_API_KEY = 'test-key';
    orchestrator = new ScanOrchestrator();
  });

  describe('issue creation gating', () => {
    it('should NOT create issues when scanOutput does not include "issues"', async () => {
      const config: ScanConfig = {
        repository: { owner: 'test', name: 'repo', defaultBranch: 'main' },
        scanOutput: ['report'],
        scanDirectory: '.',
        excludePaths: []
      };

      const groups = makeGroups(3);
      orchestrator['scanner'].scan = vi.fn().mockResolvedValue({
        vulnerabilities: groups.flatMap(g => g.vulnerabilities),
        groupedVulnerabilities: groups,
        stats: { totalFiles: 3, scannedFiles: 3, vulnerabilities: 3 },
        createdIssues: []
      });

      const createIssuesSpy = vi.spyOn(orchestrator['issueCreator'], 'createIssuesFromGroups');

      const result = await orchestrator.performScan(config);

      // Should NOT call createIssuesFromGroups at all
      expect(createIssuesSpy).not.toHaveBeenCalled();
      expect(result.createdIssues).toHaveLength(0);
    });

    it('should create issues when scanOutput includes "issues"', async () => {
      const config: ScanConfig = {
        repository: { owner: 'test', name: 'repo', defaultBranch: 'main' },
        scanOutput: ['issues'],
        maxIssues: 3,
        scanDirectory: '.',
        excludePaths: []
      };

      const groups = makeGroups(3);
      orchestrator['scanner'].scan = vi.fn().mockResolvedValue({
        vulnerabilities: groups.flatMap(g => g.vulnerabilities),
        groupedVulnerabilities: groups,
        stats: { totalFiles: 3, scannedFiles: 3, vulnerabilities: 3 },
        createdIssues: []
      });

      vi.spyOn(orchestrator['issueCreator'], 'createIssuesFromGroups')
        .mockResolvedValue({
          issues: [
            { number: 1, title: 'Issue 1', url: 'url1', vulnerabilityType: 'vuln-type-0', fileCount: 1 },
          ],
          skippedValidated: 0,
          skippedFalsePositive: 0
        });

      const result = await orchestrator.performScan(config);

      expect(result.createdIssues).toHaveLength(1);
    });

    it('should create issues when scanOutput is empty array (dry run)', async () => {
      const config: ScanConfig = {
        repository: { owner: 'test', name: 'repo', defaultBranch: 'main' },
        scanOutput: [],
        scanDirectory: '.',
        excludePaths: []
      };

      const groups = makeGroups(3);
      orchestrator['scanner'].scan = vi.fn().mockResolvedValue({
        vulnerabilities: groups.flatMap(g => g.vulnerabilities),
        groupedVulnerabilities: groups,
        stats: { totalFiles: 3, scannedFiles: 3, vulnerabilities: 3 },
        createdIssues: []
      });

      const createIssuesSpy = vi.spyOn(orchestrator['issueCreator'], 'createIssuesFromGroups');

      const result = await orchestrator.performScan(config);

      // Empty array = dry run, no issues created
      expect(createIssuesSpy).not.toHaveBeenCalled();
      expect(result.createdIssues).toHaveLength(0);
    });

    it('should default to creating issues when scanOutput is undefined (backward compat)', async () => {
      const config: ScanConfig = {
        repository: { owner: 'test', name: 'repo', defaultBranch: 'main' },
        // No scanOutput set — backward compatible
        createIssues: true,
        maxIssues: 3,
        scanDirectory: '.',
        excludePaths: []
      };

      const groups = makeGroups(2);
      orchestrator['scanner'].scan = vi.fn().mockResolvedValue({
        vulnerabilities: groups.flatMap(g => g.vulnerabilities),
        groupedVulnerabilities: groups,
        stats: { totalFiles: 2, scannedFiles: 2, vulnerabilities: 2 },
        createdIssues: []
      });

      vi.spyOn(orchestrator['issueCreator'], 'createIssuesFromGroups')
        .mockResolvedValue({
          issues: [
            { number: 1, title: 'Issue 1', url: 'url1', vulnerabilityType: 'vuln-type-0', fileCount: 1 },
            { number: 2, title: 'Issue 2', url: 'url2', vulnerabilityType: 'vuln-type-1', fileCount: 1 },
          ],
          skippedValidated: 0,
          skippedFalsePositive: 0
        });

      const result = await orchestrator.performScan(config);

      // Default behavior: create issues
      expect(result.createdIssues).toHaveLength(2);
    });
  });

  describe('report generation', () => {
    it('should include scanReport in result when scanOutput includes "report"', async () => {
      const config: ScanConfig = {
        repository: { owner: 'test', name: 'repo', defaultBranch: 'main' },
        scanOutput: ['report'],
        scanDirectory: '.',
        excludePaths: []
      };

      const groups = makeGroups(3);
      orchestrator['scanner'].scan = vi.fn().mockResolvedValue({
        vulnerabilities: groups.flatMap(g => g.vulnerabilities),
        groupedVulnerabilities: groups,
        stats: { totalFiles: 3, scannedFiles: 3, vulnerabilities: 3 },
        createdIssues: []
      });

      const result = await orchestrator.performScan(config);

      // Should have scanReport field with JSON + markdown
      expect(result.scanReport).toBeDefined();
      expect(result.scanReport!.json).toBeDefined();
      expect(result.scanReport!.markdown).toBeDefined();
      expect(result.scanReport!.json.findings).toHaveLength(3);
      expect(result.scanReport!.markdown).toContain('RSOLV Scan Report');
    });

    it('should NOT include scanReport when scanOutput does not include "report"', async () => {
      const config: ScanConfig = {
        repository: { owner: 'test', name: 'repo', defaultBranch: 'main' },
        scanOutput: ['issues'],
        maxIssues: 3,
        scanDirectory: '.',
        excludePaths: []
      };

      const groups = makeGroups(2);
      orchestrator['scanner'].scan = vi.fn().mockResolvedValue({
        vulnerabilities: groups.flatMap(g => g.vulnerabilities),
        groupedVulnerabilities: groups,
        stats: { totalFiles: 2, scannedFiles: 2, vulnerabilities: 2 },
        createdIssues: []
      });

      vi.spyOn(orchestrator['issueCreator'], 'createIssuesFromGroups')
        .mockResolvedValue({
          issues: [],
          skippedValidated: 0,
          skippedFalsePositive: 0
        });

      const result = await orchestrator.performScan(config);

      expect(result.scanReport).toBeUndefined();
    });

    it('should include ALL findings in report regardless of max_issues', async () => {
      const config: ScanConfig = {
        repository: { owner: 'test', name: 'repo', defaultBranch: 'main' },
        scanOutput: ['report', 'issues'],
        maxIssues: 2,
        scanDirectory: '.',
        excludePaths: []
      };

      const groups = makeGroups(5);
      orchestrator['scanner'].scan = vi.fn().mockResolvedValue({
        vulnerabilities: groups.flatMap(g => g.vulnerabilities),
        groupedVulnerabilities: groups,
        stats: { totalFiles: 5, scannedFiles: 5, vulnerabilities: 5 },
        createdIssues: []
      });

      vi.spyOn(orchestrator['issueCreator'], 'createIssuesFromGroups')
        .mockResolvedValue({
          issues: [
            { number: 1, title: 'Issue 1', url: 'url1', vulnerabilityType: 'vuln-type-0', fileCount: 1 },
            { number: 2, title: 'Issue 2', url: 'url2', vulnerabilityType: 'vuln-type-1', fileCount: 1 },
          ],
          skippedValidated: 0,
          skippedFalsePositive: 0
        });

      const result = await orchestrator.performScan(config);

      // Report includes ALL findings, not just max_issues
      expect(result.scanReport!.json.findings).toHaveLength(5);
      // But only 2 issues created
      expect(result.createdIssues).toHaveLength(2);
    });
  });
});
