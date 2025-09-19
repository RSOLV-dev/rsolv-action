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

describe('ScanOrchestrator - max_issues bug', () => {
  let orchestrator: ScanOrchestrator;
  const mockLogger = logger as any;

  beforeEach(() => {
    vi.clearAllMocks();
    orchestrator = new ScanOrchestrator();
  });

  describe('RED - Shows the bug (should fail after fix)', () => {
    it('BEFORE FIX: should log incorrect number of groups when max_issues is set', async () => {
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

      await orchestrator.performScan(config);

      // BUG: The orchestrator logs "Creating issues for 8 vulnerability groups"
      // even though max_issues is 2
      const createLogCall = mockLogger.info.mock.calls.find(
        call => call[0].includes('Creating issues for')
      );

      // This test will PASS showing the bug exists
      expect(createLogCall).toBeDefined();
      expect(createLogCall![0]).toContain('8 vulnerability groups');

      // The actual issue creation should only create 2
      const createdLogCall = mockLogger.info.mock.calls.find(
        call => call[0].includes('Created') && call[0].includes('issues')
      );
      expect(createdLogCall![0]).toContain('2 issues');
    });
  });

  describe('GREEN - After the fix', () => {
    it('should respect max_issues in all log messages', async () => {
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

      // Create 8 vulnerability groups
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

      await orchestrator.performScan(config);

      // After fix: No log should mention "8 vulnerability groups" for creation
      const allLogCalls = mockLogger.info.mock.calls.map(call => call[0]);

      // Should NOT find any log saying "Creating issues for 8"
      const incorrectLog = allLogCalls.find(
        log => log.includes('Creating issues for 8')
      );
      expect(incorrectLog).toBeUndefined();

      // Should find a log that respects max_issues
      const correctLog = allLogCalls.find(
        log => log.includes('Creating issues for 2') ||
               log.includes('Creating issues for') && log.includes('(limited')
      );
      expect(correctLog).toBeDefined();
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