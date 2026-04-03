/**
 * TDD Test for prototype_pollution type mapping bug
 * RED-GREEN-REFACTOR approach
 *
 * Bug: Prototype pollution vulnerabilities detected with correct CWE-1321 and message,
 * but type field shows "improper_input_validation" instead of "prototype_pollution"
 * in GitHub issues.
 *
 * Evidence: https://github.com/RSOLV-dev/railsgoat/actions/runs/19247635771
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { IssueCreator } from '../issue-creator.js';
import type { ForgeAdapter, ForgeIssue } from '../../forge/forge-adapter.js';
import type { VulnerabilityGroup, ScanConfig } from '../types.js';
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
    createIssue: vi.fn(),
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

describe('IssueCreator - Prototype Pollution Type Mapping', () => {
  let issueCreator: IssueCreator;
  let mockForgeAdapter: ReturnType<typeof createMockForgeAdapter>;
  let mockConfig: ScanConfig;

  beforeEach(() => {
    vi.clearAllMocks();
    mockForgeAdapter = createMockForgeAdapter();
    issueCreator = new IssueCreator(mockForgeAdapter as unknown as ForgeAdapter);

    mockForgeAdapter.createIssue.mockImplementation(
      (_owner: string, _repo: string, params: { title: string; body: string; labels: string[] }) =>
        Promise.resolve({
          number: 123,
          title: params.title,
          url: 'https://github.com/test/repo/issues/123',
          labels: params.labels,
          state: 'open'
        } as ForgeIssue)
    );

    mockConfig = {
      repository: {
        owner: 'test-org',
        name: 'test-repo',
        defaultBranch: 'main'
      },
      createIssues: true,
      issueLabel: 'security',
      batchSimilar: true
    };
  });

  describe('RED Test - Demonstrate the bug', () => {
    it('should create issue with correct type label for prototype_pollution', async () => {
      // Create a vulnerability group with prototype_pollution type
      const prototypePollutionGroup: VulnerabilityGroup = {
        type: VulnerabilityType.PROTOTYPE_POLLUTION, // This is 'prototype_pollution'
        severity: 'high',
        count: 2,
        files: ['app/assets/javascripts/jsapi.js'],
        vulnerabilities: [
          {
            type: VulnerabilityType.PROTOTYPE_POLLUTION,
            severity: 'high',
            line: 10,
            message: 'Unsafe assignment to object[key] allows prototype pollution',
            description: 'Prototype pollution via __proto__ manipulation',
            cweId: 'CWE-1321',
            owaspCategory: 'A08:2021',
            confidence: 85,
            filePath: 'app/assets/javascripts/jsapi.js'
          }
        ]
      };

      // Create the issue
      const result = await issueCreator.createIssuesFromGroups(
        [prototypePollutionGroup],
        mockConfig
      );

      // Verify issue was created
      expect(result.issues).toHaveLength(1);
      expect(mockForgeAdapter.createIssue).toHaveBeenCalledTimes(1);

      // Get the params passed to createIssue (3rd arg)
      const createCallParams = mockForgeAdapter.createIssue.mock.calls[0][2];

      // RED: This should FAIL initially, demonstrating the bug
      // The type-specific label should be 'rsolv:vuln-prototype_pollution'
      expect(createCallParams.labels).toContain('rsolv:vuln-prototype_pollution');

      // Verify the issue title contains "Prototype Pollution"
      expect(createCallParams.title).toContain('Prototype Pollution');

      // Verify it's NOT using improper_input_validation
      expect(createCallParams.labels).not.toContain('rsolv:vuln-improper_input_validation');
    });

    it('should generate correct human-readable title for prototype_pollution', async () => {
      const prototypePollutionGroup: VulnerabilityGroup = {
        type: VulnerabilityType.PROTOTYPE_POLLUTION,
        severity: 'high',
        count: 3,
        files: ['file1.js', 'file2.js'],
        vulnerabilities: []
      };

      await issueCreator.createIssuesFromGroups(
        [prototypePollutionGroup],
        mockConfig
      );

      const createCallParams = mockForgeAdapter.createIssue.mock.calls[0][2];

      // RED: This should FAIL initially
      // Title should be "🔒 Prototype Pollution vulnerabilities found in 2 files"
      expect(createCallParams.title).toBe('🔒 Prototype Pollution vulnerabilities found in 2 files');

      // Should NOT be generic or use improper capitalization
      expect(createCallParams.title).not.toContain('Prototype pollution'); // lowercase p
    });

    it('should include prototype pollution in issue body description', async () => {
      const prototypePollutionGroup: VulnerabilityGroup = {
        type: VulnerabilityType.PROTOTYPE_POLLUTION,
        severity: 'high',
        count: 1,
        files: ['jsapi.js'],
        vulnerabilities: [
          {
            type: VulnerabilityType.PROTOTYPE_POLLUTION,
            severity: 'high',
            line: 10,
            message: 'Prototype pollution',
            description: 'Unsafe assignment allows prototype pollution',
            cweId: 'CWE-1321',
            owaspCategory: 'A08:2021',
            confidence: 85,
            filePath: 'jsapi.js'
          }
        ]
      };

      await issueCreator.createIssuesFromGroups(
        [prototypePollutionGroup],
        mockConfig
      );

      const createCallParams = mockForgeAdapter.createIssue.mock.calls[0][2];

      // RED: This should FAIL initially
      // Body should contain proper description for prototype pollution
      expect(createCallParams.body).toContain('Prototype Pollution');

      // Should include proper remediation advice specific to prototype pollution
      expect(createCallParams.body).toContain('Object.create(null)');
      expect(createCallParams.body).toContain('prototype');
    });
  });

  describe('Comparison with other vulnerability types', () => {
    it('should handle sql-injection type correctly (baseline test)', async () => {
      const sqlInjectionGroup: VulnerabilityGroup = {
        type: 'sql_injection',
        severity: 'high',
        count: 1,
        files: ['user.rb'],
        vulnerabilities: []
      };

      await issueCreator.createIssuesFromGroups(
        [sqlInjectionGroup],
        mockConfig
      );

      const createCallParams = mockForgeAdapter.createIssue.mock.calls[0][2];

      // This should work correctly (baseline)
      expect(createCallParams.title).toContain('SQL Injection');
      expect(createCallParams.labels).toContain('rsolv:vuln-sql_injection');
    });

    it('should handle insecure_deserialization separately from prototype_pollution', async () => {
      // These are different vulnerability types with different CWEs
      const deserializationGroup: VulnerabilityGroup = {
        type: VulnerabilityType.INSECURE_DESERIALIZATION, // 'insecure_deserialization'
        severity: 'high',
        count: 1,
        files: ['deserialize.rb'],
        vulnerabilities: []
      };

      const prototypePollutionGroup: VulnerabilityGroup = {
        type: VulnerabilityType.PROTOTYPE_POLLUTION, // 'prototype_pollution'
        severity: 'high',
        count: 1,
        files: ['jsapi.js'],
        vulnerabilities: []
      };

      // Create issues for both
      await issueCreator.createIssuesFromGroups(
        [deserializationGroup],
        mockConfig
      );

      await issueCreator.createIssuesFromGroups(
        [prototypePollutionGroup],
        mockConfig
      );

      // Verify they create different issues with different labels
      expect(mockForgeAdapter.createIssue).toHaveBeenCalledTimes(2);

      const deserializationParams = mockForgeAdapter.createIssue.mock.calls[0][2];
      const prototypePollutionParams = mockForgeAdapter.createIssue.mock.calls[1][2];

      // RED: These should be different
      expect(deserializationParams.labels).toContain('rsolv:vuln-insecure_deserialization');
      expect(prototypePollutionParams.labels).toContain('rsolv:vuln-prototype_pollution');

      // Titles should be different
      expect(deserializationParams.title).toContain('Insecure Deserialization');
      expect(prototypePollutionParams.title).toContain('Prototype Pollution');
    });
  });
});
