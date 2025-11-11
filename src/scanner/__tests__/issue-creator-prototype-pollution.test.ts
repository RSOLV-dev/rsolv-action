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
import type { VulnerabilityGroup, ScanConfig } from '../types.js';
import { VulnerabilityType } from '../../security/types.js';

// Mock the GitHub API client
const mockIssueCreate = vi.fn();

vi.mock('../../github/api.js', () => ({
  getGitHubClient: () => ({
    issues: {
      create: mockIssueCreate,
      listForRepo: vi.fn().mockResolvedValue({ data: [] })
    }
  })
}));

// Mock logger
vi.mock('../../utils/logger.js', () => ({
  logger: {
    info: vi.fn(),
    error: vi.fn(),
    warn: vi.fn(),
    debug: vi.fn()
  }
}));

describe('IssueCreator - Prototype Pollution Type Mapping', () => {
  let issueCreator: IssueCreator;
  let mockConfig: ScanConfig;

  beforeEach(() => {
    vi.clearAllMocks();
    issueCreator = new IssueCreator();

    mockIssueCreate.mockImplementation(({ title, labels }) =>
      Promise.resolve({
        data: {
          number: 123,
          title,
          html_url: 'https://github.com/test/repo/issues/123',
          labels
        }
      })
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
      expect(mockIssueCreate).toHaveBeenCalledTimes(1);

      // Get the arguments passed to create
      const createCallArgs = mockIssueCreate.mock.calls[0][0];

      // RED: This should FAIL initially, demonstrating the bug
      // The type-specific label should be 'rsolv:vuln-prototype_pollution'
      expect(createCallArgs.labels).toContain('rsolv:vuln-prototype_pollution');

      // Verify the issue title contains "Prototype Pollution"
      expect(createCallArgs.title).toContain('Prototype Pollution');

      // Verify it's NOT using improper_input_validation
      expect(createCallArgs.labels).not.toContain('rsolv:vuln-improper_input_validation');
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

      const createCallArgs = mockIssueCreate.mock.calls[0][0];

      // RED: This should FAIL initially
      // Title should be "🔒 Prototype Pollution vulnerabilities found in 2 files"
      expect(createCallArgs.title).toBe('🔒 Prototype Pollution vulnerabilities found in 2 files');

      // Should NOT be generic or use improper capitalization
      expect(createCallArgs.title).not.toContain('Prototype pollution'); // lowercase p
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

      const createCallArgs = mockIssueCreate.mock.calls[0][0];

      // RED: This should FAIL initially
      // Body should contain proper description for prototype pollution
      expect(createCallArgs.body).toContain('Prototype Pollution');

      // Should include proper remediation advice specific to prototype pollution
      expect(createCallArgs.body).toContain('Object.create(null)');
      expect(createCallArgs.body).toContain('prototype');
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

      const createCallArgs = mockIssueCreate.mock.calls[0][0];

      // This should work correctly (baseline)
      expect(createCallArgs.title).toContain('SQL Injection');
      expect(createCallArgs.labels).toContain('rsolv:vuln-sql_injection');
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
      expect(mockIssueCreate).toHaveBeenCalledTimes(2);

      const deserializationCall = mockIssueCreate.mock.calls[0][0];
      const prototypePollutionCall = mockIssueCreate.mock.calls[1][0];

      // RED: These should be different
      expect(deserializationCall.labels).toContain('rsolv:vuln-insecure_deserialization');
      expect(prototypePollutionCall.labels).toContain('rsolv:vuln-prototype_pollution');

      // Titles should be different
      expect(deserializationCall.title).toContain('Insecure Deserialization');
      expect(prototypePollutionCall.title).toContain('Prototype Pollution');
    });
  });
});
