/**
 * Integration test for prototype pollution type mapping
 * Verifies the full flow: VulnerabilityGroup → IssueCreator → GitHub Issue
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

vi.mock('../../utils/logger.js', () => ({
  logger: {
    info: vi.fn(),
    error: vi.fn(),
    warn: vi.fn()
  }
}));

describe('Prototype Pollution Integration Test', () => {
  let issueCreator: IssueCreator;
  let mockConfig: ScanConfig;

  beforeEach(() => {
    vi.clearAllMocks();
    issueCreator = new IssueCreator();

    mockIssueCreate.mockResolvedValue({
      data: {
        number: 1,
        title: 'Test Issue',
        html_url: 'https://github.com/test/repo/issues/1',
        labels: []
      }
    });

    mockConfig = {
      repository: {
        owner: 'RSOLV-dev',
        name: 'railsgoat',
        defaultBranch: 'main'
      },
      createIssues: true,
      issueLabel: 'security'
    };
  });

  it('should create properly formatted GitHub issue for prototype_pollution vulnerability', async () => {
    // Simulate what the scanner produces when it detects prototype pollution
    const prototypePollutionGroup: VulnerabilityGroup = {
      type: VulnerabilityType.PROTOTYPE_POLLUTION, // 'prototype_pollution'
      severity: 'high',
      count: 2,
      files: ['app/assets/javascripts/jsapi.js'],
      vulnerabilities: [
        {
          type: VulnerabilityType.PROTOTYPE_POLLUTION,
          severity: 'high',
          line: 10,
          column: 5,
          message: 'Unsafe assignment to object[key] allows prototype pollution',
          description: 'User-controlled key in object assignment can pollute Object.prototype',
          cweId: 'CWE-1321',
          owaspCategory: 'A08:2021',
          remediation: 'Use Object.create(null) or validate keys against whitelist',
          confidence: 85,
          filePath: 'app/assets/javascripts/jsapi.js',
          snippet: 'obj[userKey] = value;'
        },
        {
          type: VulnerabilityType.PROTOTYPE_POLLUTION,
          severity: 'high',
          line: 25,
          column: 3,
          message: 'Prototype pollution via __proto__',
          description: 'Direct __proto__ assignment',
          cweId: 'CWE-1321',
          owaspCategory: 'A08:2021',
          remediation: 'Use Object.create(null) or validate keys against whitelist',
          confidence: 90,
          filePath: 'app/assets/javascripts/jsapi.js',
          snippet: 'obj.__proto__ = malicious;'
        }
      ]
    };

    // Act: Create issue from the vulnerability group
    const result = await issueCreator.createIssuesFromGroups(
      [prototypePollutionGroup],
      mockConfig
    );

    // Assert: Verify the issue was created correctly
    expect(result.issues).toHaveLength(1);
    expect(mockIssueCreate).toHaveBeenCalledTimes(1);

    const githubIssuePayload = mockIssueCreate.mock.calls[0][0];

    // Verify title uses human-readable "Prototype Pollution"
    expect(githubIssuePayload.title).toBe('🔒 Prototype Pollution vulnerabilities found in 1 file');
    expect(githubIssuePayload.title).not.toContain('prototype_pollution'); // no underscore
    expect(githubIssuePayload.title).not.toContain('Prototype_pollution'); // no underscore

    // Verify labels include correct type-specific label
    expect(githubIssuePayload.labels).toContain('rsolv:vuln-prototype_pollution');
    expect(githubIssuePayload.labels).toContain('rsolv:detected');
    expect(githubIssuePayload.labels).toContain('security');
    expect(githubIssuePayload.labels).toContain('high');

    // Verify body contains properly formatted type name
    expect(githubIssuePayload.body).toContain('**Type**: Prototype Pollution');
    expect(githubIssuePayload.body).not.toContain('**Type**: Prototype_pollution');
    expect(githubIssuePayload.body).not.toContain('**Type**: prototype_pollution');

    // Verify body contains proper description
    expect(githubIssuePayload.body).toContain('Prototype pollution vulnerabilities occur');
    expect(githubIssuePayload.body).toContain('prototype chain');

    // Verify body contains proper remediation
    expect(githubIssuePayload.body).toContain('Object.create(null)');
    expect(githubIssuePayload.body).toContain('Map instead of plain objects');

    // Verify vulnerability details are included
    expect(githubIssuePayload.body).toContain('jsapi.js');
    expect(githubIssuePayload.body).toContain('Line 10');
    expect(githubIssuePayload.body).toContain('Line 25');

    // Verify the returned issue metadata
    expect(result.issues[0].vulnerabilityType).toBe('prototype_pollution');
    expect(result.issues[0].fileCount).toBe(1);
  });

  it('should differentiate prototype_pollution from insecure_deserialization', async () => {
    // Both are in OWASP A08:2021 but are different vulnerability types
    const groups: VulnerabilityGroup[] = [
      {
        type: VulnerabilityType.PROTOTYPE_POLLUTION,
        severity: 'high',
        count: 1,
        files: ['jsapi.js'],
        vulnerabilities: []
      },
      {
        type: VulnerabilityType.INSECURE_DESERIALIZATION,
        severity: 'high',
        count: 1,
        files: ['deserialize.rb'],
        vulnerabilities: []
      }
    ];

    await issueCreator.createIssuesFromGroups(groups, mockConfig);

    expect(mockIssueCreate).toHaveBeenCalledTimes(2);

    const prototypePollutionCall = mockIssueCreate.mock.calls[0][0];
    const deserializationCall = mockIssueCreate.mock.calls[1][0];

    // Verify different titles
    expect(prototypePollutionCall.title).toContain('Prototype Pollution');
    expect(deserializationCall.title).toContain('Insecure Deserialization');

    // Verify different labels
    expect(prototypePollutionCall.labels).toContain('rsolv:vuln-prototype_pollution');
    expect(deserializationCall.labels).toContain('rsolv:vuln-insecure_deserialization');

    // Verify different descriptions
    expect(prototypePollutionCall.body).toContain('prototype chain');
    expect(deserializationCall.body).toContain('deserialized without proper validation');
  });
});
