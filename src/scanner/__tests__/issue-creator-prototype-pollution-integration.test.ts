/**
 * Integration test for prototype pollution type mapping
 * Verifies the full flow: VulnerabilityGroup -> IssueCreator -> GitHub Issue
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
    warn: vi.fn()
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

describe('Prototype Pollution Integration Test', () => {
  let issueCreator: IssueCreator;
  let mockForgeAdapter: ReturnType<typeof createMockForgeAdapter>;
  let mockConfig: ScanConfig;

  beforeEach(() => {
    vi.clearAllMocks();
    mockForgeAdapter = createMockForgeAdapter();
    issueCreator = new IssueCreator(mockForgeAdapter as unknown as ForgeAdapter);

    mockForgeAdapter.createIssue.mockResolvedValue({
      number: 1,
      title: 'Test Issue',
      url: 'https://github.com/test/repo/issues/1',
      labels: [],
      state: 'open'
    } as ForgeIssue);

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
    expect(mockForgeAdapter.createIssue).toHaveBeenCalledTimes(1);

    // createIssue is called with (owner, repo, params) -- params is the 3rd arg
    const callArgs = mockForgeAdapter.createIssue.mock.calls[0];
    const owner = callArgs[0];
    const repo = callArgs[1];
    const params = callArgs[2];

    expect(owner).toBe('RSOLV-dev');
    expect(repo).toBe('railsgoat');

    // Verify title uses human-readable "Prototype Pollution"
    expect(params.title).toBe('🔒 Prototype Pollution vulnerabilities found in 1 file');
    expect(params.title).not.toContain('prototype_pollution'); // no underscore
    expect(params.title).not.toContain('Prototype_pollution'); // no underscore

    // Verify labels include correct type-specific label
    expect(params.labels).toContain('rsolv:vuln-prototype_pollution');
    expect(params.labels).toContain('rsolv:detected');
    expect(params.labels).toContain('security');
    expect(params.labels).toContain('high');

    // Verify body contains properly formatted type name
    expect(params.body).toContain('**Type**: Prototype Pollution');
    expect(params.body).not.toContain('**Type**: Prototype_pollution');
    expect(params.body).not.toContain('**Type**: prototype_pollution');

    // Verify body contains proper description
    expect(params.body).toContain('Prototype pollution vulnerabilities occur');
    expect(params.body).toContain('prototype chain');

    // Verify body contains proper remediation
    expect(params.body).toContain('Object.create(null)');
    expect(params.body).toContain('Map instead of plain objects');

    // Verify vulnerability details are included
    expect(params.body).toContain('jsapi.js');
    expect(params.body).toContain('Line 10');
    expect(params.body).toContain('Line 25');

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

    expect(mockForgeAdapter.createIssue).toHaveBeenCalledTimes(2);

    const prototypePollutionParams = mockForgeAdapter.createIssue.mock.calls[0][2];
    const deserializationParams = mockForgeAdapter.createIssue.mock.calls[1][2];

    // Verify different titles
    expect(prototypePollutionParams.title).toContain('Prototype Pollution');
    expect(deserializationParams.title).toContain('Insecure Deserialization');

    // Verify different labels
    expect(prototypePollutionParams.labels).toContain('rsolv:vuln-prototype_pollution');
    expect(deserializationParams.labels).toContain('rsolv:vuln-insecure_deserialization');

    // Verify different descriptions
    expect(prototypePollutionParams.body).toContain('prototype chain');
    expect(deserializationParams.body).toContain('deserialized without proper validation');
  });
});
