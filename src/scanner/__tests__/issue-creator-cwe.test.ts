import { describe, it, expect, vi, beforeEach } from 'vitest';
import { IssueCreator } from '../issue-creator.js';
import type { ForgeAdapter } from '../../forge/forge-adapter.js';
import type { VulnerabilityGroup, ScanConfig } from '../types.js';

vi.mock('../../utils/logger.js');

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

function createScanConfig(): ScanConfig {
  return {
    repository: { owner: 'test', name: 'repo' },
    branch: 'main',
    createIssues: true,
  };
}

describe('IssueCreator - cweId population', () => {
  let issueCreator: IssueCreator;
  let mockForgeAdapter: ReturnType<typeof createMockForgeAdapter>;

  beforeEach(() => {
    vi.clearAllMocks();
    mockForgeAdapter = createMockForgeAdapter();
    issueCreator = new IssueCreator(mockForgeAdapter as unknown as ForgeAdapter);
  });

  it('includes cweId in created issue when vulnerabilities have cweId', async () => {
    mockForgeAdapter.createIssue.mockResolvedValue({
      number: 42,
      title: 'test title',
      url: 'https://github.com/test/repo/issues/42',
      labels: ['rsolv:detected'],
      state: 'open',
    });

    const group: VulnerabilityGroup = {
      type: 'sql-injection',
      severity: 'critical',
      count: 1,
      files: ['app.py'],
      vulnerabilities: [
        {
          type: 'sql-injection',
          severity: 'critical',
          filePath: 'app.py',
          line: 10,
          description: 'SQL injection via string concatenation',
          cweId: 'CWE-89',
        },
      ],
    };

    const result = await issueCreator.createIssuesFromGroups([group], createScanConfig());

    expect(result.issues).toHaveLength(1);
    expect(result.issues[0].cweId).toBe('CWE-89');
  });

  it('includes cweId in updated existing issue', async () => {
    // First call returns existing issue, meaning findExistingIssue finds a match
    mockForgeAdapter.listIssues.mockResolvedValue([{
      number: 99,
      title: 'existing issue',
      url: 'https://github.com/test/repo/issues/99',
      labels: ['rsolv:detected', 'rsolv:vuln-xss'],
      state: 'open',
    }]);

    const group: VulnerabilityGroup = {
      type: 'xss',
      severity: 'high',
      count: 2,
      files: ['index.js'],
      vulnerabilities: [
        {
          type: 'xss',
          severity: 'high',
          filePath: 'index.js',
          line: 5,
          description: 'XSS via innerHTML',
          cweId: 'CWE-79',
        },
        {
          type: 'xss',
          severity: 'high',
          filePath: 'index.js',
          line: 20,
          description: 'XSS via unescaped output',
          cweId: 'CWE-79',
        },
      ],
    };

    const result = await issueCreator.createIssuesFromGroups([group], createScanConfig());

    expect(result.issues).toHaveLength(1);
    expect(result.issues[0].cweId).toBe('CWE-79');
  });

  it('returns undefined cweId when vulnerabilities lack cweId', async () => {
    mockForgeAdapter.createIssue.mockResolvedValue({
      number: 55,
      title: 'test',
      url: 'https://github.com/test/repo/issues/55',
      labels: ['rsolv:detected'],
      state: 'open',
    });

    const group: VulnerabilityGroup = {
      type: 'command-injection',
      severity: 'high',
      count: 1,
      files: ['run.js'],
      vulnerabilities: [
        {
          type: 'command-injection',
          severity: 'high',
          filePath: 'run.js',
          line: 3,
          description: 'Command injection via exec',
          // no cweId
        },
      ],
    };

    const result = await issueCreator.createIssuesFromGroups([group], createScanConfig());

    expect(result.issues).toHaveLength(1);
    expect(result.issues[0].cweId).toBeUndefined();
  });
});
