/**
 * RED TESTS — Vulnerability description enrichment for template_injection
 * and improper_input_validation pattern types.
 *
 * Tests that getVulnerabilityDescription returns specific (not generic)
 * descriptions for these two pattern types via the generated issue body.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { IssueCreator } from '../issue-creator.js';
import type { ForgeAdapter } from '../../forge/forge-adapter.js';
import type { VulnerabilityGroup, ScanConfig } from '../types.js';

vi.mock('../../utils/logger.js', () => ({
  logger: {
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    debug: vi.fn(),
  }
}));

const GENERIC_FALLBACK = 'This type of vulnerability can compromise the security of your application.';

describe('getVulnerabilityDescription — missing pattern types', () => {
  let issueCreator: IssueCreator;
  let mockCreateIssue: ReturnType<typeof vi.fn>;

  const config: ScanConfig = {
    repository: { owner: 'test', name: 'repo', defaultBranch: 'main' },
    createIssues: true,
    issueLabel: 'rsolv:detected',
  };

  beforeEach(() => {
    mockCreateIssue = vi.fn().mockResolvedValue({
      number: 1,
      title: 'test',
      url: 'https://github.com/test/repo/issues/1',
      labels: [],
      state: 'open',
    });

    const mockForgeAdapter = {
      listIssues: vi.fn().mockResolvedValue([]),
      createIssue: mockCreateIssue,
      updateIssue: vi.fn().mockResolvedValue(undefined),
      addLabels: vi.fn().mockResolvedValue(undefined),
      createComment: vi.fn().mockResolvedValue(undefined),
      removeLabel: vi.fn().mockResolvedValue(undefined),
      createPullRequest: vi.fn().mockResolvedValue({ number: 1, title: 'test', url: '', head: '', base: '' }),
      listPullRequests: vi.fn().mockResolvedValue([]),
      getFileTree: vi.fn().mockResolvedValue([]),
      getFileContent: vi.fn().mockResolvedValue(''),
    } as unknown as ForgeAdapter;

    issueCreator = new IssueCreator(mockForgeAdapter);
  });

  function createGroup(type: string): VulnerabilityGroup {
    return {
      type,
      severity: 'high',
      count: 1,
      files: ['app.py'],
      vulnerabilities: [{
        type: type as never,
        severity: 'high',
        line: 10,
        message: `${type} detected`,
        description: `${type} vulnerability found`,
        confidence: 85,
        filePath: 'app.py',
      }],
    };
  }

  it('returns specific description for template_injection (not generic fallback)', async () => {
    const group = createGroup('template_injection');
    await issueCreator.createIssuesFromGroups([group], config);

    expect(mockCreateIssue).toHaveBeenCalledTimes(1);
    const body = mockCreateIssue.mock.calls[0][2].body as string;

    // Should NOT contain the generic fallback
    expect(body).not.toContain(GENERIC_FALLBACK);
    // Should contain a template-specific description
    expect(body).toContain('template');
  });

  it('returns specific description for improper_input_validation (not generic fallback)', async () => {
    const group = createGroup('improper_input_validation');
    await issueCreator.createIssuesFromGroups([group], config);

    expect(mockCreateIssue).toHaveBeenCalledTimes(1);
    const body = mockCreateIssue.mock.calls[0][2].body as string;

    // Should NOT contain the generic fallback
    expect(body).not.toContain(GENERIC_FALLBACK);
    // Should contain an input-validation-specific description
    expect(body).toContain('input');
  });
});
