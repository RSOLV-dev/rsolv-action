/**
 * RED TESTS — executeMitigateForIssue phase data storage (RFC-096 Phase F.2 Step 8)
 *
 * Tests that executeMitigateForIssue stores mitigation results via storePhaseData
 * and includes backendOrchestrated marker + PR metadata.
 */
import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest';
import { PhaseExecutor } from '../index.js';
import type { ActionConfig, IssueContext, ScanPhaseData } from '../../../types/index.js';

// Mock GitHub API
vi.mock('../../../github/api.js', () => ({
  getIssue: vi.fn(),
  getIssues: vi.fn(),
  addLabels: vi.fn(),
  removeLabel: vi.fn(),
  getGitHubClient: vi.fn().mockReturnValue({
    rest: {
      pulls: {
        create: vi.fn().mockResolvedValue({ data: { number: 42, html_url: 'https://github.com/test-org/test-repo/pull/42' } }),
      },
      issues: {
        addLabels: vi.fn(),
        createComment: vi.fn(),
      },
      repos: {
        getBranch: vi.fn().mockRejectedValue(new Error('not found')),
      },
      git: {
        createRef: vi.fn(),
      },
    },
  }),
}));

// Mock PR creation
vi.mock('../../../github/pr-git-educational.js', () => ({
  createEducationalPullRequest: vi.fn().mockResolvedValue({
    success: true,
    pullRequestUrl: 'https://github.com/test-org/test-repo/pull/42',
    pullRequestNumber: 42,
    message: 'PR created',
  }),
}));

// Mock MitigationClient
vi.mock('../../../pipeline/mitigation-client.js', () => ({
  MitigationClient: vi.fn().mockImplementation(() => ({
    runMitigation: vi.fn().mockResolvedValue({
      success: true,
      title: 'fix: CWE-79 XSS in template rendering',
      description: 'Fixed XSS vulnerability by escaping user input',
    }),
  })),
}));

// Mock child_process for git operations
vi.mock('child_process', () => ({
  execSync: vi.fn().mockImplementation((cmd: string) => {
    if (cmd === 'git diff --name-only') return 'src/views/template.ts\n';
    if (cmd.startsWith('git config user.name') && !cmd.includes('"')) return 'Test User';
    if (cmd.startsWith('git add')) return '';
    if (cmd.startsWith('git commit')) return '';
    if (cmd === 'git rev-parse HEAD') return 'deadbeef1234\n';
    if (cmd.startsWith('git diff HEAD~1 --stat')) return ' 1 file changed, 3 insertions(+), 1 deletion(-)\n';
    return '';
  }),
}));

describe('executeMitigateForIssue phase data storage', () => {
  let executor: PhaseExecutor;
  let mockConfig: ActionConfig;
  let mockIssue: IssueContext;
  let mockScanData: ScanPhaseData;

  beforeEach(() => {
    vi.clearAllMocks();
    process.env.RSOLV_TESTING_MODE = 'true';

    mockConfig = {
      githubToken: 'test-token',
      repository: { owner: 'test-org', name: 'test-repo' },
      issueLabel: 'rsolv:detected',
      rsolvApiKey: 'test-api-key',
      maxIssues: 1,
      aiProvider: {
        name: 'claude-code',
        useVendedCredentials: true,
      },
      fixValidation: { enabled: false },
    } as ActionConfig;

    executor = new PhaseExecutor(mockConfig);

    mockIssue = {
      number: 7,
      title: 'CWE-79: XSS in template rendering',
      body: '#### `src/views/template.ts`\n- **Line 42**: Unescaped output',
      labels: ['rsolv:validated'],
      repository: { owner: 'test-org', name: 'test-repo' },
      url: 'https://github.com/test-org/test-repo/issues/7',
    };

    mockScanData = {
      analysisData: {
        issueType: 'security',
        vulnerabilityType: 'xss',
        severity: 'high',
        estimatedComplexity: 'moderate',
        suggestedApproach: 'Escape user input in templates',
        filesToModify: ['src/views/template.ts'],
        cwe: 'CWE-79',
        isAiGenerated: true,
      },
    } as unknown as ScanPhaseData;
  });

  afterEach(() => {
    delete process.env.RSOLV_TESTING_MODE;
  });

  test('stores mitigation phase data after successful PR creation', async () => {
    const storePhaseDataSpy = vi.spyOn(executor, 'storePhaseData' as any);

    const result = await executor.executeMitigateForIssue(mockIssue, mockScanData, null);

    expect(result.success).toBe(true);

    // Find the mitigation store call
    const mitigationStoreCall = storePhaseDataSpy.mock.calls.find(
      (call: unknown[]) => call[0] === 'mitigation'
    );

    expect(mitigationStoreCall).toBeDefined();

    const storedData = mitigationStoreCall![1] as Record<string, Record<string, unknown>>;
    const issueData = storedData['issue-7'];

    expect(issueData).toBeDefined();
    expect(issueData.fixed).toBe(true);
    expect(issueData.prUrl).toBe('https://github.com/test-org/test-repo/pull/42');
    expect(issueData.prNumber).toBe(42);
    expect(issueData.backendOrchestrated).toBe(true);
    expect(issueData.timestamp).toBeDefined();
  });

  test('includes PR metadata and diff stats in stored data', async () => {
    const storePhaseDataSpy = vi.spyOn(executor, 'storePhaseData' as any);

    await executor.executeMitigateForIssue(mockIssue, mockScanData, null);

    const mitigationStoreCall = storePhaseDataSpy.mock.calls.find(
      (call: unknown[]) => call[0] === 'mitigation'
    );

    const storedData = mitigationStoreCall![1] as Record<string, Record<string, unknown>>;
    const issueData = storedData['issue-7'];

    expect(issueData.filesModified).toEqual(['src/views/template.ts']);
    expect(issueData.commitHash).toBe('deadbeef1234');
  });

  test('passes repo and issue metadata to storePhaseData', async () => {
    const storePhaseDataSpy = vi.spyOn(executor, 'storePhaseData' as any);

    await executor.executeMitigateForIssue(mockIssue, mockScanData, null);

    const mitigationStoreCall = storePhaseDataSpy.mock.calls.find(
      (call: unknown[]) => call[0] === 'mitigation'
    );

    // Third arg is metadata
    const metadata = mitigationStoreCall![2] as Record<string, unknown>;
    expect(metadata.repo).toBe('test-org/test-repo');
    expect(metadata.issueNumber).toBe(7);
  });

  test('does not store phase data when mitigation fails', async () => {
    // Override the MitigationClient mock to fail
    const { MitigationClient } = await import('../../../pipeline/mitigation-client.js');
    (MitigationClient as unknown as ReturnType<typeof vi.fn>).mockImplementation(() => ({
      runMitigation: vi.fn().mockResolvedValue({
        success: false,
        error: 'Backend mitigation failed: timeout',
      }),
    }));

    const freshExecutor = new PhaseExecutor(mockConfig);
    const storePhaseDataSpy = vi.spyOn(freshExecutor, 'storePhaseData' as any);

    const result = await freshExecutor.executeMitigateForIssue(mockIssue, mockScanData, null);

    expect(result.success).toBe(false);

    const mitigationStoreCall = storePhaseDataSpy.mock.calls.find(
      (call: unknown[]) => call[0] === 'mitigation'
    );

    // Should NOT store when mitigation failed
    expect(mitigationStoreCall).toBeUndefined();
  });
});
