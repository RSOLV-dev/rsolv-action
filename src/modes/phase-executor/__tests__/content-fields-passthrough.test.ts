/**
 * RED TESTS — Content fields (fix_summary, changes_explanation, risk_assessment) passthrough
 *
 * Verifies that when the backend mitigation returns content fields,
 * they are included in the storePhaseData call to the platform.
 */
import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest';
import { PhaseExecutor } from '../index.js';
import type { ActionConfig, IssueContext, ScanPhaseData } from '../../../types/index.js';

// Mock TestRunner
vi.mock('../../../ai/test-runner.js', () => ({
  TestRunner: vi.fn().mockImplementation(() => ({
    ensureRuntime: vi.fn().mockResolvedValue(undefined),
    runTests: vi.fn(),
  })),
}));

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

// Mock MitigationClient to return content fields
vi.mock('../../../pipeline/mitigation-client.js', () => ({
  MitigationClient: vi.fn().mockImplementation(() => ({
    runMitigation: vi.fn().mockResolvedValue({
      success: true,
      title: 'fix: CWE-79 XSS in template rendering',
      description: 'Fixed XSS vulnerability by escaping user input',
      fix_summary: 'Escaped all user-provided template variables using contextual output encoding.',
      changes_explanation: 'Line-level: Added htmlEscape() calls around 3 template interpolations in views/template.ts.\nConcept-level: Applied contextual output encoding to prevent XSS.\nBusiness-level: User-generated content can no longer execute scripts in other users\' browsers.',
      risk_assessment: 'Before: Any user input rendered in templates could execute arbitrary JavaScript. After: All dynamic content is escaped, eliminating reflected and stored XSS vectors.',
    }),
  })),
}));

// Mock child_process
vi.mock('child_process', () => ({
  exec: vi.fn(),
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

describe('content fields passthrough to platform', () => {
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

  test('stores fix_summary in mitigation phase data', async () => {
    const storePhaseDataSpy = vi.spyOn(executor, 'storePhaseData' as never);

    await executor.executeMitigateForIssue(mockIssue, mockScanData, null);

    const mitigationStoreCall = storePhaseDataSpy.mock.calls.find(
      (call: unknown[]) => call[0] === 'mitigation'
    );

    expect(mitigationStoreCall).toBeDefined();
    const storedData = mitigationStoreCall![1] as Record<string, Record<string, unknown>>;
    const issueData = storedData['issue-7'];

    expect(issueData.fix_summary).toBe(
      'Escaped all user-provided template variables using contextual output encoding.'
    );
  });

  test('stores changes_explanation in mitigation phase data', async () => {
    const storePhaseDataSpy = vi.spyOn(executor, 'storePhaseData' as never);

    await executor.executeMitigateForIssue(mockIssue, mockScanData, null);

    const mitigationStoreCall = storePhaseDataSpy.mock.calls.find(
      (call: unknown[]) => call[0] === 'mitigation'
    );

    const storedData = mitigationStoreCall![1] as Record<string, Record<string, unknown>>;
    const issueData = storedData['issue-7'];

    expect(issueData.changes_explanation).toContain('htmlEscape()');
  });

  test('stores risk_assessment in mitigation phase data', async () => {
    const storePhaseDataSpy = vi.spyOn(executor, 'storePhaseData' as never);

    await executor.executeMitigateForIssue(mockIssue, mockScanData, null);

    const mitigationStoreCall = storePhaseDataSpy.mock.calls.find(
      (call: unknown[]) => call[0] === 'mitigation'
    );

    const storedData = mitigationStoreCall![1] as Record<string, Record<string, unknown>>;
    const issueData = storedData['issue-7'];

    expect(issueData.risk_assessment).toContain('eliminating reflected and stored XSS');
  });

  test('omits content fields when backend does not return them', async () => {
    // Override mock to return no content fields
    const { MitigationClient } = await import('../../../pipeline/mitigation-client.js');
    (MitigationClient as unknown as ReturnType<typeof vi.fn>).mockImplementation(() => ({
      runMitigation: vi.fn().mockResolvedValue({
        success: true,
        title: 'fix: basic fix',
        description: 'Fixed it',
      }),
    }));

    const freshExecutor = new PhaseExecutor(mockConfig);
    const storePhaseDataSpy = vi.spyOn(freshExecutor, 'storePhaseData' as never);

    await freshExecutor.executeMitigateForIssue(mockIssue, mockScanData, null);

    const mitigationStoreCall = storePhaseDataSpy.mock.calls.find(
      (call: unknown[]) => call[0] === 'mitigation'
    );

    const storedData = mitigationStoreCall![1] as Record<string, Record<string, unknown>>;
    const issueData = storedData['issue-7'];

    // Fields should not be present (not even as undefined keys)
    expect(issueData.fix_summary).toBeUndefined();
    expect(issueData.changes_explanation).toBeUndefined();
    expect(issueData.risk_assessment).toBeUndefined();
  });
});
