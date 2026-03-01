/**
 * Educational PR tests for PhaseExecutor
 *
 * HISTORY: This file originally contained 10 tests under describe.skip that tested the
 * deprecated executor.execute('mitigate', ...) -> processIssues -> createMitigationPR path.
 * That code path was replaced by RFC-096 backend-orchestrated pipeline:
 *   executeMitigateForIssue -> MitigationClient (SSE) -> createEducationalPullRequest
 *
 * COVERAGE: The educational content flow is now tested by:
 *   - src/github/__tests__/pr-git-educational.test.ts (16 tests)
 *     Tests createEducationalPullRequest directly: platform-provided content,
 *     generic fallback, CWE links, validation data, attack examples
 *   - mitigate-standalone.test.ts — executeMitigateStandalone delegates correctly
 *   - mitigate-for-issue-storage.test.ts — MITIGATE result storage
 *
 * This file tests the integration point: executeMitigateForIssue passes
 * educational_content from the SSE completion event to createEducationalPullRequest.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import type { ActionConfig, IssueContext } from '../../../types/index.js';

// vi.hoisted runs before vi.mock hoisting — safe to reference in factory functions
const { mockCreateEducationalPullRequest, mockRunMitigation } = vi.hoisted(() => ({
  mockCreateEducationalPullRequest: vi.fn().mockResolvedValue({
    success: true,
    pullRequestUrl: 'https://github.com/test/repo/pull/1',
    pullRequestNumber: 1,
    branchName: 'rsolv/fix-issue-42',
    commitHash: 'abc123',
    educationalContent: 'Platform-provided content',
  }),
  mockRunMitigation: vi.fn(),
}));

// Mock TestRunner
vi.mock('../../../ai/test-runner.js', () => ({
  TestRunner: vi.fn().mockImplementation(() => ({
    ensureRuntime: vi.fn().mockResolvedValue(undefined),
    runTests: vi.fn(),
  })),
}));

// Track what createEducationalPullRequest receives
vi.mock('../../../github/pr-git-educational.js', () => ({
  createEducationalPullRequest: mockCreateEducationalPullRequest,
}));

// Mock GitHub API
vi.mock('../../../github/api.js', () => ({
  getIssue: vi.fn(),
  getIssues: vi.fn(),
  addLabels: vi.fn(),
  removeLabel: vi.fn(),
  getGitHubClient: vi.fn().mockReturnValue({
    rest: {
      pulls: { create: vi.fn().mockResolvedValue({ data: { number: 1, html_url: '' } }) },
      issues: { addLabels: vi.fn(), createComment: vi.fn() },
      repos: { getBranch: vi.fn().mockRejectedValue(new Error('not found')) },
      git: { createRef: vi.fn() },
    },
  }),
}));

// Mock MitigationClient — returns educational_content from platform Registry
vi.mock('../../../pipeline/mitigation-client.js', () => ({
  MitigationClient: vi.fn().mockImplementation(() => ({
    runMitigation: mockRunMitigation,
  })),
}));

// Mock child_process for git operations
vi.mock('child_process', () => ({
  exec: vi.fn(),
  execSync: vi.fn().mockImplementation((cmd: string) => {
    if (cmd === 'git diff --name-only') return 'src/config.py\n';
    if (cmd === 'git rev-parse HEAD') return 'abc123def456\n';
    if (cmd.startsWith('git config user.name') && !cmd.includes('"')) return 'Test User';
    if (cmd.startsWith('git add')) return '';
    if (cmd.startsWith('git commit')) return '';
    if (cmd.startsWith('git diff HEAD~1 --stat')) return ' 1 file changed, 3 insertions(+), 1 deletion(-)\n';
    return '';
  }),
}));

// Import PhaseExecutor AFTER mocks are set up
import { PhaseExecutor } from '../index.js';

describe('PhaseExecutor Educational PR — SSE integration', () => {
  let executor: PhaseExecutor;
  let mockConfig: ActionConfig;

  const mockIssue: IssueContext = {
    number: 42,
    title: 'CWE-798: Hardcoded API key in config.py',
    body: '#### `src/config.py`\n- **Line 8**: Hardcoded API key detected',
    labels: ['rsolv:detected'],
    repository: { owner: 'test-owner', name: 'test-repo' },
    url: 'https://github.com/test-owner/test-repo/issues/42',
  };

  const platformEducation = {
    title: 'Hardcoded Credentials',
    description: 'Hardcoded credentials (passwords, API keys, tokens) in source code can be extracted by attackers who gain access to the codebase.',
    prevention: 'Store secrets in environment variables or a secrets manager. Never commit credentials to version control.',
  };

  beforeEach(() => {
    vi.clearAllMocks();
    process.env.RSOLV_TESTING_MODE = 'true';
    process.env.GITHUB_SHA = 'abc123';

    mockConfig = {
      rsolvApiKey: 'rsolv_test_key_123',
      githubToken: 'github_test_token',
      aiProvider: { name: 'claude-code', useVendedCredentials: true },
      repository: { owner: 'test-owner', name: 'test-repo' },
      issueLabel: 'rsolv:detected',
      maxIssues: 1,
      fixValidation: { enabled: false },
    } as ActionConfig;

    // Default: MitigationClient returns result WITH educational_content from platform
    mockRunMitigation.mockResolvedValue({
      success: true,
      title: 'fix: Replace hardcoded API key with env var',
      description: 'Replaced hardcoded API key with os.environ lookup',
      educational_content: platformEducation,
    });

    executor = new PhaseExecutor(mockConfig);

    // Mock scan data retrieval (VALIDATE data from prior phase)
    executor.retrievePhaseData = vi.fn().mockResolvedValue({
      validation: {
        'issue-42': {
          validated: true,
          classification: 'validated',
          backendOrchestrated: true,
        },
      },
    });
  });

  afterEach(() => {
    delete process.env.RSOLV_TESTING_MODE;
    delete process.env.GITHUB_SHA;
  });

  describe('platform-provided educational content', () => {
    it('passes educational_content from SSE result to createEducationalPullRequest', async () => {
      await executor.executeMitigateForIssue(mockIssue, {
        analysisData: {
          issueType: 'hardcoded_secrets',
          vulnerabilityType: 'hardcoded_secrets',
          severity: 'high',
          cwe: 'CWE-798',
          canBeFixed: true,
        },
      }, undefined);

      expect(mockCreateEducationalPullRequest).toHaveBeenCalledTimes(1);

      // 3rd argument is the summary object — should include educationalContent
      const summary = mockCreateEducationalPullRequest.mock.calls[0][2];
      expect(summary.educationalContent).toEqual(platformEducation);
      expect(summary.educationalContent.title).toBe('Hardcoded Credentials');
      expect(summary.educationalContent.prevention).toContain('environment variables');
    });

    it('passes CWE from scan data to createEducationalPullRequest summary', async () => {
      await executor.executeMitigateForIssue(mockIssue, {
        analysisData: {
          issueType: 'hardcoded_secrets',
          vulnerabilityType: 'hardcoded_secrets',
          severity: 'high',
          cwe: 'CWE-798',
          canBeFixed: true,
        },
      }, undefined);

      const summary = mockCreateEducationalPullRequest.mock.calls[0][2];
      expect(summary.cwe).toBe('CWE-798');
    });

    it('passes issue context as first argument', async () => {
      await executor.executeMitigateForIssue(mockIssue, {
        analysisData: {
          issueType: 'hardcoded_secrets',
          vulnerabilityType: 'hardcoded_secrets',
          severity: 'high',
          cwe: 'CWE-798',
          canBeFixed: true,
        },
      }, undefined);

      const issueArg = mockCreateEducationalPullRequest.mock.calls[0][0];
      expect(issueArg.number).toBe(42);
      expect(issueArg.title).toContain('CWE-798');
    });

    it('passes config as fourth argument', async () => {
      await executor.executeMitigateForIssue(mockIssue, {
        analysisData: {
          issueType: 'hardcoded_secrets',
          vulnerabilityType: 'hardcoded_secrets',
          severity: 'high',
          cwe: 'CWE-798',
          canBeFixed: true,
        },
      }, undefined);

      const configArg = mockCreateEducationalPullRequest.mock.calls[0][3];
      expect(configArg.rsolvApiKey).toBe('rsolv_test_key_123');
      expect(configArg.githubToken).toBe('github_test_token');
    });
  });

  describe('missing educational content (generic fallback)', () => {
    it('passes undefined educationalContent when platform omits it', async () => {
      // Backend returns result WITHOUT educational_content
      mockRunMitigation.mockResolvedValue({
        success: true,
        title: 'fix: Remove eval usage',
        description: 'Replaced eval with safe alternative',
        // No educational_content — unknown CWE or platform didn't enrich
      });

      await executor.executeMitigateForIssue(mockIssue, {
        analysisData: {
          issueType: 'code_injection',
          vulnerabilityType: 'code_injection',
          severity: 'critical',
          cwe: 'CWE-94',
          canBeFixed: true,
        },
      }, undefined);

      const summary = mockCreateEducationalPullRequest.mock.calls[0][2];
      // educationalContent should be undefined — createEducationalPullRequest
      // will call buildGenericEducation internally
      expect(summary.educationalContent).toBeUndefined();
    });

    it('still creates PR successfully without platform educational content', async () => {
      mockRunMitigation.mockResolvedValue({
        success: true,
        title: 'fix: Sanitize input',
        description: 'Added input validation',
      });

      const result = await executor.executeMitigateForIssue(mockIssue, {
        analysisData: {
          issueType: 'xss',
          vulnerabilityType: 'xss',
          severity: 'high',
          cwe: 'CWE-79',
          canBeFixed: true,
        },
      }, undefined);

      expect(result.success).toBe(true);
      expect(mockCreateEducationalPullRequest).toHaveBeenCalledTimes(1);
    });
  });

  describe('diff stats forwarding', () => {
    it('passes diff stats to createEducationalPullRequest', async () => {
      await executor.executeMitigateForIssue(mockIssue, {
        analysisData: {
          issueType: 'hardcoded_secrets',
          vulnerabilityType: 'hardcoded_secrets',
          severity: 'high',
          cwe: 'CWE-798',
          canBeFixed: true,
        },
      }, undefined);

      // 5th argument is diffStats
      const diffStats = mockCreateEducationalPullRequest.mock.calls[0][4];
      expect(diffStats).toBeDefined();
      expect(diffStats.filesChanged).toBeGreaterThanOrEqual(1);
      expect(typeof diffStats.insertions).toBe('number');
      expect(typeof diffStats.deletions).toBe('number');
    });
  });

  describe('mitigation failure', () => {
    it('returns failure when MitigationClient reports no success', async () => {
      mockRunMitigation.mockResolvedValue({
        success: false,
        error: 'Max turns reached without resolution',
      });

      const result = await executor.executeMitigateForIssue(mockIssue, {
        analysisData: {
          issueType: 'sql_injection',
          vulnerabilityType: 'sql_injection',
          severity: 'critical',
          cwe: 'CWE-89',
          canBeFixed: true,
        },
      }, undefined);

      expect(result.success).toBe(false);
      expect(mockCreateEducationalPullRequest).not.toHaveBeenCalled();
    });
  });

  describe('result storage', () => {
    it('stores mitigation result with backendOrchestrated flag', async () => {
      const storePhaseDataSpy = vi.spyOn(executor, 'storePhaseData' as never);

      await executor.executeMitigateForIssue(mockIssue, {
        analysisData: {
          issueType: 'hardcoded_secrets',
          vulnerabilityType: 'hardcoded_secrets',
          severity: 'high',
          cwe: 'CWE-798',
          canBeFixed: true,
        },
      }, undefined);

      const mitigationStoreCall = storePhaseDataSpy.mock.calls.find(
        (call: unknown[]) => call[0] === 'mitigation'
      );

      expect(mitigationStoreCall).toBeDefined();
      const storedData = mitigationStoreCall![1] as Record<string, Record<string, unknown>>;
      const issueData = storedData['issue-42'];
      expect(issueData).toBeDefined();
      expect(issueData.backendOrchestrated).toBe(true);
      expect(issueData.prUrl).toBe('https://github.com/test/repo/pull/1');
    });
  });
});
