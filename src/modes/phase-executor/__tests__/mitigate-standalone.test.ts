/**
 * Tests for PhaseExecutor.executeMitigateStandalone (RFC-096 Phase F.2)
 *
 * Verifies that executeMitigateStandalone correctly:
 * 1. Retrieves validation data from PhaseDataClient
 * 2. Delegates to executeMitigateForIssue for backend-orchestrated mitigation
 * 3. Handles missing validation data gracefully
 * 4. Stores aggregate results
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { ActionConfig } from '../../../types/index.js';

// Mock TestRunner to prevent ensureRuntime from hanging
vi.mock('../../../ai/test-runner.js', () => ({
  TestRunner: vi.fn().mockImplementation(() => ({
    ensureRuntime: vi.fn().mockResolvedValue(undefined),
    runTests: vi.fn(),
  })),
}));

// Mock MitigationClient
vi.mock('../../../pipeline/mitigation-client.js', () => ({
  MitigationClient: vi.fn().mockImplementation(() => ({
    runMitigation: vi.fn().mockResolvedValue({
      success: true,
      title: 'fix: test vulnerability',
      description: 'Fixed vulnerability',
    }),
  })),
}));

// Mock PR creation
vi.mock('../../../github/pr-git-educational.js', () => ({
  createEducationalPullRequest: vi.fn().mockResolvedValue({
    success: true,
    pullRequestUrl: 'https://github.com/test-owner/test-repo/pull/1',
    pullRequestNumber: 1,
    message: 'PR created',
  }),
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

// Mock child_process for git operations
vi.mock('child_process', () => ({
  exec: vi.fn(),
  execSync: vi.fn().mockImplementation((cmd: string) => {
    if (cmd === 'git diff --name-only') return 'src/fix.ts\n';
    if (cmd === 'git rev-parse HEAD') return 'abc123\n';
    if (cmd.startsWith('git config user.name') && !cmd.includes('"')) return 'Test User';
    if (cmd.startsWith('git add')) return '';
    if (cmd.startsWith('git commit')) return '';
    if (cmd.startsWith('git diff HEAD~1 --stat')) return ' 1 file changed, 2 insertions(+)\n';
    return '';
  }),
}));

// Import PhaseExecutor AFTER setting up mocks
import { PhaseExecutor } from '../index.js';

describe('PhaseExecutor#executeMitigateStandalone', () => {
  let mockConfig: ActionConfig;

  beforeEach(() => {
    vi.clearAllMocks();
    process.env.RSOLV_TESTING_MODE = 'true';
    process.env.GITHUB_SHA = 'abc123';

    mockConfig = {
      rsolvApiKey: 'rsolv_test_key_123',
      githubToken: 'github_test_token',
      aiProvider: {
        name: 'claude-code',
        useVendedCredentials: true,
      },
      repository: { owner: 'test-owner', name: 'test-repo' },
      issueLabel: 'rsolv:detected',
      maxIssues: 1,
      fixValidation: { enabled: false },
    } as ActionConfig;
  });

  afterEach(() => {
    delete process.env.RSOLV_TESTING_MODE;
    delete process.env.GITHUB_SHA;
  });

  const createExecutorWithMocks = (config: ActionConfig = mockConfig): PhaseExecutor => {
    const executor = new PhaseExecutor(config);
    executor.phaseDataClient.retrievePhaseResults = vi.fn().mockResolvedValue({
      validation: {
        'issue-1107': {
          validated: true,
          classification: 'validated',
          backendOrchestrated: true,
        },
      },
    });
    return executor;
  };

  describe('credential handling', () => {
    it('passes rsolvApiKey to MitigationClient via executeMitigateForIssue', async () => {
      const executor = createExecutorWithMocks();

      await executor.executeMitigateStandalone({
        repository: { owner: 'test-owner', name: 'test-repo', defaultBranch: 'main' },
        issueNumber: 1107,
      });

      // MitigationClient should receive the API key
      const { MitigationClient } = await import('../../../pipeline/mitigation-client.js');
      expect(MitigationClient).toHaveBeenCalledWith(
        expect.objectContaining({ apiKey: 'rsolv_test_key_123' })
      );
    });

    it('handles missing rsolvApiKey gracefully', async () => {
      delete (mockConfig as Record<string, unknown>).rsolvApiKey;
      const executor = createExecutorWithMocks(mockConfig);

      const result = await executor.executeMitigateStandalone({
        repository: { owner: 'test-owner', name: 'test-repo', defaultBranch: 'main' },
        issueNumber: 1107,
      });

      // The backend client will fail when API key is missing
      expect(result).toBeDefined();
    });
  });

  describe('validation data retrieval', () => {
    it('retrieves validation data from PhaseDataClient', async () => {
      const executor = createExecutorWithMocks();

      await executor.executeMitigateStandalone({
        repository: { owner: 'test-owner', name: 'test-repo', defaultBranch: 'main' },
        issueNumber: 1107,
      });

      expect(executor.phaseDataClient.retrievePhaseResults).toHaveBeenCalledWith(
        'test-owner/test-repo',
        1107,
        expect.any(String)
      );
    });

    it('returns error when no validation data available', async () => {
      const executor = new PhaseExecutor(mockConfig);
      executor.phaseDataClient.retrievePhaseResults = vi.fn().mockResolvedValue(null);

      const result = await executor.executeMitigateStandalone({
        repository: { owner: 'test-owner', name: 'test-repo', defaultBranch: 'main' },
        issueNumber: 1107,
      });

      expect(result.success).toBe(false);
      expect(result.error).toContain('validation data');
    });
  });

  describe('backend delegation', () => {
    it('delegates to executeMitigateForIssue for each issue', async () => {
      const executor = createExecutorWithMocks();
      const spy = vi.spyOn(executor, 'executeMitigateForIssue');

      await executor.executeMitigateStandalone({
        repository: { owner: 'test-owner', name: 'test-repo', defaultBranch: 'main' },
        issueNumber: 1107,
      });

      expect(spy).toHaveBeenCalledTimes(1);
    });
  });
});
