/**
 * Tests for executeMitigate credential handling (RFC-096 Phase F.2).
 *
 * Verifies that executeMitigate correctly passes credentials to the
 * backend MitigationClient and fails gracefully when API key is missing.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { PhaseExecutor } from '../index.js';
import { ActionConfig } from '../../../types/index.js';

// Mock TestRunner to prevent ensureRuntime from hanging
vi.mock('../../../ai/test-runner.js', () => ({
  TestRunner: vi.fn().mockImplementation(() => ({
    ensureRuntime: vi.fn().mockResolvedValue(undefined),
    runTests: vi.fn(),
  })),
}));

// Mock MitigationClient to capture config
const mockRunMitigation = vi.fn();
vi.mock('../../../pipeline/mitigation-client.js', () => ({
  MitigationClient: vi.fn().mockImplementation((config: { apiKey: string; baseUrl: string }) => ({
    runMitigation: mockRunMitigation.mockImplementation(() => {
      // If no API key, simulate auth failure
      if (!config.apiKey) {
        return Promise.resolve({
          success: false,
          error: 'Failed to start mitigation session: RSOLV_API_KEY is required',
        });
      }
      return Promise.resolve({
        success: true,
        title: 'fix: test vulnerability',
        description: 'Fixed test vulnerability',
      });
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
    if (cmd.startsWith('git config user.name') && !cmd.includes('"')) return 'Test User';
    if (cmd.startsWith('git add')) return '';
    if (cmd.startsWith('git commit')) return '';
    if (cmd === 'git rev-parse HEAD') return 'abc123\n';
    if (cmd.startsWith('git diff HEAD~1 --stat')) return ' 1 file changed, 2 insertions(+)\n';
    return '';
  }),
}));

describe('PhaseExecutor - Mitigate Phase Credential Handling', () => {
  let executor: PhaseExecutor;
  let mockConfig: ActionConfig;

  beforeEach(() => {
    vi.clearAllMocks();
    process.env.RSOLV_TESTING_MODE = 'true';

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

    executor = new PhaseExecutor(mockConfig);
  });

  afterEach(() => {
    delete process.env.RSOLV_TESTING_MODE;
  });

  it('should pass rsolvApiKey to MitigationClient when delegating to backend', async () => {
    // Mock GitHub API to return an issue
    const githubApiModule = await import('../../../github/api.js');
    (githubApiModule.getIssue as ReturnType<typeof vi.fn>).mockResolvedValue({
      id: 'issue-1',
      number: 123,
      title: 'CWE-79: XSS vulnerability',
      body: '#### `file.js`\n- **Line 10**: XSS found',
      labels: [{ name: 'rsolv:validated' }],
      created_at: '2026-01-01T00:00:00Z',
      updated_at: '2026-01-01T00:00:00Z',
    });

    // Mock phase data retrieval
    executor.phaseDataClient.retrievePhaseResults = vi.fn().mockResolvedValue({
      validation: {
        'issue-123': {
          validated: true,
          classification: 'validated',
          backendOrchestrated: true,
        },
      },
    });

    const result = await executor.executeMitigate({
      repository: { owner: 'test-owner', name: 'test-repo', defaultBranch: 'main' },
      issueNumber: 123,
    });

    // MitigationClient should have been constructed with the API key
    const { MitigationClient } = await import('../../../pipeline/mitigation-client.js');
    expect(MitigationClient).toHaveBeenCalledWith(
      expect.objectContaining({
        apiKey: 'rsolv_test_key_123',
      })
    );

    expect(result.success).toBe(true);
  });

  it('should fail gracefully when rsolvApiKey is missing', async () => {
    // Remove rsolvApiKey
    delete (mockConfig as Record<string, unknown>).rsolvApiKey;

    const executorNoKey = new PhaseExecutor(mockConfig);

    // Mock GitHub API
    const githubApiModule = await import('../../../github/api.js');
    (githubApiModule.getIssue as ReturnType<typeof vi.fn>).mockResolvedValue({
      id: 'issue-1',
      number: 123,
      title: 'CWE-79: XSS vulnerability',
      body: '#### `file.js`\n- **Line 10**: XSS found',
      labels: [{ name: 'rsolv:validated' }],
      created_at: '2026-01-01T00:00:00Z',
      updated_at: '2026-01-01T00:00:00Z',
    });

    // Mock phase data retrieval
    executorNoKey.phaseDataClient.retrievePhaseResults = vi.fn().mockResolvedValue({
      validation: {
        'issue-123': {
          validated: true,
          classification: 'validated',
          backendOrchestrated: true,
        },
      },
    });

    const result = await executorNoKey.executeMitigate({
      repository: { owner: 'test-owner', name: 'test-repo', defaultBranch: 'main' },
      issueNumber: 123,
    });

    // Should fail because MitigationClient got an undefined apiKey
    expect(result.success).toBe(false);
    expect(result.error).toBeDefined();
  });
});
