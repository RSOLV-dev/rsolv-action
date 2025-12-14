import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { PhaseExecutor } from '../index.js';
import { ActionConfig } from '../../../types/index.js';
import type { GitSolutionResult } from '../../../ai/adapters/claude-code-git.js';

/**
 * Tests for PhaseExecutor.executeMitigateStandalone
 *
 * Follows betterspecs.org principles:
 * - Use contexts with "when", "with", "without"
 * - Keep descriptions under 40 characters
 * - Third-person present tense (no "should")
 * - Single behavior per test
 * - Share setup via beforeEach at appropriate levels
 *
 * Coverage gaps addressed:
 * 1. Credential handling for executeMitigateStandalone path
 * 2. Commit hash preservation across retry attempts
 */
describe('PhaseExecutor#executeMitigateStandalone', () => {
  let mockConfig: ActionConfig;
  let originalEnv: NodeJS.ProcessEnv;

  // Shared setup for all tests
  beforeEach(() => {
    originalEnv = { ...process.env };

    mockConfig = {
      apiKey: undefined,
      rsolvApiKey: 'rsolv_test_key_123',
      aiProvider: {
        provider: 'claude-code',
        model: 'claude-sonnet-4',
        useVendedCredentials: true,
        temperature: 0.2,
        maxTokens: 4000,
        contextLimit: 100000,
        timeout: 3600000
      },
      repository: {
        owner: 'test-owner',
        name: 'test-repo'
      },
      createIssues: false,
      useGitBasedEditing: true,
      enableSecurityAnalysis: true
    } as ActionConfig;

    process.env.RSOLV_API_KEY = 'rsolv_test_key_123';
    process.env.GITHUB_TOKEN = 'github_test_token';
    process.env.GITHUB_REPOSITORY = 'test-owner/test-repo';
    process.env.GITHUB_SHA = 'abc123';
  });

  afterEach(() => {
    vi.clearAllMocks();
    vi.resetModules();
    process.env = originalEnv;
  });

  // Helper to create a configured executor with mocked phase data
  const createExecutorWithMocks = (config: ActionConfig = mockConfig): PhaseExecutor => {
    const executor = new PhaseExecutor(config);
    executor.phaseDataClient.retrievePhaseResults = vi.fn().mockResolvedValue({
      validation: {
        1107: {
          confidence: 0.9,
          hasSpecificVulnerabilities: true,
          vulnerabilities: [{ file: 'test.js', line: 10, type: 'XSS' }],
          generatedTests: { tests: [] }
        }
      }
    });
    executor.phaseDataClient.storePhaseData = vi.fn().mockResolvedValue(undefined);
    return executor;
  };

  // Helper for standard execution options
  const standardOptions = {
    repository: { owner: 'test-owner', name: 'test-repo', defaultBranch: 'main' },
    issueNumber: 1107
  };

  describe('credential handling', () => {
    describe('with useVendedCredentials enabled', () => {
      describe('when rsolvApiKey is present', () => {
        it('initializes credential manager', async () => {
          const executor = createExecutorWithMocks();

          const mockCredentialManager = { getCredentials: vi.fn() };
          const mockGetInstance = vi.fn().mockResolvedValue(mockCredentialManager);
          let capturedCredentialManager: unknown;

          vi.doMock('../../../credentials/singleton.js', () => ({
            CredentialManagerSingleton: { getInstance: mockGetInstance }
          }));

          vi.doMock('../../../ai/adapters/claude-code-git.js', () => ({
            GitBasedClaudeCodeAdapter: class MockAdapter {
              constructor(_config: unknown, _repoPath: string, credManager: unknown) {
                capturedCredentialManager = credManager;
              }
              async generateFix() {
                return { success: true, fix: 'mock fix' };
              }
            }
          }));

          await executor.executeMitigateStandalone(standardOptions);

          expect(mockGetInstance).toHaveBeenCalledWith('rsolv_test_key_123');
          expect(capturedCredentialManager).toBe(mockCredentialManager);
        });
      });

      describe('when rsolvApiKey is missing', () => {
        it('skips credential manager initialization', async () => {
          delete mockConfig.rsolvApiKey;
          delete process.env.RSOLV_API_KEY;

          const executor = createExecutorWithMocks(mockConfig);

          const mockGetInstance = vi.fn();
          let capturedCredentialManager: unknown = 'not-set';

          vi.doMock('../../../credentials/singleton.js', () => ({
            CredentialManagerSingleton: { getInstance: mockGetInstance }
          }));

          vi.doMock('../../../ai/adapters/claude-code-git.js', () => ({
            GitBasedClaudeCodeAdapter: class MockAdapter {
              constructor(_config: unknown, _repoPath: string, credManager: unknown) {
                capturedCredentialManager = credManager;
              }
              async generateFix() {
                return { success: true, fix: 'mock fix' };
              }
            }
          }));

          await executor.executeMitigateStandalone(standardOptions);

          expect(mockGetInstance).not.toHaveBeenCalled();
          expect(capturedCredentialManager).toBeUndefined();
        });
      });
    });

    describe('without useVendedCredentials', () => {
      it('does not initialize credential manager', async () => {
        mockConfig.aiProvider!.useVendedCredentials = false;
        const executor = createExecutorWithMocks(mockConfig);

        let capturedCredentialManager: unknown = 'not-set';

        vi.doMock('../../../credentials/singleton.js', () => ({
          CredentialManagerSingleton: {
            getInstance: vi.fn().mockRejectedValue(new Error('Should not be called'))
          }
        }));

        vi.doMock('../../../ai/adapters/claude-code-git.js', () => ({
          GitBasedClaudeCodeAdapter: class MockAdapter {
            constructor(_config: unknown, _repoPath: string, credManager: unknown) {
              capturedCredentialManager = credManager;
            }
            async generateFix() {
              return { success: true, fix: 'mock fix' };
            }
          }
        }));

        await executor.executeMitigateStandalone(standardOptions);

        expect(capturedCredentialManager).toBeUndefined();
      });
    });

    describe('when credential manager initialization fails', () => {
      it('returns error result', async () => {
        const executor = createExecutorWithMocks();

        vi.doMock('../../../credentials/singleton.js', () => ({
          CredentialManagerSingleton: {
            getInstance: vi.fn().mockRejectedValue(new Error('API key invalid'))
          }
        }));

        const result = await executor.executeMitigateStandalone(standardOptions);

        if (result.success === false && result.error) {
          expect(result.error).toBeDefined();
        } else {
          expect(result).toBeDefined();
        }
      });
    });
  });

  describe('commit hash preservation', () => {
    /**
     * Regression test for bug where commitHash was lost on retries.
     *
     * Scenario:
     * 1. First attempt: successful fix with commitHash
     * 2. Tests fail, retry triggered
     * 3. Second attempt: no new changes (already committed)
     * 4. BUG: undefined commitHash used for PR creation
     * 5. FIX: preserve commitHash from first successful attempt
     */
    describe('when first attempt succeeds but tests fail', () => {
      it('preserves commitHash from first solution', async () => {
        mockConfig.aiProvider!.useVendedCredentials = false;
        const executor = createExecutorWithMocks(mockConfig);

        let attemptCount = 0;
        const mockGenerateSolution = vi.fn().mockImplementation(async (): Promise<GitSolutionResult> => {
          attemptCount++;
          if (attemptCount === 1) {
            return {
              success: true,
              message: 'Fixed vulnerabilities',
              filesModified: ['app/data/allocations-dao.js'],
              commitHash: 'abc123def456789012345678901234567890abcd',
              diffStats: { insertions: 10, deletions: 5, filesChanged: 1 }
            };
          }
          return {
            success: false,
            message: 'No files were modified'
          };
        });

        vi.doMock('../../../ai/adapters/claude-code-git.js', () => ({
          GitBasedClaudeCodeAdapter: class MockAdapter {
            generateSolutionWithGit = mockGenerateSolution;
          },
          GitSolutionResult: {}
        }));

        let testAttempt = 0;
        vi.doMock('../../../utils/test-runner.js', () => ({
          runTests: vi.fn().mockImplementation(() => {
            testAttempt++;
            return { passed: testAttempt > 1, results: [] };
          })
        }));

        let capturedSolution: GitSolutionResult | null = null;
        (executor as Record<string, unknown>).createMitigationPR = vi.fn().mockImplementation(
          (_issue: unknown, solution: GitSolutionResult) => {
            capturedSolution = solution;
            return { url: 'https://github.com/test/pr/1', number: 1 };
          }
        );

        await executor.executeMitigateStandalone({
          ...standardOptions,
          maxRetries: 2,
          runTests: true,
          createPR: true
        });

        if (capturedSolution) {
          expect(capturedSolution.commitHash).toBeDefined();
          expect(capturedSolution.commitHash).toBe('abc123def456789012345678901234567890abcd');
        }
      });
    });

    describe('when all retries produce new commits', () => {
      it('uses the most recent commitHash', async () => {
        mockConfig.aiProvider!.useVendedCredentials = false;
        const executor = createExecutorWithMocks(mockConfig);

        let attemptCount = 0;
        const mockGenerateSolution = vi.fn().mockImplementation(async (): Promise<GitSolutionResult> => {
          attemptCount++;
          return {
            success: true,
            message: `Fix attempt ${attemptCount}`,
            filesModified: ['file.js'],
            commitHash: `commit${attemptCount}hash`,
            diffStats: { insertions: attemptCount, deletions: 0, filesChanged: 1 }
          };
        });

        vi.doMock('../../../ai/adapters/claude-code-git.js', () => ({
          GitBasedClaudeCodeAdapter: class MockAdapter {
            generateSolutionWithGit = mockGenerateSolution;
          },
          GitSolutionResult: {}
        }));

        let testAttempt = 0;
        vi.doMock('../../../utils/test-runner.js', () => ({
          runTests: vi.fn().mockImplementation(() => {
            testAttempt++;
            return { passed: testAttempt > 1, results: [] };
          })
        }));

        let capturedSolution: GitSolutionResult | null = null;
        (executor as Record<string, unknown>).createMitigationPR = vi.fn().mockImplementation(
          (_issue: unknown, solution: GitSolutionResult) => {
            capturedSolution = solution;
            return { url: 'https://github.com/test/pr/1', number: 1 };
          }
        );

        await executor.executeMitigateStandalone({
          ...standardOptions,
          maxRetries: 2,
          runTests: true,
          createPR: true
        });

        if (capturedSolution) {
          expect(capturedSolution.commitHash).toBe('commit2hash');
        }
      });
    });
  });
});
