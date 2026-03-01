/**
 * Tests for phase decomposition of processIssueWithGit
 * Testing the extracted phases from processIssueWithGit
 *
 * RFC-096 Phase F: Tests updated to use backend-orchestrated pipeline.
 * VALIDATE uses ValidationClient (SSE → backend).
 * MITIGATE uses MitigationClient (SSE → backend).
 */

import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest';
import { PhaseExecutor } from '../phase-executor/index.js';
import { IssueContext, ActionConfig } from '../../types/index.js';

// Use vi.hoisted for mocks that need to be available during module initialization
const { mockExecSync, mockAnalyzeIssue, mockRunValidation, mockRunMitigation } = vi.hoisted(() => {
  const execSync = vi.fn((cmd: string) => {
    if (cmd.includes('git status')) {
      return ''; // Clean status
    }
    if (cmd.includes('git rev-parse HEAD')) {
      return 'abc123def456';
    }
    if (cmd.includes('git diff --name-only')) {
      return 'user.js\n'; // Modified files from backend mitigation
    }
    if (cmd.includes('git config user.name') && !cmd.includes('"')) {
      return 'RSOLV[bot]';
    }
    if (cmd.includes('git diff HEAD~1 --stat')) {
      return ' 1 file changed, 10 insertions(+), 5 deletions(-)';
    }
    return '';
  });

  const analyzeIssue = vi.fn(() => Promise.resolve({
    canBeFixed: true,
    issueType: 'sql-injection',
    filesToModify: ['user.js'],
    suggestedApproach: 'Use parameterized queries',
    estimatedComplexity: 'medium',
    vulnerabilityType: 'SQL_INJECTION',
    severity: 'high'
  }));

  const runValidation = vi.fn(() => Promise.resolve({
    validated: true,
    test_path: 'test/sql-injection.test.js',
    test_code: 'assert(vulnerabilityExists())',
    framework: 'jest',
    cwe_id: 'CWE-89',
  }));

  const runMitigation = vi.fn(() => Promise.resolve({
    success: true,
    title: 'Fix SQL injection in user.js',
    description: 'Used parameterized queries',
    files_mentioned: ['user.js'],
  }));

  return {
    mockExecSync: execSync,
    mockAnalyzeIssue: analyzeIssue,
    mockRunValidation: runValidation,
    mockRunMitigation: runMitigation,
  };
});

// Mock child_process at module level
vi.mock('child_process', () => ({
  execSync: mockExecSync,
  exec: vi.fn((cmd: string, callback: (err: Error | null, result: { stdout: string; stderr: string }) => void) => {
    callback(null, { stdout: '', stderr: '' });
  })
}));

// Mock analyzer at module level
vi.mock('../../ai/analyzer.js', () => ({
  analyzeIssue: mockAnalyzeIssue
}));

// Mock ValidationClient (RFC-096: backend-orchestrated pipeline)
vi.mock('../../pipeline/validation-client.js', () => ({
  ValidationClient: class {
    constructor() {}
    async runValidation(context: unknown) {
      return mockRunValidation(context);
    }
  },
}));

// Mock MitigationClient (RFC-096: backend-orchestrated pipeline)
vi.mock('../../pipeline/mitigation-client.js', () => ({
  MitigationClient: class {
    constructor() {}
    async runMitigation(context: unknown) {
      return mockRunMitigation(context);
    }
  },
}));

// Mock ClaudeAgentSDKAdapter (RFC-095: still used in standalone execution paths)
vi.mock('../../ai/adapters/claude-agent-sdk.js', () => ({
  ClaudeAgentSDKAdapter: class {
    constructor() {}
    async generateSolutionWithGit() {
      return {
        success: true,
        commitHash: 'fix-commit-123',
        summary: { title: 'Fix SQL injection' },
        filesModified: ['user.js'],
        diffStats: { insertions: 10, deletions: 5, filesChanged: 1 }
      };
    }
  },
  GitSolutionResult: {},
  createClaudeAgentSDKAdapter: () => ({
    async generateSolutionWithGit() {
      return {
        success: true,
        commitHash: 'fix-commit-123',
        summary: { title: 'Fix SQL injection' },
        filesModified: ['user.js'],
        diffStats: { insertions: 10, deletions: 5, filesChanged: 1 }
      };
    }
  })
}));

// Mock PR creation functions
vi.mock('../../github/pr-git-educational.js', () => ({
  createEducationalPullRequest: vi.fn(() => Promise.resolve({
    success: true,
    pullRequestUrl: 'https://github.com/test/repo/pull/1',
    pullRequestNumber: 1
  }))
}));

vi.mock('../../github/pr-git.js', () => ({
  createPullRequestFromGit: vi.fn(() => Promise.resolve({
    success: true,
    pullRequestUrl: 'https://github.com/test/repo/pull/1',
    pullRequestNumber: 1
  }))
}));

describe('Phase Decomposition - processIssueWithGit refactoring', () => {
  let executor: PhaseExecutor;
  let mockConfig: ActionConfig;
  let mockIssue: IssueContext;

  beforeEach(() => {
    // Reset mocks
    vi.clearAllMocks();

    // Reset the mock implementations
    mockExecSync.mockImplementation((cmd: string) => {
      if (cmd.includes('git status')) {
        return ''; // Clean status
      }
      if (cmd.includes('git rev-parse HEAD')) {
        return 'abc123def456';
      }
      if (cmd.includes('git diff --name-only')) {
        return 'user.js\n';
      }
      if (cmd.includes('git config user.name') && !cmd.includes('"')) {
        return 'RSOLV[bot]';
      }
      if (cmd.includes('git diff HEAD~1 --stat')) {
        return ' 1 file changed, 10 insertions(+), 5 deletions(-)';
      }
      return '';
    });

    // Reset backend client mocks to defaults
    mockRunValidation.mockResolvedValue({
      validated: true,
      test_path: 'test/sql-injection.test.js',
      test_code: 'assert(vulnerabilityExists())',
      framework: 'jest',
      cwe_id: 'CWE-89',
    });

    mockRunMitigation.mockResolvedValue({
      success: true,
      title: 'Fix SQL injection in user.js',
      description: 'Used parameterized queries',
      files_mentioned: ['user.js'],
    });

    mockConfig = {
      aiProvider: {
        provider: 'anthropic',
        apiKey: 'test-key',
        model: 'claude-3',
        maxTokens: 4000
      },
      rsolvApiKey: 'rsolv_test_key_123',
      enableSecurityAnalysis: true,
      fixValidation: {
        enabled: true,
        maxIterations: 3
      },
      testGeneration: {
        enabled: true,
        validateFixes: true
      }
    } as ActionConfig;

    mockIssue = {
      id: 'issue-123',
      number: 123,
      title: 'SQL Injection in user.js',
      body: 'Found SQL injection vulnerability',
      labels: ['rsolv:automate'],
      assignees: [],
      repository: {
        owner: 'test',
        name: 'repo',
        fullName: 'test/repo',
        defaultBranch: 'main',
        language: 'JavaScript'
      },
      source: 'github',
      createdAt: '2025-08-06T10:00:00Z',
      updatedAt: '2025-08-06T10:00:00Z',
      metadata: {}
    };

    executor = new PhaseExecutor(mockConfig);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('Scan Phase Extraction', () => {
    test('executeScanForIssue should analyze issue and determine if fixable', async () => {
      // This method doesn't exist yet - RED phase
      const result = await executor.executeScanForIssue(mockIssue);
      
      expect(result.success).toBe(true);
      expect(result.phase).toBe('scan');
      expect(result.data).toHaveProperty('canBeFixed');
      expect(result.data).toHaveProperty('analysisData');
      expect(result.data).toHaveProperty('gitStatus');
    });

    test('executeScanForIssue should fail if git has uncommitted changes', async () => {
      // Mock dirty git state
      const mockCheckGitStatus = vi.fn(() => ({
        clean: false,
        modifiedFiles: ['file1.js', 'file2.js']
      }));
      
      executor.checkGitStatus = mockCheckGitStatus;
      
      const result = await executor.executeScanForIssue(mockIssue);
      
      expect(result.success).toBe(false);
      expect(result.error).toContain('Uncommitted changes');
    });

    test('executeScanForIssue returns scan result (RFC-126: storage is server-side)', async () => {
      const result = await executor.executeScanForIssue(mockIssue);

      expect(result.success).toBe(true);
      expect(result.data).toBeDefined();
    });
  });

  describe('Validate Phase Extraction', () => {
    test('executeValidateForIssue should generate tests via backend pipeline', async () => {
      const scanData = {
        analysisData: {
          canBeFixed: true,
          issueType: 'sql-injection',
          filesToModify: ['user.js']
        }
      };

      const result = await executor.executeValidateForIssue(mockIssue, scanData);

      expect(result.success).toBe(true);
      expect(result.phase).toBe('validate');
      expect(result.data).toHaveProperty('validation');
      // RFC-096: keyed as `issue_${number}`
      const issueKey = `issue_${mockIssue.number}`;
      expect(result.data.validation).toHaveProperty(issueKey);
      expect(result.data.validation[issueKey]).toHaveProperty('validated', true);
      expect(result.data.validation[issueKey]).toHaveProperty('test_path', 'test/sql-injection.test.js');
      expect(result.data.validation[issueKey]).toHaveProperty('framework');
    });

    test('executeValidateForIssue should call ValidationClient.runValidation', async () => {
      const scanData = {
        analysisData: {
          canBeFixed: true,
          filesToModify: ['user.js']
        }
      };

      const result = await executor.executeValidateForIssue(mockIssue, scanData);

      expect(mockRunValidation).toHaveBeenCalledTimes(1);
      expect(mockRunValidation).toHaveBeenCalledWith(
        expect.objectContaining({
          vulnerability: expect.objectContaining({
            location: 'user.js',
          }),
        })
      );
      const issueKey = `issue_${mockIssue.number}`;
      expect(result.data.validation[issueKey]).toHaveProperty('validated', true);
      expect(result.data.validation[issueKey].test_code).toBeDefined();
    });

    test('executeValidateForIssue should return failure when validation rejects', async () => {
      mockRunValidation.mockResolvedValueOnce({
        validated: false,
        error: 'Test did not prove vulnerability is exploitable',
      });

      const scanData = {
        analysisData: {
          canBeFixed: true,
          filesToModify: ['user.js']
        }
      };

      const result = await executor.executeValidateForIssue(mockIssue, scanData);

      expect(result.success).toBe(false);
      expect(result.phase).toBe('validate');
      expect(result.message).toContain('did not prove vulnerability');
    });
  });

  describe('Mitigate Phase Extraction', () => {
    test('executeMitigateForIssue should apply fix via backend pipeline', async () => {
      const validationData = {
        validation: {
          [`issue_${mockIssue.number}`]: {
            validated: true,
            test_path: 'test/sql-injection.test.js',
            test_code: 'assert(vulnerabilityExists())',
            framework: 'jest',
            cwe_id: 'CWE-89',
          },
        },
      };

      const scanData = {
        analysisData: {
          canBeFixed: true,
          issueType: 'sql-injection',
          suggestedApproach: 'Use parameterized queries',
          vulnerabilityType: 'SQL_INJECTION',
          severity: 'high',
        }
      };

      const result = await executor.executeMitigateForIssue(
        mockIssue,
        scanData,
        validationData
      );

      expect(result.success).toBe(true);
      expect(result.phase).toBe('mitigate');
      // RFC-096: data contains PR info at top level
      expect(result.data).toHaveProperty('pullRequestUrl');
      expect(result.data).toHaveProperty('commitHash');
      expect(result.data).toHaveProperty('backendOrchestrated', true);
    });

    test('executeMitigateForIssue should call MitigationClient.runMitigation', async () => {
      const validationData = {
        validation: {
          [`issue_${mockIssue.number}`]: {
            validated: true,
            test_path: 'test/sql-injection.test.js',
            test_code: 'assert(vulnerabilityExists())',
            framework: 'jest',
          },
        },
      };

      const scanData = {
        analysisData: {
          canBeFixed: true
        }
      };

      await executor.executeMitigateForIssue(mockIssue, scanData, validationData);

      expect(mockRunMitigation).toHaveBeenCalledTimes(1);
      expect(mockRunMitigation).toHaveBeenCalledWith(
        expect.objectContaining({
          issue: expect.objectContaining({
            number: mockIssue.number,
          }),
          repoPath: expect.any(String),
        })
      );
    });

    test('executeMitigateForIssue should fail when backend mitigation fails', async () => {
      mockRunMitigation.mockResolvedValueOnce({
        success: false,
        error: 'Anthropic API rate limit exceeded',
      });

      const validationData = {
        validation: {
          [`issue_${mockIssue.number}`]: {
            validated: true,
          },
        },
      };

      const scanData = {
        analysisData: {
          canBeFixed: true
        }
      };

      const result = await executor.executeMitigateForIssue(
        mockIssue,
        scanData,
        validationData
      );

      expect(result.success).toBe(false);
      expect(result.phase).toBe('mitigate');
    });
  });

  describe('Full Three-Phase Execution', () => {
    test('executeThreePhaseForIssue should run all phases sequentially', async () => {
      // RFC-096: Backend pipeline mocks are set up in beforeEach via
      // mockRunValidation and mockRunMitigation — no client-side mocking needed.

      const result = await executor.executeThreePhaseForIssue(mockIssue);

      expect(result.success).toBe(true);
      expect(result.phase).toBe('three-phase');
      expect(result.data).toHaveProperty('scan');
      expect(result.data).toHaveProperty('validation');
      expect(result.data).toHaveProperty('mitigation');
    });

    test('executeThreePhaseForIssue should abort if scan determines not fixable', async () => {
      executor.executeScanForIssue = vi.fn(() => Promise.resolve({
        success: true,
        phase: 'scan',
        data: {
          canBeFixed: false,
          analysisData: {
            canBeFixed: false,
            reason: 'Too complex'
          }
        }
      }));
      
      const result = await executor.executeThreePhaseForIssue(mockIssue);
      
      expect(result.success).toBe(false);
      expect(result.message).toContain('cannot be fixed');
      expect(result.data).not.toHaveProperty('validation');
      expect(result.data).not.toHaveProperty('mitigation');
    });

    test('executeThreePhaseForIssue should pass data between phases', async () => {
      const scanSpy = vi.fn(() => Promise.resolve({
        success: true,
        phase: 'scan',
        data: { canBeFixed: true, analysisData: { test: 'scan' } }
      }));
      
      const validateSpy = vi.fn(() => Promise.resolve({
        success: true,
        phase: 'validate',
        data: { generatedTests: { test: 'validate' } }
      }));
      
      const mitigateSpy = vi.fn(() => Promise.resolve({
        success: true,
        phase: 'mitigate',
        data: { pullRequestUrl: 'https://github.com/pr/1' }
      }));
      
      executor.executeScanForIssue = scanSpy;
      executor.executeValidateForIssue = validateSpy;
      executor.executeMitigateForIssue = mitigateSpy;
      
      await executor.executeThreePhaseForIssue(mockIssue);
      
      // Validate should receive scan data
      expect(validateSpy).toHaveBeenCalledWith(
        mockIssue,
        expect.objectContaining({ analysisData: { test: 'scan' } })
      );
      
      // Mitigate should receive both scan and validation data
      expect(mitigateSpy).toHaveBeenCalledWith(
        mockIssue,
        expect.objectContaining({ analysisData: { test: 'scan' } }),
        expect.objectContaining({ generatedTests: { test: 'validate' } })
      );
    });
  });

});