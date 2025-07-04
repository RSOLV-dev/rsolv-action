/**
 * Tests for fix validation integration in git-based-processor
 * TDD Phase: RED - Writing failing tests first
 */

import { describe, it, expect, beforeEach, afterEach, mock } from 'bun:test';
import { processIssueWithGit } from '../git-based-processor.js';
import { TestGeneratingSecurityAnalyzer } from '../test-generating-security-analyzer.js';
import { GitBasedTestValidator } from '../git-based-test-validator.js';
import { GitBasedClaudeCodeAdapter } from '../adapters/claude-code-git.js';
import { IssueContext, ActionConfig } from '../../types/index.js';
import { execSync } from 'child_process';

// Mock modules
mock.module('../test-generating-security-analyzer.js', () => ({
  TestGeneratingSecurityAnalyzer: mock()
}));

mock.module('../git-based-test-validator.js', () => ({
  GitBasedTestValidator: mock()
}));

mock.module('../adapters/claude-code-git.js', () => ({
  GitBasedClaudeCodeAdapter: mock()
}));

mock.module('../../github/pr-git.js', () => ({
  createPullRequestFromGit: mock()
}));

mock.module('child_process', () => ({
  execSync: mock()
}));

describe('Git-based processor with fix validation', () => {
  let mockConfig: ActionConfig;
  let mockIssue: IssueContext;
  let mockTestSuite: any;
  let mockValidationResult: any;

  beforeEach(() => {
    // Setup test data
    mockConfig = {
      apiKey: 'test-key',
      configPath: '',
      issueLabel: 'security',
      aiProvider: {
        provider: 'anthropic',
        model: 'claude-3',
        apiKey: 'test-key'
      },
      containerConfig: { enabled: false },
      securitySettings: {},
      enableSecurityAnalysis: true,
      fixValidation: {
        enabled: true,
        maxIterations: 3
      }
    };

    mockIssue = {
      id: 'test-1',
      number: 1,
      title: 'Security vulnerability',
      body: 'Found eval() usage',
      labels: ['security'],
      assignees: [],
      repository: {
        owner: 'test',
        name: 'repo',
        fullName: 'test/repo',
        defaultBranch: 'main',
        language: 'javascript'
      },
      source: 'test',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    };

    mockTestSuite = {
      red: {
        testName: 'should be vulnerable',
        testCode: 'test code',
        expectedBehavior: 'fails'
      },
      green: {
        testName: 'should be fixed',
        testCode: 'test code',
        expectedBehavior: 'passes'
      },
      refactor: {
        testName: 'should maintain functionality',
        testCode: 'test code',
        expectedBehavior: 'passes'
      }
    };

    mockValidationResult = {
      success: true,
      vulnerableCommit: {
        redTestPassed: false,
        greenTestPassed: false,
        refactorTestPassed: true
      },
      fixedCommit: {
        redTestPassed: true,
        greenTestPassed: true,
        refactorTestPassed: true
      },
      isValidFix: true
    };

    // Reset all mocks
    (execSync as any).mockClear();
  });

  describe('when fix validation is enabled', () => {
    it('should generate tests before creating fix', async () => {
      // Arrange
      const mockTestAnalyzer = {
        analyzeWithTestGeneration: mock().mockResolvedValue({
          canBeFixed: true,
          generatedTests: {
            success: true,
            testSuite: mockTestSuite,
            tests: [{
              framework: 'mocha',
              testCode: 'test code',
              testSuite: mockTestSuite
            }]
          }
        })
      };

      (TestGeneratingSecurityAnalyzer as any).mockReturnValue(mockTestAnalyzer);
      (execSync as any).mockReturnValue(''); // Clean git status

      // Act
      await processIssueWithGit(mockIssue, mockConfig);

      // Assert
      expect(mockTestAnalyzer.analyzeWithTestGeneration).toHaveBeenCalledWith(
        mockIssue,
        mockConfig,
        expect.any(Map)
      );
    });

    it('should validate fix after generation', async () => {
      // Arrange
      const mockValidator = {
        validateFixWithTests: mock().mockResolvedValue(mockValidationResult)
      };

      const mockAdapter = {
        generateSolutionWithGit: mock().mockResolvedValue({
          success: true,
          commitHash: 'abc123',
          message: 'Fixed vulnerability',
          filesModified: ['file.js']
        })
      };

      (GitBasedTestValidator as any).mockReturnValue(mockValidator);
      (GitBasedClaudeCodeAdapter as any).mockReturnValue(mockAdapter);
      (execSync as any).mockReturnValue(''); // Clean git status

      // Act
      await processIssueWithGit(mockIssue, mockConfig);

      // Assert
      expect(mockValidator.validateFixWithTests).toHaveBeenCalledWith(
        expect.any(String), // before commit
        'abc123', // after commit
        mockTestSuite
      );
    });

    it('should retry with enhanced context when validation fails', async () => {
      // Arrange
      const failedValidation = {
        ...mockValidationResult,
        isValidFix: false,
        fixedCommit: {
          redTestPassed: false, // Fix didn't work
          greenTestPassed: false,
          refactorTestPassed: true
        }
      };

      const mockValidator = {
        validateFixWithTests: mock()
          .mockResolvedValueOnce(failedValidation) // First attempt fails
          .mockResolvedValueOnce(mockValidationResult) // Second attempt succeeds
      };

      const mockAdapter = {
        generateSolutionWithGit: mock().mockResolvedValue({
          success: true,
          commitHash: 'abc123',
          message: 'Fixed vulnerability',
          filesModified: ['file.js']
        })
      };

      (GitBasedTestValidator as any).mockReturnValue(mockValidator);
      (GitBasedClaudeCodeAdapter as any).mockReturnValue(mockAdapter);

      // Act
      await processIssueWithGit(mockIssue, mockConfig);

      // Assert
      expect(mockAdapter.generateSolutionWithGit).toHaveBeenCalledTimes(2);
      
      // Check second call has enhanced context
      const secondCallIssue = mockAdapter.generateSolutionWithGit.mock.calls[1][0];
      expect(secondCallIssue.body).toContain('Previous Fix Attempt Failed');
      expect(secondCallIssue.body).toContain('RED test failed');
    });

    it('should respect configurable iteration limits', async () => {
      // Arrange
      mockConfig.fixValidation!.maxIterations = 2;
      
      const failedValidation = {
        ...mockValidationResult,
        isValidFix: false
      };

      const mockValidator = {
        validateFixWithTests: mock().mockResolvedValue(failedValidation)
      };

      const mockAdapter = {
        generateSolutionWithGit: mock().mockResolvedValue({
          success: true,
          commitHash: 'abc123',
          message: 'Fixed vulnerability'
        })
      };

      (GitBasedTestValidator as any).mockReturnValue(mockValidator);
      (GitBasedClaudeCodeAdapter as any).mockReturnValue(mockAdapter);

      // Act
      const result = await processIssueWithGit(mockIssue, mockConfig);

      // Assert
      expect(mockAdapter.generateSolutionWithGit).toHaveBeenCalledTimes(2); // Not 3
      expect(result.success).toBe(false);
      expect(result.message).toContain('failed after 2 attempts');
    });

    it('should use label-based iteration override', async () => {
      // Arrange
      mockIssue.labels = ['security', 'fix-validation-max-5'];
      
      const failedValidation = {
        ...mockValidationResult,
        isValidFix: false
      };

      const mockValidator = {
        validateFixWithTests: mock().mockResolvedValue(failedValidation)
      };

      const mockAdapter = {
        generateSolutionWithGit: mock().mockResolvedValue({
          success: true,
          commitHash: 'abc123',
          message: 'Fixed'
        })
      };

      (GitBasedTestValidator as any).mockReturnValue(mockValidator);
      (GitBasedClaudeCodeAdapter as any).mockReturnValue(mockAdapter);

      // Act
      const result = await processIssueWithGit(mockIssue, mockConfig);

      // Assert
      expect(mockAdapter.generateSolutionWithGit).toHaveBeenCalledTimes(5);
      expect(result.message).toContain('failed after 5 attempts');
    });

    it('should rollback changes when all iterations fail', async () => {
      // Arrange
      const failedValidation = {
        ...mockValidationResult,
        isValidFix: false
      };

      const mockValidator = {
        validateFixWithTests: mock().mockResolvedValue(failedValidation)
      };

      (GitBasedTestValidator as any).mockReturnValue(mockValidator);
      (execSync as any).mockReturnValue(''); // For git commands

      // Act
      await processIssueWithGit(mockIssue, mockConfig);

      // Assert
      expect(execSync).toHaveBeenCalledWith(
        expect.stringContaining('git reset --hard'),
        expect.any(Object)
      );
    });

    it('should skip validation when disabled', async () => {
      // Arrange
      mockConfig.fixValidation = { enabled: false };
      
      const mockValidator = {
        validateFixWithTests: mock()
      };

      (GitBasedTestValidator as any).mockReturnValue(mockValidator);

      // Act
      await processIssueWithGit(mockIssue, mockConfig);

      // Assert
      expect(mockValidator.validateFixWithTests).not.toHaveBeenCalled();
    });

    it('should create PR only when validation passes', async () => {
      // Arrange
      const mockCreatePR = mock().mockResolvedValue({
        success: true,
        pullRequestUrl: 'https://github.com/test/repo/pull/1',
        pullRequestNumber: 1
      });

      mock.module('../../github/pr-git.js', () => ({
        createPullRequestFromGit: mockCreatePR
      }));

      const mockValidator = {
        validateFixWithTests: mock().mockResolvedValue(mockValidationResult)
      };

      (GitBasedTestValidator as any).mockReturnValue(mockValidator);

      // Act
      const result = await processIssueWithGit(mockIssue, mockConfig);

      // Assert
      expect(mockCreatePR).toHaveBeenCalled();
      expect(result.success).toBe(true);
      expect(result.pullRequestUrl).toBeDefined();
    });

    it('should include test code in enhanced context', async () => {
      // Arrange
      const failedValidation = {
        ...mockValidationResult,
        isValidFix: false
      };

      const mockTestAnalyzer = {
        analyzeWithTestGeneration: mock().mockResolvedValue({
          canBeFixed: true,
          generatedTests: {
            success: true,
            testSuite: mockTestSuite,
            tests: [{
              framework: 'jest',
              testCode: 'describe("security", () => { /* tests */ })',
              testSuite: mockTestSuite
            }]
          }
        })
      };

      const mockAdapter = {
        generateSolutionWithGit: mock().mockResolvedValue({
          success: true,
          commitHash: 'abc123'
        })
      };

      (TestGeneratingSecurityAnalyzer as any).mockReturnValue(mockTestAnalyzer);
      (GitBasedClaudeCodeAdapter as any).mockReturnValue(mockAdapter);
      (GitBasedTestValidator as any).mockReturnValue({
        validateFixWithTests: mock().mockResolvedValue(failedValidation)
      });

      // Act
      await processIssueWithGit(mockIssue, mockConfig);

      // Assert
      const enhancedCall = mockAdapter.generateSolutionWithGit.mock.calls[1];
      expect(enhancedCall[0].body).toContain('describe("security"');
      expect(enhancedCall[0].body).toContain('Generated Test Code:');
    });

    it('should handle vulnerability type specific limits', async () => {
      // Arrange
      mockConfig.fixValidation = {
        enabled: true,
        maxIterations: 3,
        maxIterationsByType: {
          'sql-injection': 5,
          'command-injection': 4
        }
      };

      mockIssue.body = 'SQL injection vulnerability in user input';

      const failedValidation = {
        ...mockValidationResult,
        isValidFix: false
      };

      const mockValidator = {
        validateFixWithTests: mock().mockResolvedValue(failedValidation)
      };

      (GitBasedTestValidator as any).mockReturnValue(mockValidator);

      // Act
      const result = await processIssueWithGit(mockIssue, mockConfig);

      // Assert
      expect(result.message).toContain('failed after 5 attempts'); // SQL injection limit
    });
  });
});