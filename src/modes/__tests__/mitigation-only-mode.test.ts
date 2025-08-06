/**
 * Tests for mitigation-only mode
 * Following TDD: RED → GREEN → REFACTOR
 * These tests should FAIL initially (RED phase)
 */

import { describe, test, expect, beforeEach, afterEach, mock } from 'bun:test';
import { PhaseExecutor } from '../phase-executor/index.js';
import { IssueContext, ActionConfig } from '../../types/index.js';

describe('Mitigation-Only Mode', () => {
  let executor: PhaseExecutor;
  let mockConfig: ActionConfig;
  let mockIssue: IssueContext;
  let mockValidationData: any;

  beforeEach(() => {
    // Clean up mocks to prevent pollution
    mock.restore();
    
    // Mock Claude Code adapter to prevent actual execution
    mock.module('../../ai/adapters/claude-code-git.js', () => ({
      GitBasedClaudeCodeAdapter: class {
        async generateSolutionWithGit() {
          return {
            success: true,
            prUrl: 'https://github.com/test/webapp/pull/790',
            fixCommit: 'abc123',
            filesModified: ['src/user.js']
          };
        }
      }
    }));
    
    // Mock git status to be clean
    mock.module('child_process', () => ({
      execSync: mock((cmd: string) => {
        if (cmd.includes('git status --porcelain')) {
          return ''; // Clean status
        }
        if (cmd.includes('git rev-parse HEAD')) {
          return 'abc123def456';
        }
        return '';
      })
    }));
    
    mockConfig = {
      aiProvider: {
        provider: 'anthropic',
        apiKey: 'test-key',
        model: 'claude-3',
        maxTokens: 4000
      },
      enableSecurityAnalysis: true,
      testGeneration: {
        enabled: true,
        validateFixes: true // Need to validate fixes work
      },
      github: {
        token: 'test-token',
        owner: 'test',
        repo: 'webapp'
      }
    } as ActionConfig;

    mockIssue = {
      id: 'issue-789',
      number: 789,
      title: 'SQL Injection in user query',
      body: 'User input not properly parameterized',
      labels: ['rsolv:automate', 'security'],
      assignees: [],
      repository: {
        owner: 'test',
        name: 'webapp',
        fullName: 'test/webapp',
        defaultBranch: 'main',
        language: 'JavaScript'
      },
      source: 'github',
      createdAt: '2025-08-06T14:00:00Z',
      updatedAt: '2025-08-06T14:00:00Z',
      metadata: {}
    };

    // Mock validation data from prior phase
    mockValidationData = {
      validation: {
        'issue-789': {
          issueNumber: 789,
          validated: true,
          generatedTests: {
            success: true,
            tests: [
              {
                name: 'should detect SQL injection vulnerability',
                code: `test('should fail with SQL injection', () => {
                  const result = getUserById("1' OR '1'='1");
                  expect(result).toContain('OR');
                });`,
                type: 'red'
              },
              {
                name: 'should pass when properly parameterized',
                code: `test('should use parameterized queries', () => {
                  const result = getUserById("1");
                  expect(result.query).toContain('?');
                });`,
                type: 'green'
              }
            ],
            redTest: 'should detect SQL injection vulnerability',
            greenTest: 'should pass when properly parameterized'
          },
          analysisData: {
            issueType: 'security',
            filesToModify: ['src/user.js'],
            estimatedComplexity: 'medium',
            canBeFixed: true,
            suggestedApproach: 'Use parameterized queries'
          },
          timestamp: '2025-08-06T14:30:00Z'
        }
      }
    };

    executor = new PhaseExecutor(mockConfig);
  });

  afterEach(() => {
    mock.restore();
  });

  describe('Basic Execution', () => {
    test('should execute mitigation with validation data from prior phase', async () => {
      // RED: This test should fail - executeMitigateStandalone doesn't exist yet
      const result = await executor.executeMitigateStandalone({
        issues: [mockIssue],
        validationData: mockValidationData
      });

      expect(result.success).toBe(true);
      expect(result.phase).toBe('mitigate');
      expect(result.data).toHaveProperty('mitigation');
    });

    test('should handle missing validation data gracefully', async () => {
      // RED: Should fail - method doesn't exist
      const result = await executor.executeMitigateStandalone({
        issues: [mockIssue]
      });

      expect(result.success).toBe(false);
      expect(result.error).toContain('No validation data');
    });

    test('should retrieve validation data from PhaseDataClient if not provided', async () => {
      // Mock phase data retrieval
      const mockPhaseData = {
        validation: mockValidationData.validation,
        scan: { canBeFixed: true }
      };

      mock.module('../phase-data-client/index.js', () => ({
        PhaseDataClient: class {
          async retrievePhaseResults() {
            return mockPhaseData;
          }
          async storePhaseResults() {
            return { success: true };
          }
        }
      }));

      // RED: Method doesn't exist yet
      const result = await executor.executeMitigateStandalone({
        repository: mockIssue.repository,
        issueNumber: 789,
        usePriorValidation: true
      });

      expect(result.success).toBe(true);
      expect(result.data.mitigation).toBeDefined();
    });
  });

  describe('Fix Application', () => {
    test('should apply fix using GitBasedClaudeCodeAdapter', async () => {
      // Mock the adapter
      mock.module('../../ai/adapters/claude-code-git.js', () => ({
        GitBasedClaudeCodeAdapter: class {
          async generateSolutionWithGit() {
            return {
              success: true,
              prUrl: 'https://github.com/test/webapp/pull/790',
              fixCommit: 'abc123'
            };
          }
        }
      }));

      // RED: Method doesn't exist
      const result = await executor.executeMitigateStandalone({
        issues: [mockIssue],
        validationData: mockValidationData
      });

      expect(result.success).toBe(true);
      expect(result.data.mitigation['issue-789'].prUrl).toBe('https://github.com/test/webapp/pull/790');
    });

    test('should verify tests pass after fix (GREEN phase)', async () => {
      // Mock test runner
      mock.module('../../utils/test-runner.js', () => ({
        runTests: async () => ({
          passed: true,
          failed: 0,
          total: 2
        })
      }));

      // RED: Method doesn't exist
      const result = await executor.executeMitigateStandalone({
        issues: [mockIssue],
        validationData: mockValidationData,
        runTests: true
      });

      expect(result.success).toBe(true);
      expect(result.data.mitigation['issue-789'].testsPass).toBe(true);
    });

    test('should retry fix if tests fail', async () => {
      let attemptCount = 0;
      
      // Mock test runner to fail first time, pass second
      mock.module('../../utils/test-runner.js', () => ({
        runTests: async () => {
          attemptCount++;
          return {
            passed: attemptCount > 1,
            failed: attemptCount > 1 ? 0 : 1,
            total: 2
          };
        }
      }));

      // RED: Method doesn't exist
      const result = await executor.executeMitigateStandalone({
        issues: [mockIssue],
        validationData: mockValidationData,
        runTests: true,
        maxRetries: 3
      });

      expect(result.success).toBe(true);
      expect(attemptCount).toBe(2); // Should retry once
    });

    test('should refactor code to match codebase style', async () => {
      // RED: Method doesn't exist
      const result = await executor.executeMitigateStandalone({
        issues: [mockIssue],
        validationData: mockValidationData,
        refactorStyle: true
      });

      expect(result.success).toBe(true);
      expect(result.data.mitigation['issue-789'].refactored).toBe(true);
    });
  });

  describe('PR Creation', () => {
    test('should create educational PR with test results', async () => {
      // Mock GitHub API
      mock.module('../../utils/github-client.js', () => ({
        createPullRequest: async () => ({
          number: 790,
          url: 'https://github.com/test/webapp/pull/790',
          title: 'Fix SQL Injection vulnerability'
        })
      }));

      // RED: Method doesn't exist
      const result = await executor.executeMitigateStandalone({
        issues: [mockIssue],
        validationData: mockValidationData,
        createPR: true,
        prType: 'educational'
      });

      expect(result.success).toBe(true);
      expect(result.data.mitigation['issue-789'].prCreated).toBe(true);
      expect(result.data.mitigation['issue-789'].prType).toBe('educational');
    });

    test('should include before/after code in PR description', async () => {
      let prDescription = '';
      
      // Mock GitHub to capture PR description
      mock.module('../../utils/github-client.js', () => ({
        createPullRequest: async (options: any) => {
          prDescription = options.body;
          return {
            number: 790,
            url: 'https://github.com/test/webapp/pull/790'
          };
        }
      }));

      // RED: Method doesn't exist
      const result = await executor.executeMitigateStandalone({
        issues: [mockIssue],
        validationData: mockValidationData,
        createPR: true,
        includeBeforeAfter: true
      });

      expect(result.success).toBe(true);
      expect(prDescription).toContain('Before');
      expect(prDescription).toContain('After');
    });

    test('should add security education context to PR', async () => {
      let prDescription = '';
      
      // Mock GitHub
      mock.module('../../utils/github-client.js', () => ({
        createPullRequest: async (options: any) => {
          prDescription = options.body;
          return {
            number: 790,
            url: 'https://github.com/test/webapp/pull/790'
          };
        }
      }));

      // RED: Method doesn't exist
      const result = await executor.executeMitigateStandalone({
        issues: [mockIssue],
        validationData: mockValidationData,
        createPR: true,
        prType: 'educational'
      });

      expect(result.success).toBe(true);
      expect(prDescription).toContain('vulnerability');
      expect(prDescription).toContain('security');
      expect(prDescription).toContain('Learn more');
    });
  });

  describe('Multiple Issues', () => {
    test('should handle multiple issues in batch', async () => {
      const issue2 = { ...mockIssue, number: 791, id: 'issue-791' };
      const validation2 = {
        validation: {
          'issue-791': {
            ...mockValidationData.validation['issue-789'],
            issueNumber: 791
          }
        }
      };

      const combinedValidation = {
        validation: {
          ...mockValidationData.validation,
          ...validation2.validation
        }
      };

      // RED: Method doesn't exist
      const result = await executor.executeMitigateStandalone({
        issues: [mockIssue, issue2],
        validationData: combinedValidation
      });

      expect(result.success).toBe(true);
      expect(Object.keys(result.data.mitigation)).toHaveLength(2);
      expect(result.data.mitigation['issue-789']).toBeDefined();
      expect(result.data.mitigation['issue-791']).toBeDefined();
    });

    test('should handle partial failures gracefully', async () => {
      const issue2 = { ...mockIssue, number: 791, id: 'issue-791' };
      
      // Make second issue fail
      mock.module('../../ai/adapters/claude-code-git.js', () => ({
        GitBasedClaudeCodeAdapter: class {
          async generateSolutionWithGit(issue: any) {
            if (issue.number === 791) {
              throw new Error('Failed to generate fix');
            }
            return {
              success: true,
              prUrl: 'https://github.com/test/webapp/pull/790'
            };
          }
        }
      }));

      // RED: Method doesn't exist
      const result = await executor.executeMitigateStandalone({
        issues: [mockIssue, issue2],
        validationData: {
          validation: {
            'issue-789': mockValidationData.validation['issue-789'],
            'issue-791': mockValidationData.validation['issue-789'] // Reuse for simplicity
          }
        }
      });

      expect(result.success).toBe(false); // Overall fails
      expect(result.partial).toBe(true); // But partial success
      expect(result.data.mitigation['issue-789'].success).toBe(true);
      expect(result.data.mitigation['issue-791'].success).toBe(false);
    });
  });

  describe('Error Handling', () => {
    test('should handle missing AI adapter gracefully', async () => {
      // Remove AI config
      executor = new PhaseExecutor({
        ...mockConfig,
        aiProvider: undefined
      } as any);

      // RED: Method doesn't exist
      const result = await executor.executeMitigateStandalone({
        issues: [mockIssue],
        validationData: mockValidationData
      });

      expect(result.success).toBe(false);
      expect(result.error).toContain('AI provider not configured');
    });

    test('should handle test execution failures', async () => {
      // Mock test runner to always fail
      mock.module('../../utils/test-runner.js', () => ({
        runTests: async () => {
          throw new Error('Test environment not available');
        }
      }));

      // RED: Method doesn't exist
      const result = await executor.executeMitigateStandalone({
        issues: [mockIssue],
        validationData: mockValidationData,
        runTests: true
      });

      expect(result.success).toBe(false);
      expect(result.error).toContain('Test environment');
    });

    test('should timeout if fix takes too long', async () => {
      // Mock slow fix generation
      mock.module('../../ai/adapters/claude-code-git.js', () => ({
        GitBasedClaudeCodeAdapter: class {
          async generateSolutionWithGit() {
            await new Promise(resolve => setTimeout(resolve, 10000));
            return { success: true };
          }
        }
      }));

      // RED: Method doesn't exist
      const result = await executor.executeMitigateStandalone({
        issues: [mockIssue],
        validationData: mockValidationData,
        timeout: 100 // 100ms timeout
      });

      expect(result.success).toBe(false);
      expect(result.error).toContain('timeout');
    });
  });

  describe('Integration with execute() method', () => {
    test('should work through main execute method', async () => {
      // RED: Integration doesn't exist
      const result = await executor.execute('mitigate', {
        issues: [mockIssue],
        validationData: mockValidationData
      });

      expect(result.success).toBe(true);
      expect(result.phase).toBe('mitigate');
    });

    test('should support mitigation without prior validation', async () => {
      // RED: Should generate tests on the fly if needed
      const result = await executor.execute('mitigate', {
        issues: [mockIssue],
        generateTestsIfMissing: true
      });

      expect(result.success).toBe(true);
      expect(result.data.testsGenerated).toBe(true);
    });
  });

  describe('Report Generation', () => {
    test('should generate mitigation report in markdown', async () => {
      // RED: Method doesn't exist
      const result = await executor.executeMitigateStandalone({
        issues: [mockIssue],
        validationData: mockValidationData,
        format: 'markdown'
      });

      expect(result.success).toBe(true);
      expect(result.report).toContain('## Mitigation Report');
      expect(result.report).toContain('Fixed');
    });

    test('should generate JSON report for CI integration', async () => {
      // RED: Method doesn't exist
      const result = await executor.executeMitigateStandalone({
        issues: [mockIssue],
        validationData: mockValidationData,
        format: 'json'
      });

      expect(result.success).toBe(true);
      expect(result.jsonReport).toBeDefined();
      expect(result.jsonReport.mitigations).toHaveLength(1);
    });
  });
});