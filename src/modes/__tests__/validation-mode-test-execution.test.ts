/**
 * ValidationMode - Test Execution Integration Tests
 *
 * Tests the integration of TestRunner into ValidationMode for executing RED tests,
 * capturing test execution metadata, and applying GitHub labels based on validation results.
 *
 * @see src/modes/validation-mode.ts
 * @implements RFC-060 Phase 2.2
 */

import { describe, test, expect, beforeEach, vi, afterEach } from 'vitest';
import type { IssueContext, ActionConfig } from '../../types/index.js';
import type { TestRunResult } from '../../ai/test-runner.js';

// Create mocks using vi.hoisted to ensure proper hoisting
const {
  mockRunTests,
  mockStorePhaseResults,
  mockAddLabels,
  mockCreateLabel,
  mockAnalyzeIssue,
  mockAnalyzeWithTestGeneration,
  mockValidateFixWithTests
} = vi.hoisted(() => ({
  mockRunTests: vi.fn(),
  mockStorePhaseResults: vi.fn(),
  mockAddLabels: vi.fn(),
  mockCreateLabel: vi.fn(),
  mockAnalyzeIssue: vi.fn(),
  mockAnalyzeWithTestGeneration: vi.fn(),
  mockValidateFixWithTests: vi.fn()
}));

// Mock dependencies
vi.mock('../../ai/test-runner.js', () => ({
  TestRunner: vi.fn().mockImplementation(() => ({
    runTests: mockRunTests
  }))
}));

vi.mock('../../modes/phase-data-client/index.js', () => ({
  PhaseDataClient: vi.fn().mockImplementation(() => ({
    storePhaseResults: mockStorePhaseResults
  }))
}));

vi.mock('@octokit/rest', () => ({
  Octokit: vi.fn().mockImplementation(() => ({
    issues: {
      addLabels: mockAddLabels,
      createLabel: mockCreateLabel
    }
  }))
}));

vi.mock('../../ai/analyzer.js', () => ({
  analyzeIssue: mockAnalyzeIssue
}));

vi.mock('../../ai/test-generating-security-analyzer.js', () => ({
  TestGeneratingSecurityAnalyzer: vi.fn().mockImplementation(() => ({
    analyzeWithTestGeneration: mockAnalyzeWithTestGeneration
  }))
}));

vi.mock('../../ai/git-based-test-validator.js', () => ({
  GitBasedTestValidator: vi.fn().mockImplementation(() => ({
    validateFixWithTests: mockValidateFixWithTests
  }))
}));

vi.mock('child_process', () => ({
  execSync: vi.fn().mockReturnValue('test-commit-hash')
}));

vi.mock('fs', () => ({
  default: {
    existsSync: vi.fn().mockReturnValue(false),
    readFileSync: vi.fn(),
    writeFileSync: vi.fn(),
    mkdirSync: vi.fn()
  },
  existsSync: vi.fn().mockReturnValue(false),
  readFileSync: vi.fn(),
  writeFileSync: vi.fn(),
  mkdirSync: vi.fn()
}));

import { ValidationMode } from '../validation-mode.js';

describe('RFC-060 Phase 2.2: ValidationMode Test Execution Integration', () => {
  let validationMode: ValidationMode;
  let mockConfig: ActionConfig;
  let mockIssue: IssueContext;

  beforeEach(() => {
    vi.clearAllMocks();

    // Reset all mocks
    mockRunTests.mockReset();
    mockStorePhaseResults.mockReset();
    mockAddLabels.mockReset();
    mockCreateLabel.mockReset();
    mockAnalyzeIssue.mockReset();
    mockAnalyzeWithTestGeneration.mockReset();
    mockValidateFixWithTests.mockReset();

    // Default successful resolutions
    mockStorePhaseResults.mockResolvedValue({ success: true });
    mockAddLabels.mockResolvedValue({});
    mockCreateLabel.mockResolvedValue({});

    mockConfig = {
      apiKey: 'test-api-key',
      configPath: '/test/config',
      issueLabel: 'rsolv:vulnerability',
      repoToken: 'test-token',
      rsolvApiKey: 'test-rsolv-key',
      aiProvider: {
        provider: 'anthropic',
        apiKey: 'test-ai-key',
        model: 'claude-sonnet-4-5-20250929',
        maxTokens: 4000,
        useVendedCredentials: false
      },
      containerConfig: {
        enabled: false
      },
      securitySettings: {
        scanDependencies: true
      }
    };

    mockIssue = {
      id: '1',
      number: 123,
      title: 'SQL Injection in user authentication',
      body: 'Vulnerability details...',
      labels: ['rsolv:vulnerability'],
      assignees: [],
      repository: {
        owner: 'test-org',
        name: 'test-repo',
        fullName: 'test-org/test-repo',
        defaultBranch: 'main'
      },
      source: 'github',
      createdAt: '2024-01-01T00:00:00Z',
      updatedAt: '2024-01-01T00:00:00Z'
    };

    // Mock analysis to return fixable issue
    mockAnalyzeIssue.mockResolvedValue({
      canBeFixed: true,
      filesToModify: ['src/auth.js'],
      issueType: 'security',
      estimatedComplexity: 'medium',
      requiredContext: [],
      suggestedApproach: 'Fix SQL injection'
    });

    // Mock test generation
    mockAnalyzeWithTestGeneration.mockResolvedValue({
      generatedTests: {
        testSuite: 'test content',
        framework: 'jest',
        testFile: 'src/__tests__/auth.test.js'
      }
    });

    validationMode = new ValidationMode(mockConfig, '/tmp/test-repo');
  });

  describe('Test Execution with TestRunner', () => {
    test('should mark as validated when RED test fails (vulnerability confirmed)', async () => {
      // Mock test failure (RED test fails = vulnerability exists)
      mockValidateFixWithTests.mockResolvedValue({
        success: false, // Test failed = vulnerability confirmed
        output: 'FAIL: SQL injection test detected vulnerability',
        passed: false,
        vulnerableCommit: {
          allPassed: false, // Tests fail = vulnerability exists
          redTestPassed: false,
          greenTestPassed: false,
          refactorTestPassed: true
        },
        fixedCommit: {
          allPassed: true,
          redTestPassed: true,
          greenTestPassed: true,
          refactorTestPassed: true
        },
        isValidFix: false
      });

      const result = await validationMode.validateVulnerability(mockIssue);

      expect(result.validated).toBe(true);
      expect(result.testExecutionResult).toBeDefined();
      expect(result.testExecutionResult?.passed).toBe(false);
      expect(result.testExecutionResult?.output).toContain('FAIL: SQL injection');
    });

    test('should mark as false positive when RED test passes (no vulnerability)', async () => {
      // Mock test success (RED test passes = no vulnerability = false positive)
      mockValidateFixWithTests.mockResolvedValue({
        success: true, // Test passed = no vulnerability
        output: 'PASS: All tests passed',
        passed: true,
        vulnerableCommit: {
          allPassed: true, // Tests pass = no vulnerability
          redTestPassed: true,
          greenTestPassed: true,
          refactorTestPassed: true
        },
        fixedCommit: {
          allPassed: true,
          redTestPassed: true,
          greenTestPassed: true,
          refactorTestPassed: true
        }
      });

      const result = await validationMode.validateVulnerability(mockIssue);

      expect(result.validated).toBe(false);
      expect(result.falsePositiveReason).toContain('passed on allegedly vulnerable code');
    });
  });

  describe('PhaseDataClient Integration', () => {
    test('should store test execution results in PhaseDataClient', async () => {
      mockValidateFixWithTests.mockResolvedValue({
        success: false,
        output: 'Test failed with details',
        passed: false,
        vulnerableCommit: {
          allPassed: false,
          redTestPassed: false,
          greenTestPassed: false,
          refactorTestPassed: true
        },
        fixedCommit: {
          allPassed: true,
          redTestPassed: true,
          greenTestPassed: true,
          refactorTestPassed: true
        }
      });

      const result = await validationMode.validateVulnerability(mockIssue);

      expect(mockStorePhaseResults).toHaveBeenCalled();
      expect(result.testExecutionResult).toBeDefined();
      expect(result.testExecutionResult?.output).toContain('"success": false');
      expect(result.testExecutionResult?.output).toContain('Test failed with details');
    });

    test('should include test output in stored metadata', async () => {
      const detailedOutput = 'FAIL: Detailed test output with vulnerability evidence';
      const detailedStderr = 'Warning: Security issue detected';

      mockValidateFixWithTests.mockResolvedValue({
        success: false,
        output: detailedOutput,
        stderr: detailedStderr,
        passed: false,
        vulnerableCommit: {
          allPassed: false,
          redTestPassed: false,
          greenTestPassed: false,
          refactorTestPassed: true
        },
        fixedCommit: {
          allPassed: true,
          redTestPassed: true,
          greenTestPassed: true,
          refactorTestPassed: true
        }
      });

      const result = await validationMode.validateVulnerability(mockIssue);

      expect(result.testExecutionResult).toBeDefined();
      expect(result.testExecutionResult?.output).toContain(detailedOutput);
      expect(result.testExecutionResult?.stderr).toBe('');
    });
  });

  describe('GitHub Issue Labeling', () => {
    test('should apply rsolv:validated label when vulnerability is confirmed', async () => {
      mockValidateFixWithTests.mockResolvedValue({
        success: false,
        output: 'Test failed - vulnerability exists',
        passed: false,
        vulnerableCommit: {
          allPassed: false,
          redTestPassed: false,
          greenTestPassed: false,
          refactorTestPassed: true
        },
        fixedCommit: {
          allPassed: true,
          redTestPassed: true,
          greenTestPassed: true,
          refactorTestPassed: true
        }
      });

      process.env.GITHUB_TOKEN = 'test-token';
      process.env.GITHUB_REPOSITORY = 'test-org/test-repo';

      const result = await validationMode.validateVulnerability(mockIssue);

      expect(result.validated).toBe(true);
      expect(mockAddLabels).toHaveBeenCalledWith(
        expect.objectContaining({
          owner: 'test-org',
          repo: 'test-repo',
          issue_number: 123,
          labels: expect.arrayContaining(['rsolv:validated'])
        })
      );
    });

    test('should apply rsolv:false-positive label when validation fails', async () => {
      mockValidateFixWithTests.mockResolvedValue({
        success: true,
        output: 'Test passed - no vulnerability',
        passed: true,
        vulnerableCommit: {
          allPassed: true,
          redTestPassed: true,
          greenTestPassed: true,
          refactorTestPassed: true
        },
        fixedCommit: {
          allPassed: true,
          redTestPassed: true,
          greenTestPassed: true,
          refactorTestPassed: true
        }
      });

      process.env.GITHUB_TOKEN = 'test-token';
      process.env.GITHUB_REPOSITORY = 'test-org/test-repo';

      const result = await validationMode.validateVulnerability(mockIssue);

      expect(result.validated).toBe(false);
      expect(mockAddLabels).toHaveBeenCalledWith(
        expect.objectContaining({
          owner: 'test-org',
          repo: 'test-repo',
          issue_number: 123,
          labels: expect.arrayContaining(['rsolv:false-positive'])
        })
      );
    });
  });

  describe('Error Handling', () => {
    test('should handle test execution timeout', async () => {
      mockValidateFixWithTests.mockResolvedValue({
        success: false,
        output: '',
        stderr: '',
        error: 'Test execution timed out',
        passed: false,
        vulnerableCommit: {
          allPassed: false,
          redTestPassed: false,
          greenTestPassed: false,
          refactorTestPassed: false
        },
        fixedCommit: {
          allPassed: false,
          redTestPassed: false,
          greenTestPassed: false,
          refactorTestPassed: false
        }
      });

      const result = await validationMode.validateVulnerability(mockIssue);

      expect(result.validated).toBe(true); // Tests failed = vulnerability exists
      expect(result.testExecutionResult).toBeDefined();
      expect(result.testExecutionResult?.error).toContain('timed out');
    });

    test('should handle test execution errors gracefully', async () => {
      mockValidateFixWithTests.mockRejectedValue(
        new Error('Command not found: jest')
      );

      const result = await validationMode.validateVulnerability(mockIssue);

      expect(result.validated).toBe(false);
      expect(result.falsePositiveReason).toContain('error');
    });
  });

  describe('RFC-060 Phase 3.1: PhaseDataClient Metadata Storage', () => {
    test('should store branchName and testPath in PhaseDataClient', async () => {
      // Set up phaseDataClient
      const mockPhaseDataClient = {
        storePhaseResults: mockStorePhaseResults
      } as any;
      (validationMode as any).phaseDataClient = mockPhaseDataClient;

      // Mock test failure (RED test fails = vulnerability exists)
      mockValidateFixWithTests.mockResolvedValue({
        success: false,
        output: 'Test failed',
        passed: false,
        vulnerableCommit: {
          allPassed: false,
          redTestPassed: false,
          greenTestPassed: false,
          refactorTestPassed: true
        },
        fixedCommit: {
          allPassed: true,
          redTestPassed: true,
          greenTestPassed: true,
          refactorTestPassed: true
        }
      });

      mockStorePhaseResults.mockResolvedValue({ success: true });

      await validationMode.validateVulnerability(mockIssue);

      expect(mockStorePhaseResults).toHaveBeenCalled();
      const storeCall = mockStorePhaseResults.mock.calls[0];

      // Verify branchName and testPath are included in the stored data
      expect(storeCall[0]).toBe('validate');
      expect(storeCall[1].validate[123]).toHaveProperty('branchName');
      expect(storeCall[1].validate[123]).toHaveProperty('testPath');
      expect(storeCall[1].validate[123]).toHaveProperty('validated');
      expect(storeCall[1].validate[123]).toHaveProperty('testExecutionResult');
    });
  });
});
