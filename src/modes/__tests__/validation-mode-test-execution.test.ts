/**
 * ValidationMode - Test Execution Integration Tests
 *
 * Tests the RFC-060-AMENDMENT-001 pipeline where validateVulnerability() uses
 * framework-native test generation instead of GitBasedTestValidator.
 *
 * Pipeline: analyzeIssue -> detectFrameworkFromFile -> scanTestFiles ->
 *           testIntegrationClient.analyze -> generateTestWithRetry ->
 *           branch/commit/label/phaseData
 *
 * @see src/modes/validation-mode.ts
 * @implements RFC-060-AMENDMENT-001
 */

import { describe, test, expect, beforeEach, vi, afterEach } from 'vitest';
import type { IssueContext, ActionConfig } from '../../types/index.js';
import type { TestSuite } from '../types.js';

// Create mocks using vi.hoisted to ensure proper hoisting
const {
  mockAnalyzeIssue,
  mockTestIntegrationClientAnalyze,
  mockStorePhaseResults,
  mockAddLabels,
  mockCreateLabel
} = vi.hoisted(() => ({
  mockAnalyzeIssue: vi.fn(),
  mockTestIntegrationClientAnalyze: vi.fn(),
  mockStorePhaseResults: vi.fn(),
  mockAddLabels: vi.fn(),
  mockCreateLabel: vi.fn()
}));

// Mock dependencies
vi.mock('../../ai/analyzer.js', () => ({
  analyzeIssue: mockAnalyzeIssue
}));

vi.mock('../test-integration-client.js', () => ({
  TestIntegrationClient: vi.fn().mockImplementation(() => ({
    analyze: mockTestIntegrationClientAnalyze
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

vi.mock('../../github/api.js', () => ({
  getGitHubClient: vi.fn().mockReturnValue({
    issues: {
      addLabels: mockAddLabels,
      createLabel: mockCreateLabel
    }
  })
}));

vi.mock('../vendor-utils.js', () => ({
  vendorFilterUtils: {
    checkForVendorFiles: vi.fn().mockResolvedValue({ isVendor: false, files: [] })
  }
}));

vi.mock('../../ai/client.js', () => ({
  getAiClient: vi.fn().mockResolvedValue({
    complete: vi.fn().mockResolvedValue(`\`\`\`javascript
test('security vulnerability', () => {
  expect(vulnerable).toBe(true);
});
\`\`\``)
  })
}));

vi.mock('child_process', () => ({
  execSync: vi.fn().mockReturnValue('test-commit-hash')
}));

vi.mock('fs', () => ({
  default: {
    existsSync: vi.fn().mockReturnValue(false),
    readFileSync: vi.fn().mockReturnValue(''),
    writeFileSync: vi.fn(),
    mkdirSync: vi.fn(),
    readdirSync: vi.fn().mockReturnValue([])
  },
  existsSync: vi.fn().mockReturnValue(false),
  readFileSync: vi.fn().mockReturnValue(''),
  writeFileSync: vi.fn(),
  mkdirSync: vi.fn(),
  readdirSync: vi.fn().mockReturnValue([])
}));

import { ValidationMode } from '../validation-mode.js';

describe('RFC-060-AMENDMENT-001: ValidationMode Test Execution Integration', () => {
  let validationMode: ValidationMode;
  let mockConfig: ActionConfig;
  let mockIssue: IssueContext;

  // Reusable test suite returned by generateTestWithRetry when validation succeeds
  const successTestSuite: TestSuite = {
    framework: 'jest',
    testFile: 'src/__tests__/auth.test.js',
    redTests: [{
      testName: 'SQL injection vulnerability',
      testCode: 'expect(vulnerable).toBe(true);',
      attackVector: 'sql_injection',
      expectedBehavior: 'should reject malicious input'
    }]
  };

  beforeEach(() => {
    vi.clearAllMocks();

    // Reset all hoisted mocks
    mockAnalyzeIssue.mockReset();
    mockTestIntegrationClientAnalyze.mockReset();
    mockStorePhaseResults.mockReset();
    mockAddLabels.mockReset();
    mockCreateLabel.mockReset();

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

    // Default: analyzeIssue returns fixable issue
    mockAnalyzeIssue.mockResolvedValue({
      canBeFixed: true,
      filesToModify: ['src/auth.js'],
      issueType: 'security',
      estimatedComplexity: 'medium',
      requiredContext: [],
      suggestedApproach: 'Fix SQL injection'
    });

    // Default: testIntegrationClient.analyze returns a recommendation
    mockTestIntegrationClientAnalyze.mockResolvedValue({
      recommendations: [{ path: 'test/auth.test.js', score: 0.9, reason: 'Best match' }],
      fallback: { path: 'test/auth.test.js', reason: 'Only candidate' }
    });

    // Set env vars for GitHub operations
    process.env.GITHUB_TOKEN = 'test-token';
    process.env.GITHUB_REPOSITORY = 'test-org/test-repo';

    // Create instance (rsolvApiKey set so TestIntegrationClient initializes)
    validationMode = new ValidationMode(mockConfig, '/tmp/test-repo');

    // Spy on private methods to control the pipeline
    vi.spyOn(validationMode as any, 'ensureCleanGitState').mockImplementation(() => {});
    vi.spyOn(validationMode as any, 'loadFalsePositiveCache').mockImplementation(() => {});
    vi.spyOn(validationMode as any, 'detectFrameworkFromFile').mockReturnValue('jest');
    vi.spyOn(validationMode as any, 'detectFrameworkWithBackend').mockResolvedValue('jest');
    // RFC-103 v3.8.94: Ensure noTestFrameworkAvailable is false for tests
    (validationMode as any).noTestFrameworkAvailable = false;
    vi.spyOn(validationMode as any, 'scanTestFiles').mockResolvedValue(['test/auth.test.js']);
    vi.spyOn(validationMode as any, 'integrateTestsWithBackendRetry').mockResolvedValue({
      targetFile: 'test/auth.test.js',
      content: 'integrated test content'
    });
    vi.spyOn(validationMode as any, 'addGitHubLabel').mockResolvedValue(undefined);
    vi.spyOn(validationMode as any, 'storeTestExecutionInPhaseData').mockResolvedValue(undefined);
  });

  afterEach(() => {
    delete process.env.GITHUB_TOKEN;
    delete process.env.GITHUB_REPOSITORY;
  });

  describe('Test Execution with generateTestWithRetry Pipeline', () => {
    test('should mark as validated when RED test fails (vulnerability confirmed)', async () => {
      // generateTestWithRetry returns a test suite => RED test failed on vulnerable code
      vi.spyOn(validationMode as any, 'generateTestWithRetry').mockResolvedValue(successTestSuite);

      const result = await validationMode.validateVulnerability(mockIssue);

      expect(result.validated).toBe(true);
      expect(result.testExecutionResult).toBeDefined();
      expect(result.testExecutionResult?.passed).toBe(false);
      expect(result.testExecutionResult?.output).toContain('RED test failed on vulnerable code');
      expect(result.testExecutionResult?.framework).toBe('jest');
      expect(result.testExecutionResult?.testFile).toBe('src/__tests__/auth.test.js');
    });

    test('should mark as false positive when RED test passes (generateTestWithRetry returns null)', async () => {
      // generateTestWithRetry returns null => could not generate a valid RED test
      vi.spyOn(validationMode as any, 'generateTestWithRetry').mockResolvedValue(null);

      const result = await validationMode.validateVulnerability(mockIssue);

      expect(result.validated).toBe(false);
      expect(result.falsePositiveReason).toContain('Unable to generate valid RED test');
      expect(result.falsePositiveReason).toContain('4 attempts');
    });

    test('should include branchName in result when validated', async () => {
      vi.spyOn(validationMode as any, 'generateTestWithRetry').mockResolvedValue(successTestSuite);

      const result = await validationMode.validateVulnerability(mockIssue);

      expect(result.validated).toBe(true);
      expect(result.branchName).toBeDefined();
      expect(result.branchName).toContain('rsolv/validate/issue-123');
    });
  });

  describe('PhaseDataClient Integration', () => {
    test('should store test execution results when validated', async () => {
      // Re-create the spy so we can assert on it (beforeEach already sets one)
      const storeSpy = vi.spyOn(validationMode as any, 'storeTestExecutionInPhaseData')
        .mockResolvedValue(undefined);
      vi.spyOn(validationMode as any, 'generateTestWithRetry').mockResolvedValue(successTestSuite);

      await validationMode.validateVulnerability(mockIssue);

      expect(storeSpy).toHaveBeenCalled();
    });

    test('should not store phase data when validation fails (null test suite)', async () => {
      const storePhaseDataSpy = vi.spyOn(validationMode as any, 'storeTestExecutionInPhaseData');
      vi.spyOn(validationMode as any, 'generateTestWithRetry').mockResolvedValue(null);

      await validationMode.validateVulnerability(mockIssue);

      // storeTestExecutionInPhaseData is NOT called when testSuite is null
      // because we return early before reaching the store call
      expect(storePhaseDataSpy).not.toHaveBeenCalled();
    });
  });

  describe('GitHub Issue Labeling', () => {
    test('should apply rsolv:validated label when vulnerability is confirmed', async () => {
      vi.spyOn(validationMode as any, 'generateTestWithRetry').mockResolvedValue(successTestSuite);

      const result = await validationMode.validateVulnerability(mockIssue);

      expect(result.validated).toBe(true);
      expect((validationMode as any).addGitHubLabel).toHaveBeenCalledWith(
        mockIssue,
        'rsolv:validated'
      );
    });

    test('should not apply rsolv:validated label when validation fails', async () => {
      vi.spyOn(validationMode as any, 'generateTestWithRetry').mockResolvedValue(null);

      const result = await validationMode.validateVulnerability(mockIssue);

      expect(result.validated).toBe(false);
      // addGitHubLabel should not be called with 'rsolv:validated' when testSuite is null
      expect((validationMode as any).addGitHubLabel).not.toHaveBeenCalledWith(
        mockIssue,
        'rsolv:validated'
      );
    });
  });

  describe('Error Handling', () => {
    test('should handle timeout scenario (generateTestWithRetry returns null)', async () => {
      // When all retry attempts time out, generateTestWithRetry returns null
      vi.spyOn(validationMode as any, 'generateTestWithRetry').mockResolvedValue(null);

      const result = await validationMode.validateVulnerability(mockIssue);

      expect(result.validated).toBe(false);
      expect(result.falsePositiveReason).toContain('Unable to generate valid RED test');
    });

    test('should handle errors gracefully when generateTestWithRetry throws', async () => {
      vi.spyOn(validationMode as any, 'generateTestWithRetry').mockRejectedValue(
        new Error('Command not found: jest')
      );

      const result = await validationMode.validateVulnerability(mockIssue);

      expect(result.validated).toBe(false);
      expect(result.falsePositiveReason).toContain('Validation error');
    });

    test('should handle missing TestIntegrationClient when rsolvApiKey is not set', async () => {
      const configWithoutKey = { ...mockConfig, rsolvApiKey: undefined };
      const modeWithoutKey = new ValidationMode(configWithoutKey, '/tmp/test-repo');
      vi.spyOn(modeWithoutKey as any, 'ensureCleanGitState').mockImplementation(() => {});
      vi.spyOn(modeWithoutKey as any, 'loadFalsePositiveCache').mockImplementation(() => {});

      const result = await modeWithoutKey.validateVulnerability(mockIssue);

      expect(result.validated).toBe(false);
      expect(result.falsePositiveReason).toContain('TestIntegrationClient not initialized');
    });
  });

  describe('RFC-060-AMENDMENT-001: PhaseDataClient Metadata Storage', () => {
    test('should pass branchName and testPath to storeTestExecutionInPhaseData', async () => {
      vi.spyOn(validationMode as any, 'generateTestWithRetry').mockResolvedValue(successTestSuite);
      // Replace the spy with one that captures args
      const storeSpy = vi.spyOn(validationMode as any, 'storeTestExecutionInPhaseData')
        .mockResolvedValue(undefined);

      await validationMode.validateVulnerability(mockIssue);

      expect(storeSpy).toHaveBeenCalledWith(
        mockIssue,
        expect.objectContaining({
          passed: false,
          framework: 'jest',
          testFile: 'src/__tests__/auth.test.js'
        }),
        true,
        expect.stringContaining('rsolv/validate/issue-123'),
        expect.any(Array) // vulnerabilities
      );
    });
  });

  describe('Pipeline Flow', () => {
    test('should call analyzeIssue before generating tests', async () => {
      vi.spyOn(validationMode as any, 'generateTestWithRetry').mockResolvedValue(successTestSuite);

      await validationMode.validateVulnerability(mockIssue);

      expect(mockAnalyzeIssue).toHaveBeenCalledWith(mockIssue, mockConfig);
    });

    test('should not generate tests when analyzeIssue says issue cannot be fixed', async () => {
      mockAnalyzeIssue.mockResolvedValue({
        canBeFixed: false,
        cannotFixReason: 'Requires architectural changes',
        filesToModify: [],
        issueType: 'security',
        estimatedComplexity: 'high',
        requiredContext: [],
        suggestedApproach: ''
      });

      const generateSpy = vi.spyOn(validationMode as any, 'generateTestWithRetry');

      const result = await validationMode.validateVulnerability(mockIssue);

      expect(result.validated).toBe(false);
      expect(result.falsePositiveReason).toContain('Requires architectural changes');
      expect(generateSpy).not.toHaveBeenCalled();
    });

    test('should call detectFrameworkWithBackend with primary vulnerable file', async () => {
      vi.spyOn(validationMode as any, 'generateTestWithRetry').mockResolvedValue(successTestSuite);
      const frameworkSpy = vi.spyOn(validationMode as any, 'detectFrameworkWithBackend');

      await validationMode.validateVulnerability(mockIssue);

      expect(frameworkSpy).toHaveBeenCalled();
    });

    test('should call scanTestFiles to find candidate test files', async () => {
      vi.spyOn(validationMode as any, 'generateTestWithRetry').mockResolvedValue(successTestSuite);
      const scanSpy = vi.spyOn(validationMode as any, 'scanTestFiles');

      await validationMode.validateVulnerability(mockIssue);

      expect(scanSpy).toHaveBeenCalled();
    });

    test('should skip analyzeIssue when priorAnalysis is provided', async () => {
      vi.spyOn(validationMode as any, 'generateTestWithRetry').mockResolvedValue(successTestSuite);

      const priorAnalysis = {
        canBeFixed: true,
        filesToModify: ['src/auth.js'],
        issueType: 'security' as const,
        estimatedComplexity: 'medium' as const,
        requiredContext: [],
        suggestedApproach: 'Fix SQL injection'
      };

      await validationMode.validateVulnerability(mockIssue, priorAnalysis);

      expect(mockAnalyzeIssue).not.toHaveBeenCalled();
    });

    test('should use priorAnalysis.canBeFixed to skip unfixable issues', async () => {
      const priorAnalysis = {
        canBeFixed: false,
        cannotFixReason: 'Requires major refactor',
        filesToModify: [],
        issueType: 'security' as const,
        estimatedComplexity: 'complex' as const,
        requiredContext: [],
        suggestedApproach: ''
      };

      const generateSpy = vi.spyOn(validationMode as any, 'generateTestWithRetry');

      const result = await validationMode.validateVulnerability(mockIssue, priorAnalysis);

      expect(mockAnalyzeIssue).not.toHaveBeenCalled();
      expect(result.validated).toBe(false);
      expect(result.falsePositiveReason).toContain('Requires major refactor');
      expect(generateSpy).not.toHaveBeenCalled();
    });
  });
});
