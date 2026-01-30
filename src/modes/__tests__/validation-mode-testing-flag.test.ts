/**
 * Test suite for RFC-060-AMENDMENT-001 pipeline behavior
 * Tests the new generateTestWithRetry-based validation flow
 * and verifies RSOLV_TESTING_MODE has no effect on the new pipeline
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { ValidationMode } from '../validation-mode';
import { IssueContext, ActionConfig } from '../../types/index';
import * as analyzer from '../../ai/analyzer';
import * as fs from 'fs';
import { execSync } from 'child_process';
import { TestSuite } from '../types';

// Mock dependencies
vi.mock('../../ai/analyzer');
vi.mock('../../ai/test-generating-security-analyzer');
vi.mock('child_process');
vi.mock('fs');

vi.mock('../vendor-utils.js', () => ({
  vendorFilterUtils: {
    checkForVendorFiles: vi.fn().mockResolvedValue({ isVendor: false, files: [] })
  }
}));

vi.mock('../test-integration-client.js', () => ({
  TestIntegrationClient: vi.fn().mockImplementation(() => ({
    analyze: vi.fn().mockResolvedValue({ recommendations: [] }),
    generate: vi.fn().mockResolvedValue({ integratedContent: '' })
  }))
}));

describe('ValidationMode - RFC-060-AMENDMENT-001 Pipeline', () => {
  let validationMode: ValidationMode;
  let mockConfig: ActionConfig;
  let mockIssue: IssueContext;
  let originalEnv: NodeJS.ProcessEnv;

  const validTestSuite: TestSuite = {
    framework: 'jest',
    testFile: 'test/vulnerability.test.js',
    redTests: [
      {
        testName: 'should detect XSS vulnerability',
        testCode: 'expect(sanitize("<script>alert(1)</script>")).not.toContain("<script>")',
        attackVector: 'xss',
        expectedBehavior: 'Fails on vulnerable code, passes after fix'
      }
    ]
  };

  beforeEach(() => {
    // Save original env
    originalEnv = { ...process.env };
    delete process.env.RSOLV_TESTING_MODE;

    // Setup mocks
    mockConfig = {
      apiKey: 'test-key',
      rsolvApiKey: 'test-rsolv-key',
      githubToken: 'test-token',
      mode: 'validate',
      executableTests: true,
      aiProvider: {
        apiKey: 'test-ai-key',
        model: 'claude-sonnet-4-5-20250929',
        provider: 'anthropic'
      }
    } as ActionConfig;

    mockIssue = {
      id: 'issue-123',
      number: 123,
      title: 'XSS vulnerability in NodeGoat',
      body: 'Known vulnerability in app/routes/profile.js',
      labels: ['rsolv:automate'],
      assignees: [],
      repository: {
        owner: 'RSOLV-dev',
        name: 'nodegoat-vulnerability-demo',
        fullName: 'RSOLV-dev/nodegoat-vulnerability-demo',
        defaultBranch: 'main'
      },
      source: 'github',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      metadata: {}
    };

    validationMode = new ValidationMode(mockConfig);

    // Mock file system operations
    (fs.existsSync as any).mockReturnValue(false);
    (fs.readFileSync as any).mockReturnValue('{}');
    (fs.writeFileSync as any).mockImplementation(() => {});
    (fs.mkdirSync as any).mockImplementation(() => {});

    // Mock git operations
    (execSync as any).mockImplementation((cmd: string) => {
      if (cmd.includes('git status')) return 'nothing to commit, working tree clean';
      if (cmd.includes('git rev-parse HEAD')) return 'abc123def456';
      if (cmd.includes('git checkout -b')) return '';
      if (cmd.includes('git add')) return '';
      if (cmd.includes('git commit')) return '';
      if (cmd.includes('git config')) return '';
      if (cmd.includes('git push')) return '';
      if (cmd.includes('git remote')) return '';
      return '';
    });

    // Mock private methods on the instance
    vi.spyOn(validationMode as any, 'generateTestWithRetry').mockResolvedValue(null);
    vi.spyOn(validationMode as any, 'scanTestFiles').mockResolvedValue([]);
    vi.spyOn(validationMode as any, 'detectFrameworkFromFile').mockReturnValue('jest');
    vi.spyOn(validationMode as any, 'integrateTestsWithBackendRetry').mockResolvedValue({
      targetFile: 'test/foo.test.js',
      content: 'test code'
    });
    vi.spyOn(validationMode as any, 'createValidationBranch').mockResolvedValue('rsolv/validate/issue-123');
    vi.spyOn(validationMode as any, 'ensureCleanGitState').mockImplementation(() => {});
    vi.spyOn(validationMode as any, 'addGitHubLabel').mockResolvedValue(undefined);
    vi.spyOn(validationMode as any, 'storeTestExecutionInPhaseData').mockResolvedValue(undefined);
    vi.spyOn(validationMode as any, 'loadFalsePositiveCache').mockImplementation(() => {});
  });

  afterEach(() => {
    // Restore original env
    process.env = originalEnv;
    vi.clearAllMocks();
  });

  describe('Normal mode (RSOLV_TESTING_MODE not set)', () => {
    it('should mark as validated when generateTestWithRetry returns a test suite', async () => {
      (analyzer.analyzeIssue as any).mockResolvedValue({
        canBeFixed: true,
        isSecurityIssue: true
      });

      vi.spyOn(validationMode as any, 'generateTestWithRetry').mockResolvedValue(validTestSuite);

      const result = await validationMode.validateVulnerability(mockIssue);

      expect(result.validated).toBe(true);
      expect(result.falsePositiveReason).toBeUndefined();
      expect(result.branchName).toBe('rsolv/validate/issue-123');
      expect(result.redTests).toEqual(validTestSuite);
    });

    it('should mark as false positive when generateTestWithRetry returns null', async () => {
      (analyzer.analyzeIssue as any).mockResolvedValue({
        canBeFixed: true,
        isSecurityIssue: true
      });

      vi.spyOn(validationMode as any, 'generateTestWithRetry').mockResolvedValue(null);

      const result = await validationMode.validateVulnerability(mockIssue);

      expect(result.validated).toBe(false);
      expect(result.falsePositiveReason).toBe('Unable to generate valid RED test after 3 attempts');
    });

    it('should mark as not validated when analysis says canBeFixed is false', async () => {
      (analyzer.analyzeIssue as any).mockResolvedValue({
        canBeFixed: false,
        cannotFixReason: 'Not a real security issue',
        isSecurityIssue: false
      });

      const result = await validationMode.validateVulnerability(mockIssue);

      expect(result.validated).toBe(false);
      expect(result.falsePositiveReason).toBe('Not a real security issue');
    });
  });

  describe('Testing mode (RSOLV_TESTING_MODE=true)', () => {
    beforeEach(() => {
      process.env.RSOLV_TESTING_MODE = 'true';
    });

    it('should still mark as validated when generateTestWithRetry returns a suite', async () => {
      (analyzer.analyzeIssue as any).mockResolvedValue({
        canBeFixed: true,
        isSecurityIssue: true
      });

      vi.spyOn(validationMode as any, 'generateTestWithRetry').mockResolvedValue(validTestSuite);

      const result = await validationMode.validateVulnerability(mockIssue);

      // Testing mode does not change the pipeline outcome
      expect(result.validated).toBe(true);
      expect(result.falsePositiveReason).toBeUndefined();
      expect(result.branchName).toBe('rsolv/validate/issue-123');
    });

    it('should still mark as false positive when generateTestWithRetry returns null', async () => {
      (analyzer.analyzeIssue as any).mockResolvedValue({
        canBeFixed: true,
        isSecurityIssue: true
      });

      vi.spyOn(validationMode as any, 'generateTestWithRetry').mockResolvedValue(null);

      const result = await validationMode.validateVulnerability(mockIssue);

      // In the new pipeline, RSOLV_TESTING_MODE does NOT override test generation failures
      expect(result.validated).toBe(false);
      expect(result.falsePositiveReason).toBe('Unable to generate valid RED test after 3 attempts');
    });

    it('should still respect analysis failure even in testing mode', async () => {
      (analyzer.analyzeIssue as any).mockResolvedValue({
        canBeFixed: false,
        cannotFixReason: 'Not a real security issue',
        isSecurityIssue: false
      });

      const result = await validationMode.validateVulnerability(mockIssue);

      expect(result.validated).toBe(false);
      expect(result.falsePositiveReason).toBe('Not a real security issue');
    });
  });

  describe('Edge cases', () => {
    it('should treat RSOLV_TESTING_MODE=false the same as unset', async () => {
      process.env.RSOLV_TESTING_MODE = 'false';

      (analyzer.analyzeIssue as any).mockResolvedValue({
        canBeFixed: true,
        isSecurityIssue: true
      });

      vi.spyOn(validationMode as any, 'generateTestWithRetry').mockResolvedValue(null);

      const result = await validationMode.validateVulnerability(mockIssue);

      expect(result.validated).toBe(false);
      expect(result.falsePositiveReason).toBe('Unable to generate valid RED test after 3 attempts');
    });

    it('should include branch name and test suite when validation succeeds', async () => {
      (analyzer.analyzeIssue as any).mockResolvedValue({
        canBeFixed: true,
        isSecurityIssue: true
      });

      vi.spyOn(validationMode as any, 'generateTestWithRetry').mockResolvedValue(validTestSuite);

      const result = await validationMode.validateVulnerability(mockIssue);

      expect(result.validated).toBe(true);
      expect(result.branchName).toBe('rsolv/validate/issue-123');
      expect(result.redTests).toEqual(validTestSuite);
      expect(result.testExecutionResult).toBeDefined();
      expect(result.testExecutionResult?.passed).toBe(false); // RED test must fail
      expect(result.testExecutionResult?.framework).toBe('jest');
    });

    it('should skip validation when executableTests is disabled', async () => {
      const disabledConfig = {
        ...mockConfig,
        executableTests: false
      } as ActionConfig;

      const disabledMode = new ValidationMode(disabledConfig);
      vi.spyOn(disabledMode as any, 'loadFalsePositiveCache').mockImplementation(() => {});

      const result = await disabledMode.validateVulnerability(mockIssue);

      // When executableTests is disabled, validation is skipped and result is validated=true
      expect(result.validated).toBe(true);
      expect(result.falsePositiveReason).toBeUndefined();
    });

    it('should call addGitHubLabel and storeTestExecutionInPhaseData on success', async () => {
      (analyzer.analyzeIssue as any).mockResolvedValue({
        canBeFixed: true,
        isSecurityIssue: true
      });

      vi.spyOn(validationMode as any, 'generateTestWithRetry').mockResolvedValue(validTestSuite);

      await validationMode.validateVulnerability(mockIssue);

      expect((validationMode as any).addGitHubLabel).toHaveBeenCalledWith(mockIssue, 'rsolv:validated');
      expect((validationMode as any).storeTestExecutionInPhaseData).toHaveBeenCalled();
    });
  });
});
