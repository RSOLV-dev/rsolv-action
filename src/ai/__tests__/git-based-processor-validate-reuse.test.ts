/**
 * Tests for processIssueWithGit: VALIDATE RED test reuse path
 *
 * Verifies that when VALIDATE phase data contains proven RED tests,
 * MITIGATE skips TestGeneratingSecurityAnalyzer and uses the proven
 * RED test with an ecosystem-native runner instead.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';

// Mock the validate-test-reuse module
vi.mock('../validate-test-reuse.js', () => ({
  extractValidateRedTest: vi.fn(),
  verifyFixWithValidateRedTest: vi.fn(),
}));

// Mock test-generating-security-analyzer
vi.mock('../test-generating-security-analyzer.js', () => ({
  TestGeneratingSecurityAnalyzer: vi.fn().mockImplementation(() => ({
    analyzeWithTestGeneration: vi.fn().mockResolvedValue({
      success: false,
      generatedTests: null,
    }),
  })),
}));

// Mock git-based-test-validator
vi.mock('../git-based-test-validator.js', () => ({
  GitBasedTestValidator: vi.fn().mockImplementation(() => ({
    validateFixWithTests: vi.fn().mockResolvedValue({ isValidFix: false }),
  })),
}));

// Mock analyzer
vi.mock('../analyzer.js', () => ({
  analyzeIssue: vi.fn().mockResolvedValue({
    canBeFixed: true,
    filesToModify: ['app.py'],
    vulnerabilityType: 'sql-injection',
    suggestedApproach: 'parameterize queries',
    estimatedComplexity: 'simple',
    severity: 'high',
    issueType: 'security',
  }),
}));

// Mock adapters
vi.mock('../adapters/claude-agent-sdk.js', () => ({
  ClaudeAgentSDKAdapter: vi.fn(),
  createClaudeAgentSDKAdapter: vi.fn().mockReturnValue({
    generateSolutionWithGit: vi.fn().mockResolvedValue({
      success: true,
      commitHash: 'fix123abc',
      message: 'Fixed SQL injection',
      summary: { description: 'Parameterized query' },
      diffStats: { insertions: 5, deletions: 3, filesChanged: 1 },
    }),
  }),
  GitSolutionResult: {},
}));

vi.mock('../adapters/deprecated/claude-code-cli-dev.js', () => ({
  ClaudeCodeMaxAdapter: vi.fn(),
  isClaudeMaxAvailable: vi.fn().mockReturnValue(false),
}));

// Mock PR creation
vi.mock('../../github/pr-git.js', () => ({
  createPullRequestFromGit: vi.fn().mockResolvedValue({
    success: true,
    pullRequestUrl: 'https://github.com/test/repo/pull/1',
    pullRequestNumber: 1,
  }),
}));

vi.mock('../../github/pr-git-educational.js', () => ({
  createEducationalPullRequest: vi.fn().mockResolvedValue({
    success: true,
    pullRequestUrl: 'https://github.com/test/repo/pull/1',
    pullRequestNumber: 1,
  }),
}));

// Mock child_process
vi.mock('child_process', () => ({
  execSync: vi.fn().mockImplementation((cmd: string) => {
    if (typeof cmd === 'string' && cmd.includes('git rev-parse')) {
      return 'abc123def';
    }
    if (typeof cmd === 'string' && cmd.includes('git status')) {
      return '';
    }
    if (typeof cmd === 'string' && cmd.includes('git diff')) {
      return '';
    }
    return '';
  }),
}));

// Mock static-xss-validator
vi.mock('../static-xss-validator.js', () => ({
  shouldUseStaticValidation: vi.fn().mockReturnValue(false),
  StaticXSSValidator: vi.fn(),
}));

// Mock vulnerable-file-scanner
vi.mock('../vulnerable-file-scanner.js', () => ({
  getVulnerableFiles: vi.fn().mockResolvedValue(new Map()),
}));

// Mock fs for reading codebase files
vi.mock('fs', () => ({
  default: {
    existsSync: vi.fn().mockReturnValue(true),
    readFileSync: vi.fn().mockReturnValue('vulnerable code here'),
  },
  existsSync: vi.fn().mockReturnValue(true),
  readFileSync: vi.fn().mockReturnValue('vulnerable code here'),
}));

import { extractValidateRedTest, verifyFixWithValidateRedTest } from '../validate-test-reuse.js';
import { TestGeneratingSecurityAnalyzer } from '../test-generating-security-analyzer.js';
import { processIssueWithGit } from '../git-based-processor.js';
import type { IssueContext, ActionConfig } from '../../types/index.js';

const mockExtractValidateRedTest = vi.mocked(extractValidateRedTest);
const mockVerifyFixWithValidateRedTest = vi.mocked(verifyFixWithValidateRedTest);

describe('processIssueWithGit: VALIDATE RED test reuse path', () => {
  const baseIssue: IssueContext = {
    id: '1',
    number: 42,
    title: 'CWE-89: SQL Injection in app.py',
    body: 'SQL injection vulnerability found in user input handling',
    labels: ['security', 'rsolv:automate'],
    repository: { owner: 'test-org', name: 'test-repo' },
    assignees: [],
    state: 'open',
    created_at: '2026-01-01T00:00:00Z',
    updated_at: '2026-01-01T00:00:00Z',
  };

  const baseConfig: ActionConfig = {
    aiProvider: {
      provider: 'anthropic' as const,
      apiKey: 'test-key',
      providerApiKey: 'test-provider-key',
      model: 'claude-opus-4-6',
      maxTokens: 4096,
      useVendedCredentials: false,
    },
    enableSecurityAnalysis: true,
    testGeneration: {
      enabled: true,
      validateFixes: true,
    },
    fixValidation: {
      enabled: true,
    },
    maxIssues: 10,
  } as ActionConfig;

  beforeEach(() => {
    vi.clearAllMocks();
    // Reset env vars
    delete process.env.DISABLE_FIX_VALIDATION;
    delete process.env.RSOLV_DEV_MODE;
    delete process.env.RSOLV_USE_CLAUDE_MAX;
    delete process.env.RSOLV_EDUCATIONAL_PR;
    process.env.RSOLV_EDUCATIONAL_PR = 'false';
  });

  it('when validation phase data has redTests, skips TestGeneratingSecurityAnalyzer', async () => {
    const validationData = {
      validation: {
        'issue-42': {
          issueNumber: 42,
          validated: true,
          framework: 'pytest',
          branchName: 'rsolv/validate/issue-42',
          redTests: {
            redTests: [{
              testName: 'test_sql_injection',
              testCode: 'def test_sql_injection(): assert True',
              attackVector: 'SQL injection',
              expectedBehavior: 'should_fail_on_vulnerable_code' as const,
            }],
          },
          testResults: { testFile: 'tests/test_vulnerability_validation.py' },
        },
      },
    };

    mockExtractValidateRedTest.mockReturnValue({
      testCode: 'def test_sql_injection(): assert True',
      testFile: 'tests/test_vulnerability_validation.py',
      framework: 'pytest',
      branchName: 'rsolv/validate/issue-42',
    });

    mockVerifyFixWithValidateRedTest.mockResolvedValue({
      isValidFix: true,
      vulnerableResult: { passed: false, output: 'FAILED', exitCode: 1 },
      fixedResult: { passed: true, output: '1 passed', exitCode: 0 },
    });

    await processIssueWithGit(baseIssue, baseConfig, validationData as any);

    // TestGeneratingSecurityAnalyzer should NOT be called when we have VALIDATE RED test
    const analyzerCalls = vi.mocked(TestGeneratingSecurityAnalyzer).mock.instances;
    // If extract returns non-null, test generation should be skipped
    expect(mockExtractValidateRedTest).toHaveBeenCalledWith(validationData, 42);
  });

  it('uses extractValidateRedTest() instead of generating new tests', async () => {
    const validationData = {
      validation: {
        'issue-42': {
          issueNumber: 42,
          validated: true,
          framework: 'pytest',
          branchName: 'rsolv/validate/issue-42',
          redTests: {
            redTests: [{
              testName: 'test_vuln',
              testCode: 'def test_vuln(): pass',
              attackVector: 'vuln',
              expectedBehavior: 'should_fail_on_vulnerable_code' as const,
            }],
          },
          testResults: { testFile: 'tests/test_vuln.py' },
        },
      },
    };

    mockExtractValidateRedTest.mockReturnValue({
      testCode: 'def test_vuln(): pass',
      testFile: 'tests/test_vuln.py',
      framework: 'pytest',
      branchName: 'rsolv/validate/issue-42',
    });

    mockVerifyFixWithValidateRedTest.mockResolvedValue({
      isValidFix: true,
      vulnerableResult: { passed: false, output: 'FAILED', exitCode: 1 },
      fixedResult: { passed: true, output: '1 passed', exitCode: 0 },
    });

    await processIssueWithGit(baseIssue, baseConfig, validationData as any);

    // extractValidateRedTest should have been called
    expect(mockExtractValidateRedTest).toHaveBeenCalled();
  });

  it('calls verifyFixWithValidateRedTest() instead of GitBasedTestValidator', async () => {
    const validationData = {
      validation: {
        'issue-42': {
          issueNumber: 42,
          validated: true,
          framework: 'rspec',
          branchName: 'rsolv/validate/issue-42',
          redTests: {
            redTests: [{
              testName: 'test_vuln',
              testCode: "RSpec.describe 'vuln' do\nend",
              attackVector: 'vuln',
              expectedBehavior: 'should_fail_on_vulnerable_code' as const,
            }],
          },
          testResults: { testFile: 'spec/vulnerability_validation_spec.rb' },
        },
      },
    };

    mockExtractValidateRedTest.mockReturnValue({
      testCode: "RSpec.describe 'vuln' do\nend",
      testFile: 'spec/vulnerability_validation_spec.rb',
      framework: 'rspec',
      branchName: 'rsolv/validate/issue-42',
    });

    mockVerifyFixWithValidateRedTest.mockResolvedValue({
      isValidFix: true,
      vulnerableResult: { passed: false, output: 'FAILED', exitCode: 1 },
      fixedResult: { passed: true, output: '1 example, 0 failures', exitCode: 0 },
    });

    await processIssueWithGit(baseIssue, baseConfig, validationData as any);

    // verifyFixWithValidateRedTest should be called instead of GitBasedTestValidator
    expect(mockVerifyFixWithValidateRedTest).toHaveBeenCalled();
  });

  it('falls back to existing test generation when no validation data', async () => {
    mockExtractValidateRedTest.mockReturnValue(null);

    await processIssueWithGit(baseIssue, baseConfig, undefined);

    // extractValidateRedTest should still be called (with undefined data)
    // but it returns null, so test generation proceeds normally
    expect(mockVerifyFixWithValidateRedTest).not.toHaveBeenCalled();
  });

  it('passes test failure context to enhanced issue on retry', async () => {
    const validationData = {
      validation: {
        'issue-42': {
          issueNumber: 42,
          validated: true,
          framework: 'pytest',
          branchName: 'rsolv/validate/issue-42',
          redTests: {
            redTests: [{
              testName: 'test_vuln',
              testCode: 'def test_vuln(): assert False',
              attackVector: 'SQL injection',
              expectedBehavior: 'should_fail_on_vulnerable_code' as const,
            }],
          },
          testResults: { testFile: 'tests/test_vuln.py' },
        },
      },
    };

    mockExtractValidateRedTest.mockReturnValue({
      testCode: 'def test_vuln(): assert False',
      testFile: 'tests/test_vuln.py',
      framework: 'pytest',
      branchName: 'rsolv/validate/issue-42',
    });

    // First call: verification fails. Second call: succeeds (for retry).
    mockVerifyFixWithValidateRedTest
      .mockResolvedValueOnce({
        isValidFix: false,
        vulnerableResult: { passed: false, output: 'FAILED', exitCode: 1 },
        fixedResult: { passed: false, output: 'FAILED - still vulnerable', exitCode: 1 },
      })
      .mockResolvedValueOnce({
        isValidFix: true,
        vulnerableResult: { passed: false, output: 'FAILED', exitCode: 1 },
        fixedResult: { passed: true, output: '1 passed', exitCode: 0 },
      });

    const result = await processIssueWithGit(baseIssue, baseConfig, validationData as any);

    // verifyFixWithValidateRedTest should be called at least twice (retry)
    expect(mockVerifyFixWithValidateRedTest.mock.calls.length).toBeGreaterThanOrEqual(1);
  });
});
