/**
 * Shared test fixtures for ValidationMode tests
 *
 * Centralizes common test data factories to avoid duplication
 * across scan-test-files-patterns, force-commit-output-format,
 * and test-result-classification test files.
 */

import { ActionConfig, IssueContext } from '../../types/index.js';
import type { ValidationMode } from '../validation-mode.js';

/**
 * Test result classification returned by classifyTestResult().
 */
export interface TestResultClassification {
  type: 'test_passed' | 'test_failed' | 'syntax_error' | 'runtime_error' |
        'missing_dependency' | 'command_not_found' | 'oom_killed' | 'terminated' | 'unknown';
  isValidFailure: boolean;
  reason: string;
}

/**
 * Typed interface exposing ValidationMode's private/protected methods for testing.
 * Avoids `as any` casts while giving tests access to internal methods.
 */
export interface ValidationModeTestAccess {
  scanTestFiles(framework?: string): Promise<string[]>;
  classifyTestResult(exitCode: number, stdout: string, stderr: string): TestResultClassification;
  convertToExecutableTest(testContent: unknown): string;
  sanitizeTestStructure(code: string): string;
  validateTestSyntax(code: string): void;
  createValidationBranch(issue: IssueContext): Promise<string>;
  generateRedTests(issue: IssueContext, analysisData: unknown): Promise<unknown>;
  storeValidationResultWithBranch(
    issue: IssueContext, testResults: unknown, validationResult: unknown, branchName: string
  ): Promise<void>;
  commitTestsToBranch(testContent: unknown, branchName: string, issue?: IssueContext): Promise<void>;
  forceCommitTestsInTestMode(testContent: unknown, branchName: string, issue: IssueContext): Promise<void>;
  validateVulnerability(issue: IssueContext): Promise<unknown>;
}

/**
 * Cast a ValidationMode instance to expose private methods for testing.
 * This provides type-safe access to internals without `as any`.
 */
export function exposeForTesting(vm: ValidationMode): ValidationModeTestAccess {
  return vm as unknown as ValidationModeTestAccess;
}

/**
 * Creates a minimal ActionConfig suitable for ValidationMode tests.
 * Uses test/dummy values for all required fields.
 */
export function createTestConfig(overrides?: Partial<ActionConfig>): ActionConfig {
  const config: ActionConfig = {
    apiKey: 'test-key',
    rsolvApiKey: 'test-rsolv-key',
    repoToken: 'test-token',
    configPath: '.rsolv/config.json',
    issueLabel: 'rsolv:automate',
    executableTests: true,
    aiProvider: {
      apiKey: 'test-ai-key',
      model: 'claude-sonnet-4-5-20250929',
      provider: 'anthropic',
      ...overrides?.aiProvider,
    },
    containerConfig: {
      enabled: false,
      ...overrides?.containerConfig,
    },
    securitySettings: {
      disableNetworkAccess: false,
      ...overrides?.securitySettings,
    },
    ...overrides,
  };
  return config;
}

/**
 * Creates a minimal IssueContext suitable for ValidationMode tests.
 * Defaults to a SQL injection scenario against a Ruby controller.
 */
export function createTestIssue(overrides?: Partial<IssueContext>): IssueContext {
  const issue: IssueContext = {
    id: 'issue-123',
    number: 123,
    title: 'SQL injection in users controller',
    body: 'Vulnerability in app/controllers/users_controller.rb:42',
    labels: ['rsolv:automate'],
    assignees: [],
    file: 'app/controllers/users_controller.rb',
    repository: {
      owner: 'test-org',
      name: 'test-repo',
      fullName: 'test-org/test-repo',
      defaultBranch: 'main',
      ...overrides?.repository,
    },
    source: 'github',
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    metadata: {},
    ...overrides,
  };
  return issue;
}
