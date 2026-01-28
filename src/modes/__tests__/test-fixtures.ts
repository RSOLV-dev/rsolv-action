/**
 * Shared test fixtures for ValidationMode tests
 *
 * Centralizes common test data factories to avoid duplication
 * across scan-test-files-patterns, force-commit-output-format,
 * and test-result-classification test files.
 */

import { ActionConfig, IssueContext } from '../../types/index.js';

/**
 * Creates a minimal ActionConfig suitable for ValidationMode tests.
 * Uses test/dummy values for all required fields.
 */
export function createTestConfig(overrides?: Partial<ActionConfig>): ActionConfig {
  return {
    apiKey: 'test-key',
    rsolvApiKey: 'test-rsolv-key',
    githubToken: 'test-token',
    configPath: '.rsolv/config.json',
    issueLabel: 'rsolv:automate',
    mode: 'validate',
    executableTests: true,
    aiProvider: {
      apiKey: 'test-ai-key',
      model: 'claude-sonnet-4-5-20250929',
      provider: 'anthropic',
      ...overrides?.aiProvider
    },
    containerConfig: {
      enabled: false,
      ...overrides?.containerConfig
    },
    securitySettings: {
      disableNetworkAccess: false,
      ...overrides?.securitySettings
    },
    ...overrides
  } as ActionConfig;
}

/**
 * Creates a minimal IssueContext suitable for ValidationMode tests.
 * Defaults to a SQL injection scenario against a Ruby controller.
 */
export function createTestIssue(overrides?: Partial<IssueContext>): IssueContext {
  return {
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
      ...overrides?.repository
    },
    source: 'github',
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    metadata: {},
    ...overrides
  } as IssueContext;
}
