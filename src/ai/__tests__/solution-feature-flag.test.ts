/**
 * RFC-095: Feature Flag Adapter Selection Tests
 *
 * TDD Test: Verify that solution.ts uses the createClaudeAgentSDKAdapter factory
 * function which respects the use_legacy_claude_adapter feature flag.
 *
 * RED phase: These tests should FAIL until solution.ts is fixed to use the factory.
 */

import { describe, expect, test, vi, beforeEach, afterEach } from 'vitest';
import { generateSolution } from '../solution.js';
import { IssueContext, ActionConfig, AnalysisData } from '../../types/index.js';

// Track which adapter was instantiated
let factoryWasCalled = false;
let legacyAdapterUsed = false;
let sdkAdapterUsed = false;

// Mock credential manager with configurable feature flags
const mockCredentialManager = {
  featureFlags: { use_legacy_claude_adapter: false },
  shouldUseLegacyAdapter: vi.fn(() => mockCredentialManager.featureFlags.use_legacy_claude_adapter),
  exchangeForProviderCredentials: vi.fn(async () => ({
    provider: 'anthropic',
    apiKey: 'mock-api-key',
    model: 'claude-sonnet-4-5-20250929',
    feature_flags: mockCredentialManager.featureFlags
  })),
  getFeatureFlags: vi.fn(() => mockCredentialManager.featureFlags)
};

// Mock the credential singleton to return our mock manager
vi.mock('../../credentials/singleton', () => ({
  CredentialManagerSingleton: {
    getInstance: vi.fn(async () => mockCredentialManager)
  }
}));

// Mock fs/promises for file reading
vi.mock('fs/promises', () => ({
  readFile: async (filePath: string) => {
    const fileContents: Record<string, string> = {
      'src/auth/login.js': 'Fixed SQL injection with parameterized queries',
      'src/auth/validation.js': 'Added input validation'
    };
    if (fileContents[filePath]) {
      return fileContents[filePath];
    }
    throw new Error(`File not found: ${filePath}`);
  }
}));

// Mock the adapters module - THIS IS THE KEY TEST
// We need to verify the FACTORY function is called, not direct class instantiation
vi.mock('../adapters/claude-agent-sdk', () => {
  // Mock Legacy adapter
  class MockGitBasedClaudeCodeAdapter {
    constructor(_config: any, _repoPath: string, _credManager: any) {
      legacyAdapterUsed = true;
    }
    async generateSolution(_issue: any, _analysis: any) {
      return {
        success: true,
        message: 'Fixed via legacy adapter',
        filesModified: ['src/auth/login.js'],
        diffStats: { insertions: 5, deletions: 2, filesChanged: 1 }
      };
    }
  }

  // Mock SDK adapter
  class MockClaudeAgentSDKAdapter {
    constructor(_config: any) {
      sdkAdapterUsed = true;
    }
    async generateSolution(_issue: any, _analysis: any) {
      return {
        success: true,
        message: 'Fixed via SDK adapter',
        filesModified: ['src/auth/login.js', 'src/auth/validation.js'],
        diffStats: { insertions: 10, deletions: 5, filesChanged: 2 }
      };
    }
  }

  // Factory function that respects feature flags
  const createClaudeAgentSDKAdapter = (config: any) => {
    factoryWasCalled = true;
    const useLegacy = config.credentialManager?.shouldUseLegacyAdapter?.() ?? false;

    if (useLegacy) {
      return new MockGitBasedClaudeCodeAdapter(
        { provider: 'anthropic', model: config.model },
        config.repoPath,
        config.credentialManager
      );
    }
    return new MockClaudeAgentSDKAdapter(config);
  };

  return {
    ClaudeAgentSDKAdapter: MockClaudeAgentSDKAdapter,
    createClaudeAgentSDKAdapter,
    GitBasedClaudeCodeAdapter: MockGitBasedClaudeCodeAdapter
  };
});

describe('RFC-095: Feature Flag Adapter Selection', () => {
  const issueContext: IssueContext = {
    id: '456',
    number: 456,
    source: 'github',
    title: 'SQL Injection Security Issue',
    body: 'Fix SQL injection vulnerabilities',
    labels: ['security', 'rsolv:automate'],
    assignees: [],
    repository: {
      owner: 'demo-owner',
      name: 'demo-repo',
      fullName: 'demo-owner/demo-repo',
      defaultBranch: 'main',
      language: 'JavaScript'
    },
    url: 'https://github.com/demo-owner/demo-repo/issues/456',
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString()
  };

  const analysis: AnalysisData = {
    issueType: 'security',
    filesToModify: ['src/auth/login.js', 'src/auth/validation.js'],
    suggestedApproach: 'Fix SQL injection vulnerabilities',
    estimatedComplexity: 'medium',
    requiredContext: [],
    canBeFixed: true,
    confidenceScore: 0.8
  };

  const config: ActionConfig = {
    configPath: '.github/rsolv.yml',
    issueLabel: 'rsolv:automate',
    rsolvApiKey: 'test-rsolv-key',
    aiProvider: {
      provider: 'claude-code',
      model: 'claude-sonnet-4-20250514',
      temperature: 0.2,
      maxTokens: 4000,
      contextLimit: 100000,
      timeout: 60000,
      useVendedCredentials: true  // This triggers credential manager usage
    },
    containerConfig: { enabled: false }
  };

  beforeEach(() => {
    // Reset tracking flags
    factoryWasCalled = false;
    legacyAdapterUsed = false;
    sdkAdapterUsed = false;
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  test('should use createClaudeAgentSDKAdapter factory function (not direct instantiation)', async () => {
    // Set feature flag to use new SDK adapter
    mockCredentialManager.featureFlags.use_legacy_claude_adapter = false;

    await generateSolution(issueContext, analysis, config);

    // THIS TEST WILL FAIL until solution.ts uses the factory
    expect(factoryWasCalled).toBe(true);
  });

  test('should use legacy adapter when use_legacy_claude_adapter flag is true', async () => {
    // Set feature flag to use legacy adapter
    mockCredentialManager.featureFlags.use_legacy_claude_adapter = true;

    await generateSolution(issueContext, analysis, config);

    // THIS TEST WILL FAIL until solution.ts uses the factory
    expect(factoryWasCalled).toBe(true);
    expect(legacyAdapterUsed).toBe(true);
    expect(sdkAdapterUsed).toBe(false);
  });

  test('should use SDK adapter when use_legacy_claude_adapter flag is false', async () => {
    // Set feature flag to use new SDK adapter
    mockCredentialManager.featureFlags.use_legacy_claude_adapter = false;

    await generateSolution(issueContext, analysis, config);

    // THIS TEST WILL FAIL until solution.ts uses the factory
    expect(factoryWasCalled).toBe(true);
    expect(sdkAdapterUsed).toBe(true);
    expect(legacyAdapterUsed).toBe(false);
  });

  test('should call shouldUseLegacyAdapter on credential manager', async () => {
    mockCredentialManager.featureFlags.use_legacy_claude_adapter = false;

    await generateSolution(issueContext, analysis, config);

    // Verify the feature flag check was called
    expect(mockCredentialManager.shouldUseLegacyAdapter).toHaveBeenCalled();
  });
});
