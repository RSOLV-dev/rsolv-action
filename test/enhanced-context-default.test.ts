import { describe, it, expect, beforeEach, vi, jest } from 'vitest';

// Mock modules before importing dependencies
const analyzeIssueMock = vi.fn();
const gatherDeepContextMock = vi.fn();

vi.mock('../src/ai/analyzer', () => ({
  analyzeIssue: analyzeIssueMock
}));

vi.mock('../src/ai/adapters/claude-code-enhanced', () => ({
  EnhancedClaudeCodeAdapter: class {
    gatherDeepContext = gatherDeepContextMock;
  }
}));

// Now import after mocks are set up
import { processIssues } from '../src/ai/unified-processor';
import { IssueContext, ActionConfig } from '../src/types';

describe('Enhanced Context Default Behavior', () => {
  const mockIssue: IssueContext = {
    id: 'test-1',
    number: 1,
    title: 'Test vulnerability',
    body: 'Test issue body',
    labels: ['rsolv:automate'],
    assignees: [],
    repository: {
      owner: 'test',
      name: 'repo',
      fullName: 'test/repo',
      defaultBranch: 'main'
    },
    source: 'github',
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString()
  };

  const mockConfig: ActionConfig = {
    apiKey: 'test-key',
    configPath: '.github/rsolv.yml',
    issueLabel: 'rsolv:automate',
    aiProvider: {
      provider: 'claude-code',
      model: 'claude-3',
      apiKey: 'test-key'
    },
    containerConfig: {
      enabled: false
    },
    securitySettings: {},
    rsolvApiKey: 'test-rsolv-key'
  };

  beforeEach(() => {
    vi.clearAllMocks();
    
    // Setup default mock behavior
    analyzeIssueMock.mockResolvedValue({
      canBeFixed: true,
      issueType: 'security',
      filesToModify: ['test.js'],
      estimatedComplexity: 'simple',
      requiredContext: [],
      suggestedApproach: 'Fix vulnerability'
    });
    
    gatherDeepContextMock.mockResolvedValue({
      architecture: { patterns: [], structure: '', mainComponents: [] },
      codeConventions: { namingPatterns: [], fileOrganization: '', importPatterns: [] },
      testingPatterns: { framework: '', structure: '', conventions: [] },
      dependencies: { runtime: [], dev: [], patterns: [] },
      relatedComponents: { files: [], modules: [], interfaces: [] },
      styleGuide: { formatting: '', documentation: '', errorHandling: '' }
    });
  });

  it('should NOT enable enhanced context by default', async () => {
    // Test with no options (should use defaults)
    try {
      await processIssues([mockIssue], mockConfig);
    } catch (error) {
      // It's okay if it fails, we just want to check if gatherDeepContext was called
    }

    // Enhanced context should NOT be called by default
    expect(gatherDeepContextMock).not.toHaveBeenCalled();
  });

  it('should enable enhanced context only when explicitly requested', async () => {
    // Test with enhanced context explicitly enabled
    const options = {
      enableEnhancedContext: true,
      enableSecurityAnalysis: false
    };

    try {
      await processIssues([mockIssue], mockConfig, options);
    } catch (error) {
      // Expected to fail without full mocks
    }

    // Should be called when explicitly enabled
    expect(gatherDeepContextMock).toHaveBeenCalled();
  });
});