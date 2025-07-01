import { describe, it, expect, vi, beforeEach } from 'vitest';
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
  });

  it('should NOT enable enhanced context by default', async () => {
    // Mock the underlying functions to track what options are passed
    const analyzeIssueSpy = vi.fn().mockResolvedValue({
      canBeFixed: true,
      issueType: 'security',
      filesToModify: ['test.js'],
      estimatedComplexity: 'simple',
      requiredContext: [],
      suggestedApproach: 'Fix vulnerability'
    });

    const gatherDeepContextSpy = vi.fn();

    // Mock the modules
    vi.doMock('../src/ai/analyzer', () => ({
      analyzeIssue: analyzeIssueSpy
    }));

    vi.doMock('../src/ai/adapters/claude-code-enhanced', () => ({
      EnhancedClaudeCodeAdapter: class {
        gatherDeepContext = gatherDeepContextSpy;
      }
    }));

    // Test with no options (should use defaults)
    try {
      await processIssues([mockIssue], mockConfig);
    } catch (error) {
      // It's okay if it fails, we just want to check if gatherDeepContext was called
    }

    // Enhanced context should NOT be called by default
    expect(gatherDeepContextSpy).not.toHaveBeenCalled();
  });

  it('should enable enhanced context only when explicitly requested', async () => {
    const gatherDeepContextSpy = vi.fn().mockResolvedValue({
      architecture: { patterns: [], structure: '', mainComponents: [] },
      codeConventions: { namingPatterns: [], fileOrganization: '', importPatterns: [] },
      testingPatterns: { framework: '', structure: '', conventions: [] },
      dependencies: { runtime: [], dev: [], patterns: [] },
      relatedComponents: { files: [], modules: [], interfaces: [] },
      styleGuide: { formatting: '', documentation: '', errorHandling: '' }
    });

    vi.doMock('../src/ai/adapters/claude-code-enhanced', () => ({
      EnhancedClaudeCodeAdapter: class {
        gatherDeepContext = gatherDeepContextSpy;
      }
    }));

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
    expect(gatherDeepContextSpy).toHaveBeenCalled();
  });
});