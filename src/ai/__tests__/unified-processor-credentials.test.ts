import { describe, test, expect, beforeEach, mock } from 'bun:test';
import { processIssue } from '../unified-processor';
import { IssueContext } from '../../types';
import { ActionConfig } from '../../config';

// Mock the credential manager module
mock.module('../../credentials/manager', () => ({
  RSOLVCredentialManager: class {
    private apiKey: string = '';
    
    async initialize(apiKey: string) {
      this.apiKey = apiKey;
      return Promise.resolve();
    }
    
    getCredential(provider: string) {
      if (provider === 'anthropic') {
        return 'vended-anthropic-key-test';
      }
      throw new Error(`No credential for ${provider}`);
    }
    
    cleanup() {}
    
    async reportUsage() {}
  }
}));

// Mock the enhanced claude code adapter
let mockCredentialManagerReceived: any = null;
mock.module('../adapters/claude-code-enhanced', () => ({
  EnhancedClaudeCodeAdapter: class {
    config: any;
    repoPath: string;
    credentialManager: any;
    
    constructor(config: any, repoPath: string, credentialManager?: any) {
      this.config = config;
      this.repoPath = repoPath;
      this.credentialManager = credentialManager;
      // Capture the credential manager for testing
      mockCredentialManagerReceived = credentialManager;
    }
    
    async gatherDeepContext() {
      return {
        architecture: {
          patterns: ['MVC'],
          structure: 'test',
          mainComponents: ['test']
        },
        codeConventions: {
          namingPatterns: ['camelCase'],
          fileOrganization: 'modular',
          importPatterns: ['ES6']
        },
        testingPatterns: {
          framework: 'jest',
          structure: 'colocated',
          conventions: ['describe/it']
        },
        dependencies: {
          runtime: ['express'],
          dev: ['jest'],
          patterns: ['npm']
        }
      };
    }
  }
}));

// Mock other dependencies
mock.module('../analysis', () => ({
  analyzeIssue: async () => ({
    canBeFixed: true,
    issueType: 'bug',
    estimatedComplexity: 'medium',
    estimatedTime: 30,
    filesToModify: ['test.js'],
    suggestedApproach: 'Fix the bug'
  })
}));

mock.module('../solution', () => ({
  generateSolution: async () => ({
    success: true,
    changes: {
      'test.js': 'fixed content'
    }
  })
}));

mock.module('../pr', () => ({
  createPullRequest: async () => ({
    success: true,
    pullRequestUrl: 'https://github.com/test/repo/pull/1',
    message: 'PR created'
  })
}));

describe('Unified Processor Credential Manager Passing', () => {
  let config: ActionConfig;
  let issue: IssueContext;
  
  beforeEach(() => {
    // Reset the captured credential manager
    mockCredentialManagerReceived = null;
    
    config = {
      aiProvider: {
        provider: 'claude-code',
        apiKey: '',
        useVendedCredentials: true
      },
      rsolvApiKey: 'rsolv_test_key_123',
      enableSecurityAnalysis: false,
      claudeCodeConfig: {
        enableDeepContext: true
      }
    };
    
    issue = {
      id: 'test-issue-123',
      number: 1,
      title: 'Test Issue',
      body: 'This is a test issue',
      labels: [],
      assignees: [],
      repository: {
        fullName: 'test/repo',
        language: 'JavaScript',
        defaultBranch: 'main'
      },
      author: 'testuser',
      createdAt: new Date().toISOString(),
      platform: 'github'
    };
  });
  
  test('should create and pass credential manager to EnhancedClaudeCodeAdapter when using vended credentials', async () => {
    const result = await processIssue(issue, config, {
      enableEnhancedContext: true
    });
    
    // The credential manager should have been created and passed
    expect(mockCredentialManagerReceived).toBeDefined();
    expect(mockCredentialManagerReceived).not.toBeNull();
    expect(typeof mockCredentialManagerReceived.getCredential).toBe('function');
    
    // Verify the credential manager returns the expected key
    const apiKey = mockCredentialManagerReceived.getCredential('anthropic');
    expect(apiKey).toBe('vended-anthropic-key-test');
    
    // The result should be successful
    expect(result.success).toBe(true);
    expect(result.pullRequestUrl).toBeDefined();
  });
  
  test('should not create credential manager when useVendedCredentials is false', async () => {
    config.aiProvider.useVendedCredentials = false;
    config.aiProvider.apiKey = 'direct-api-key';
    
    const result = await processIssue(issue, config, {
      enableEnhancedContext: true
    });
    
    // No credential manager should be passed
    expect(mockCredentialManagerReceived).toBeUndefined();
    
    // The result should still be successful
    expect(result.success).toBe(true);
  });
  
  test('should not create credential manager when rsolvApiKey is missing', async () => {
    config.rsolvApiKey = undefined;
    
    const result = await processIssue(issue, config, {
      enableEnhancedContext: true
    });
    
    // No credential manager should be passed
    expect(mockCredentialManagerReceived).toBeUndefined();
    
    // The result should still be successful
    expect(result.success).toBe(true);
  });
  
  test('should handle credential manager creation errors gracefully', async () => {
    // Mock a failing credential manager
    mock.module('../../credentials/manager', () => ({
      RSOLVCredentialManager: class {
        async initialize() {
          throw new Error('Failed to initialize credentials');
        }
      }
    }));
    
    // Should not throw, but should continue without credential manager
    const result = await processIssue(issue, config, {
      enableEnhancedContext: true
    });
    
    // Should still complete but without credential manager
    expect(result).toBeDefined();
  });
});