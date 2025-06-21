import { describe, test, expect, beforeEach, mock } from 'bun:test';
import { EnhancedClaudeCodeAdapter } from '../claude-code-enhanced';
import { AIConfig } from '../../types';
import { IssueContext } from '../../../types';
import fs from 'fs';

// Mock fs module
mock.module('fs', () => ({
  existsSync: () => true,
  writeFileSync: () => {},
  readFileSync: () => '{}',
  unlinkSync: () => {}
}));

// Mock the base ClaudeCodeAdapter
mock.module('../claude-code', () => {
  class MockClaudeCodeAdapter {
    config: AIConfig;
    repoPath: string;
    credentialManager?: any;
    tempDir: string = '/tmp';
    
    constructor(config: AIConfig, repoPath: string, credentialManager?: any) {
      this.config = config;
      this.repoPath = repoPath;
      this.credentialManager = credentialManager;
    }
    
    async isAvailable(): Promise<boolean> {
      return true;
    }
    
    async executeClaudeCode(): Promise<string> {
      return JSON.stringify({
        type: 'context_response',
        architecture: {
          patterns: ['MVC'],
          structure: 'standard',
          mainComponents: ['controllers', 'models', 'views']
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
      });
    }
  }
  
  return { ClaudeCodeAdapter: MockClaudeCodeAdapter };
});

describe('EnhancedClaudeCodeAdapter', () => {
  let adapter: EnhancedClaudeCodeAdapter;
  let mockCredentialManager: any;
  let config: AIConfig;
  
  beforeEach(() => {
    // Create a mock credential manager
    mockCredentialManager = {
      getCredential: mock((provider: string) => {
        if (provider === 'anthropic') {
          return 'vended-anthropic-key-12345';
        }
        throw new Error(`No credential for ${provider}`);
      }),
      initialize: mock(async () => {}),
      cleanup: mock(() => {}),
      reportUsage: mock(async () => {})
    };
    
    config = {
      provider: 'claude-code',
      apiKey: 'test-key',
      useVendedCredentials: true,
      claudeCodeConfig: {
        contextCacheDuration: 1800000 // 30 minutes
      }
    };
  });
  
  describe('constructor', () => {
    test('should accept credential manager as third parameter', () => {
      adapter = new EnhancedClaudeCodeAdapter(config, '/test/repo', mockCredentialManager);
      
      // The adapter should have the credential manager
      expect(adapter).toBeDefined();
      expect((adapter as any).credentialManager).toBe(mockCredentialManager);
    });
    
    test('should work without credential manager', () => {
      adapter = new EnhancedClaudeCodeAdapter(config, '/test/repo');
      
      expect(adapter).toBeDefined();
      expect((adapter as any).credentialManager).toBeUndefined();
    });
    
    test('should pass credential manager to base class', () => {
      adapter = new EnhancedClaudeCodeAdapter(config, '/test/repo', mockCredentialManager);
      
      // Since we're using a mocked base class, we can check that it received the credential manager
      // The base class constructor should have been called with the credential manager
      expect((adapter as any).credentialManager).toBe(mockCredentialManager);
    });
  });
  
  describe('credential manager integration', () => {
    test('should use vended credentials when available', async () => {
      adapter = new EnhancedClaudeCodeAdapter(config, '/test/repo', mockCredentialManager);
      
      const issueContext: IssueContext = {
        id: 'test-123',
        number: 1,
        title: 'Test Issue',
        body: 'Test body',
        labels: [],
        assignees: [],
        repository: {
          fullName: 'test/repo',
          language: 'TypeScript',
          defaultBranch: 'main'
        },
        author: 'testuser',
        createdAt: new Date().toISOString(),
        platform: 'github'
      };
      
      // This should work with the vended credentials
      const result = await adapter.gatherDeepContext(issueContext, {
        enableUltraThink: false,
        maxExplorationTime: 60000,
        contextDepth: 'medium',
        includeArchitectureAnalysis: true,
        includeTestPatterns: true,
        includeStyleGuide: true,
        includeDependencyAnalysis: true
      });
      
      expect(result).toBeDefined();
      expect(result.architecture).toBeDefined();
      expect(result.architecture.patterns).toContain('MVC');
    });
    
    test('should handle missing credential manager gracefully', async () => {
      config.useVendedCredentials = true;
      adapter = new EnhancedClaudeCodeAdapter(config, '/test/repo'); // No credential manager
      
      const issueContext: IssueContext = {
        id: 'test-456',
        number: 2,
        title: 'Test Issue 2',
        body: 'Test body 2',
        labels: [],
        assignees: [],
        repository: {
          fullName: 'test/repo',
          language: 'TypeScript',
          defaultBranch: 'main'
        },
        author: 'testuser',
        createdAt: new Date().toISOString(),
        platform: 'github'
      };
      
      // Should still work but use config API key instead
      const result = await adapter.gatherDeepContext(issueContext, {
        enableUltraThink: false,
        maxExplorationTime: 60000,
        contextDepth: 'shallow',
        includeArchitectureAnalysis: true,
        includeTestPatterns: false,
        includeStyleGuide: false,
        includeDependencyAnalysis: false
      });
      
      expect(result).toBeDefined();
    });
  });
  
  describe('configuration inheritance', () => {
    test('should inherit all config properties from base class', () => {
      const customConfig: AIConfig = {
        provider: 'claude-code',
        apiKey: 'custom-key',
        model: 'claude-3',
        temperature: 0.5,
        maxTokens: 2000,
        useVendedCredentials: false,
        claudeCodeConfig: {
          executablePath: '/custom/path/claude',
          tempDir: '/custom/temp',
          contextCacheDuration: 7200000,
          verboseLogging: true,
          contextOptions: {
            maxDepth: 5,
            explorationBreadth: 3,
            includeDirs: ['src', 'lib'],
            excludeDirs: ['node_modules', 'dist']
          }
        }
      };
      
      adapter = new EnhancedClaudeCodeAdapter(customConfig, '/test/repo', mockCredentialManager);
      
      // Verify the config was passed correctly
      expect((adapter as any).config).toEqual(customConfig);
      expect((adapter as any).repoPath).toBe('/test/repo');
      expect((adapter as any).credentialManager).toBe(mockCredentialManager);
    });
  });
});