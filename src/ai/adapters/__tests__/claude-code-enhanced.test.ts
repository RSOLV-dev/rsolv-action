import { describe, expect, test, beforeEach, mock } from 'bun:test';
import { EnhancedClaudeCodeAdapter } from '../claude-code-enhanced.js';
import { AIConfig } from '../../types.js';
import { IssueContext } from '../../../types/index.js';
import path from 'path';

// Mock the parent class
mock.module('../claude-code.js', () => ({
  ClaudeCodeAdapter: class MockClaudeCodeAdapter {
    tempDir: string;
    
    constructor(public config: AIConfig, public repoPath: string, public credentialManager?: any) {
      this.tempDir = path.join(process.cwd(), 'temp');
    }
    
    async generateSolution(issueContext: any, analysis: any, prompt?: string) {
      // Mock successful solution generation
      return {
        success: true,
        message: 'Solution generated',
        changes: {
          'test.js': 'console.log("fixed");'
        }
      };
    }
  }
}));

// Mock logger
mock.module('../../../utils/logger.js', () => ({
  logger: {
    info: mock(() => {}),
    error: mock(() => {}),
    warn: mock(() => {}),
    debug: mock(() => {})
  }
}));

describe('EnhancedClaudeCodeAdapter', () => {
  let adapter: EnhancedClaudeCodeAdapter;
  let mockConfig: AIConfig;
  let mockIssueContext: IssueContext;
  
  beforeEach(() => {
    mockConfig = {
      provider: 'claude-code',
      apiKey: 'test-key',
      claudeCodeConfig: {
        contextCacheDuration: 3600000
      }
    };
    
    mockIssueContext = {
      id: 'test-123',
      number: 123,
      title: 'Test Issue',
      body: 'Test description',
      labels: [],
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
    
    adapter = new EnhancedClaudeCodeAdapter(mockConfig, '/test/repo');
  });

  describe('gatherDeepContext', () => {
    test('should gather context successfully', async () => {
      const options = {
        contextDepth: 'standard' as const,
        maxExplorationTime: 60000,
        includeTests: true,
        includeStyleGuide: true
      };
      
      const context = await adapter.gatherDeepContext(mockIssueContext, options);
      
      expect(context).toBeDefined();
      expect(context.architecture).toBeDefined();
      expect(context.codeConventions).toBeDefined();
      expect(context.testingPatterns).toBeDefined();
    });

    test('should use cached context on second call', async () => {
      const options = {
        contextDepth: 'standard' as const,
        maxExplorationTime: 60000,
        includeTests: true,
        includeStyleGuide: false
      };
      
      // First call
      const context1 = await adapter.gatherDeepContext(mockIssueContext, options);
      
      // Second call with same parameters
      const context2 = await adapter.gatherDeepContext(mockIssueContext, options);
      
      // Should be the same object (cached)
      expect(context1).toBe(context2);
    });

    test('should handle errors gracefully', async () => {
      // Mock generateSolution to throw an error
      adapter.generateSolution = mock(() => {
        throw new Error('Test error');
      });
      
      const options = {
        contextDepth: 'deep' as const,
        maxExplorationTime: 60000,
        includeTests: true,
        includeStyleGuide: true
      };
      
      const context = await adapter.gatherDeepContext(mockIssueContext, options);
      
      // Should return minimal context on error
      expect(context).toBeDefined();
      expect(context.architecture.structure).toBe('Standard');
    });
  });

  describe('generateEnhancedSolution', () => {
    test('should generate enhanced solution with deep context', async () => {
      const analysis = {
        complexity: 'medium' as const,
        estimatedTime: 30,
        relatedFiles: ['test.js']
      };
      
      // Mock the generateSolution method to return a PullRequestSolution
      adapter.generateSolution = mock(async () => ({
        title: 'Fix: Test Issue',
        description: 'This PR fixes the test issue',
        files: [
          {
            path: 'test.js',
            content: 'console.log("fixed");',
            operation: 'modify' as const
          }
        ]
      }));
      
      const result = await adapter.generateEnhancedSolution(
        mockIssueContext,
        analysis
      );
      
      expect(result).toBeDefined();
      expect(result.title).toBeDefined();
      expect(result.description).toBeDefined();
      expect(result.files).toBeArray();
    });

    test('should use enhanced prompt when provided', async () => {
      const analysis = {
        complexity: 'simple' as const,
        estimatedTime: 15,
        relatedFiles: []
      };
      
      const enhancedPrompt = 'Custom enhanced prompt';
      
      // Mock to capture the prompt
      let capturedPrompt: string | undefined;
      adapter.generateSolution = mock(async (issue, anal, prompt) => {
        capturedPrompt = prompt;
        return {
          title: 'Fix: Simple Issue',
          description: 'This PR fixes a simple issue',
          files: [
            {
              path: 'test.js',
              content: 'fixed',
              operation: 'modify' as const
            }
          ]
        };
      });
      
      await adapter.generateEnhancedSolution(
        mockIssueContext,
        analysis,
        enhancedPrompt
      );
      
      expect(capturedPrompt).toContain(enhancedPrompt);
      expect(capturedPrompt).toContain('ultrathink');
    });
  });

  describe('integration with context caching', () => {
    test('should build proper context gathering prompt', async () => {
      const options = {
        contextDepth: 'ultra' as const,
        maxExplorationTime: 300000,
        includeTests: true,
        includeStyleGuide: true
      };
      
      // Access private method through any
      const prompt = (adapter as any).buildContextGatheringPrompt(mockIssueContext, options);
      
      expect(prompt).toContain('comprehensive analysis');
      expect(prompt).toContain('Test Issue');
      expect(prompt).toContain('Style Guide and Best Practices');
    });

    test('should create minimal context correctly', () => {
      const context = (adapter as any).createMinimalContext();
      
      expect(context.architecture).toBeDefined();
      expect(context.architecture.structure).toBe('Standard');
      expect(context.codeConventions).toBeDefined();
      expect(context.testingPatterns).toBeDefined();
      expect(context.dependencies).toBeDefined();
      expect(context.relatedComponents).toBeDefined();
      expect(context.styleGuide).toBeDefined();
    });
  });
});