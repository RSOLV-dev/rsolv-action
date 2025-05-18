import { describe, it, expect, jest, beforeEach, afterEach } from '@jest/globals';
import { EnhancedClaudeCodeAdapter } from '../claude-code-enhanced.js';
import { IssueContext } from '../../../types/index.js';
import { AIConfig } from '../../types.js';

// Mock child_process spawn
jest.mock('child_process', () => ({
  spawn: jest.fn().mockReturnValue({
    stdout: {
      on: jest.fn()
    },
    stderr: {
      on: jest.fn()
    },
    on: jest.fn()
  })
}));

// Mock fs
jest.mock('fs', () => ({
  existsSync: jest.fn().mockReturnValue(true),
  mkdirSync: jest.fn(),
  writeFileSync: jest.fn(),
  readFileSync: jest.fn(),
  unlinkSync: jest.fn()
}));

describe('EnhancedClaudeCodeAdapter', () => {
  let adapter: EnhancedClaudeCodeAdapter;
  let mockConfig: AIConfig;
  let mockIssue: IssueContext;

  beforeEach(() => {
    jest.clearAllMocks();
    
    mockConfig = {
      provider: 'claude-code',
      apiKey: 'test-key',
      model: 'claude-3',
      claudeCodeConfig: {
        executablePath: 'claude',
        enableDeepContext: true,
        enableUltraThink: true,
        contextDepth: 'ultra',
        contextGatheringTimeout: 60000,
        trackUsage: false,
        verboseLogging: true
      }
    };

    mockIssue = {
      id: '123',
      number: 1,
      title: 'Test issue',
      body: 'This is a test issue',
      labels: [],
      repository: {
        id: '456',
        name: 'test-repo',
        fullName: 'owner/test-repo',
        owner: 'owner',
        language: 'TypeScript',
        path: '/test/repo'
      },
      createdAt: new Date('2024-01-01'),
      updatedAt: new Date('2024-01-01'),
      state: 'open',
      author: 'testuser'
    };

    adapter = new EnhancedClaudeCodeAdapter(mockConfig, '/test/repo');
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  describe('gatherDeepContext', () => {
    it('should gather deep context with ultra-think enabled', async () => {
      const fs = require('fs');
      const { spawn } = require('child_process');
      
      // Mock successful execution
      const mockSpawn = spawn as jest.Mock;
      const mockProcess = {
        stdout: {
          on: jest.fn((event, callback) => {
            if (event === 'data') {
              callback(Buffer.from(JSON.stringify({
                architecture: {
                  patterns: ['MVC'],
                  structure: 'Modular',
                  mainComponents: ['controllers', 'models', 'views']
                },
                codeConventions: {
                  namingPatterns: ['camelCase'],
                  fileOrganization: 'feature-based',
                  importPatterns: ['relative imports']
                },
                testingPatterns: {
                  framework: 'Jest',
                  structure: 'parallel',
                  conventions: ['describe/it blocks']
                },
                dependencies: {
                  runtime: ['express', 'mongoose'],
                  dev: ['jest', 'typescript'],
                  patterns: ['dependency injection']
                },
                relatedComponents: {
                  files: ['src/user.ts', 'src/auth.ts'],
                  modules: ['auth', 'user'],
                  interfaces: ['IUser', 'IAuth']
                },
                styleGuide: {
                  formatting: 'prettier',
                  documentation: 'jsdoc',
                  errorHandling: 'async/await with try-catch'
                }
              })));
            }
          })
        },
        stderr: {
          on: jest.fn()
        },
        on: jest.fn((event, callback) => {
          if (event === 'close') {
            callback(0);
          }
        })
      };
      mockSpawn.mockReturnValue(mockProcess);
      
      const options = {
        enableUltraThink: true,
        maxExplorationTime: 300000,
        contextDepth: 'ultra' as const,
        includeArchitectureAnalysis: true,
        includeTestPatterns: true,
        includeStyleGuide: true,
        includeDependencyAnalysis: true
      };
      
      const result = await adapter.gatherDeepContext(mockIssue, options);
      
      expect(result).toBeDefined();
      expect(result.architecture.patterns).toContain('MVC');
      expect(result.testingPatterns.framework).toBe('Jest');
      
      // Verify ultrathink was included in prompt
      const writeFileCall = (fs.writeFileSync as jest.Mock).mock.calls[0];
      expect(writeFileCall[1]).toContain('ultrathink');
    });

    it('should use cache when available', async () => {
      const { spawn } = require('child_process');
      
      // Set up cache first
      const options = {
        enableUltraThink: true,
        maxExplorationTime: 300000,
        contextDepth: 'ultra' as const,
        includeArchitectureAnalysis: true,
        includeTestPatterns: true,
        includeStyleGuide: true,
        includeDependencyAnalysis: true
      };
      
      // Mock first call to populate cache
      const mockSpawn = spawn as jest.Mock;
      mockSpawn.mockReturnValueOnce({
        stdout: {
          on: jest.fn((event, callback) => {
            if (event === 'data') {
              callback(Buffer.from(JSON.stringify({
                architecture: { patterns: ['Cached'], structure: 'Cached', mainComponents: [] },
                codeConventions: { namingPatterns: [], fileOrganization: 'Cached', importPatterns: [] },
                testingPatterns: { framework: 'Cached', structure: 'Cached', conventions: [] },
                dependencies: { runtime: [], dev: [], patterns: [] },
                relatedComponents: { files: [], modules: [], interfaces: [] },
                styleGuide: { formatting: 'Cached', documentation: 'Cached', errorHandling: 'Cached' }
              })));
            }
          })
        },
        stderr: { on: jest.fn() },
        on: jest.fn((event, callback) => {
          if (event === 'close') callback(0);
        })
      });
      
      // First call
      const result1 = await adapter.gatherDeepContext(mockIssue, options);
      expect(result1.architecture.patterns).toContain('Cached');
      
      // Second call should use cache
      const result2 = await adapter.gatherDeepContext(mockIssue, options);
      expect(result2.architecture.patterns).toContain('Cached');
      
      // Spawn should only be called once
      expect(mockSpawn).toHaveBeenCalledTimes(1);
    });
  });

  describe('generateEnhancedSolution', () => {
    it('should generate solution with deep context', async () => {
      const { spawn } = require('child_process');
      const mockSpawn = spawn as jest.Mock;
      
      // Mock context gathering
      mockSpawn.mockReturnValueOnce({
        stdout: {
          on: jest.fn((event, callback) => {
            if (event === 'data') {
              callback(Buffer.from(JSON.stringify({
                architecture: { patterns: ['MVC'], structure: 'Modular', mainComponents: [] },
                codeConventions: { namingPatterns: ['camelCase'], fileOrganization: 'Standard', importPatterns: [] },
                testingPatterns: { framework: 'Jest', structure: 'Standard', conventions: [] },
                dependencies: { runtime: [], dev: [], patterns: [] },
                relatedComponents: { files: [], modules: [], interfaces: [] },
                styleGuide: { formatting: 'Standard', documentation: 'JSDoc', errorHandling: 'try-catch' }
              })));
            }
          })
        },
        stderr: { on: jest.fn() },
        on: jest.fn((event, callback) => {
          if (event === 'close') callback(0);
        })
      });
      
      // Mock solution generation
      mockSpawn.mockReturnValueOnce({
        stdout: {
          on: jest.fn((event, callback) => {
            if (event === 'data') {
              callback(Buffer.from(JSON.stringify({
                title: 'Enhanced fix for test issue',
                description: 'Fixed using deep context',
                files: [{
                  path: 'src/test.ts',
                  changes: '// Enhanced fix'
                }],
                tests: ['Test 1']
              })));
            }
          })
        },
        stderr: { on: jest.fn() },
        on: jest.fn((event, callback) => {
          if (event === 'close') callback(0);
        })
      });
      
      const analysis = {
        issueType: 'bug' as const,
        complexity: 'medium' as const,
        relatedFiles: ['src/test.ts'],
        estimatedTime: 30,
        suggestedApproach: 'Fix the bug'
      };
      
      const result = await adapter.generateEnhancedSolution(mockIssue, analysis);
      
      expect(result).toBeDefined();
      expect(result.title).toBe('Enhanced fix for test issue');
      expect(result.description).toBe('Fixed using deep context');
      expect(result.files).toHaveLength(1);
    });
  });

  describe('cache management', () => {
    it('should clear context cache', () => {
      adapter.clearContextCache();
      const stats = adapter.getCacheStats();
      expect(stats.size).toBe(0);
      expect(stats.keys).toHaveLength(0);
    });
    
    it('should return cache statistics', async () => {
      const initialStats = adapter.getCacheStats();
      expect(initialStats.size).toBe(0);
      
      // Add to cache by making a call (mocked)
      const { spawn } = require('child_process');
      const mockSpawn = spawn as jest.Mock;
      mockSpawn.mockReturnValueOnce({
        stdout: {
          on: jest.fn((event, callback) => {
            if (event === 'data') {
              callback(Buffer.from(JSON.stringify({
                architecture: { patterns: [], structure: 'Test', mainComponents: [] },
                codeConventions: { namingPatterns: [], fileOrganization: 'Test', importPatterns: [] },
                testingPatterns: { framework: 'Test', structure: 'Test', conventions: [] },
                dependencies: { runtime: [], dev: [], patterns: [] },
                relatedComponents: { files: [], modules: [], interfaces: [] },
                styleGuide: { formatting: 'Test', documentation: 'Test', errorHandling: 'Test' }
              })));
            }
          })
        },
        stderr: { on: jest.fn() },
        on: jest.fn((event, callback) => {
          if (event === 'close') callback(0);
        })
      });
      
      await adapter.gatherDeepContext(mockIssue, {
        enableUltraThink: true,
        maxExplorationTime: 60000,
        contextDepth: 'ultra',
        includeArchitectureAnalysis: true,
        includeTestPatterns: true,
        includeStyleGuide: true,
        includeDependencyAnalysis: true
      });
      
      const stats = adapter.getCacheStats();
      expect(stats.size).toBe(1);
      expect(stats.keys).toHaveLength(1);
      expect(stats.keys[0]).toContain('owner/test-repo-ultra');
    });
  });
});