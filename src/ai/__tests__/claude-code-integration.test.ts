import { describe, expect, test, beforeEach, mock } from 'bun:test';
import { ClaudeCodeAdapter } from '../adapters/claude-code.js';
import { getAiClient } from '../client.js';
import { AIConfig } from '../types.js';

// Check if we should use real APIs
const USE_REAL_APIS = process.env.USE_REAL_CLAUDE_CODE === 'true';

describe('Claude Code Integration Tests', () => {
  let config: AIConfig;
  
  beforeEach(() => {
    if (!USE_REAL_APIS) {
      // Mock modules for unit testing
      mock.module('../../utils/logger', () => ({
        logger: {
          info: mock(() => {}),
          warn: mock(() => {}),
          error: mock(() => {}),
          debug: mock(() => {})
        }
      }));
      
      // Mock child_process for CLI simulation
      mock.module('child_process', () => ({
        spawn: () => ({
          stdout: { on: mock(() => {}) },
          stderr: { on: mock(() => {}) },
          on: (event: string, cb: Function) => {
            if (event === 'close') setTimeout(() => cb(0), 10);
          }
        })
      }));
    }
    
    config = {
      provider: 'claude-code',
      model: 'claude-3-sonnet-20240229',
      temperature: 0.2,
      maxTokens: 4000
    };
  });

  test('should create Claude Code adapter through getAiClient', async () => {
    // This test works with both mocked and real scenarios
    const client = await getAiClient(config);
    expect(client).toBeDefined();
    
    // The client should have the complete method
    expect(typeof client.complete).toBe('function');
  });

  describe.skipIf(!USE_REAL_APIS)('Real Claude Code API Tests', () => {
    test('should make real API call to Claude Code', async () => {
      const adapter = new ClaudeCodeAdapter(config);
      
      const issueContext = {
        id: 'real-123',
        number: 1,
        title: 'Add input validation to user registration',
        body: 'We need to validate email addresses and passwords in the registration form',
        labels: ['enhancement'],
        assignees: [],
        repository: {
          owner: 'test',
          name: 'repo',
          fullName: 'test/repo',
          defaultBranch: 'main',
          language: 'TypeScript'
        },
        source: 'github' as const,
        url: 'https://github.com/test/repo/issues/1',
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString()
      };

      const analysis = {
        summary: 'Add validation for user registration inputs',
        complexity: 'low' as const,
        estimatedTime: 30,
        potentialFixes: ['Add email regex validation', 'Add password strength checks'],
        recommendedApproach: 'Use a validation library like Joi or Yup',
        relatedFiles: ['src/routes/auth.ts', 'src/validators/user.ts']
      };

      console.log('Making real API call to Claude Code...');
      const startTime = Date.now();
      
      const solution = await adapter.generateSolution(issueContext, analysis);
      
      const duration = Date.now() - startTime;
      console.log(`API call completed in ${duration}ms`);
      console.log('Response:', JSON.stringify(solution, null, 2));
      
      expect(solution).toBeDefined();
      expect(solution.success).toBeDefined();
      
      // Log usage analytics if available
      const analytics = adapter.getAnalytics();
      if (analytics.totalCalls > 0) {
        console.log('Usage Analytics:', analytics);
      }
    }, 60000); // 60 second timeout for real API calls
  });

  describe.skipIf(USE_REAL_APIS)('Mocked Claude Code Tests', () => {
    test('should handle mocked responses correctly', async () => {
      // This uses the mocked child_process
      const adapter = new ClaudeCodeAdapter(config);
      const available = await adapter.isAvailable();
      
      // In mocked mode, this depends on our mock setup
      expect(typeof available).toBe('boolean');
    });
  });
});

// Separate test for comparing mocked vs real responses
describe.skipIf(!USE_REAL_APIS || !process.env.COMPARE_MODE)('Mock vs Real Comparison', () => {
  test('should compare mocked and real responses', async () => {
    const testIssue = {
      id: 'compare-123',
      number: 1,
      title: 'Simple bug fix needed',
      body: 'Fix the typo in the error message',
      labels: ['bug'],
      assignees: [],
      repository: {
        owner: 'test',
        name: 'repo',
        fullName: 'test/repo',
        defaultBranch: 'main',
        language: 'JavaScript'
      },
      source: 'github' as const,
      url: 'https://github.com/test/repo/issues/1',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    };

    const analysis = {
      summary: 'Fix typo in error message',
      complexity: 'low' as const,
      estimatedTime: 15,
      potentialFixes: ['Update the error message string'],
      recommendedApproach: 'Find and replace the typo',
      relatedFiles: ['src/errors.js']
    };

    // Get mocked response
    mock.module('child_process', () => ({
      spawn: () => ({
        stdout: { 
          on: (event: string, cb: Function) => {
            if (event === 'data') {
              cb(Buffer.from('{"title":"Fix typo","files":[{"path":"src/errors.js","changes":"Fixed"}]}'));
            }
          }
        },
        stderr: { on: () => {} },
        on: (event: string, cb: Function) => {
          if (event === 'close') cb(0);
        }
      })
    }));
    
    const mockedAdapter = new ClaudeCodeAdapter(config);
    const mockedSolution = await mockedAdapter.generateSolution(testIssue, analysis);
    
    // Reset mocks
    mock.restore();
    
    // Get real response
    const realAdapter = new ClaudeCodeAdapter(config);
    const realSolution = await realAdapter.generateSolution(testIssue, analysis);
    
    console.log('Mocked solution:', mockedSolution);
    console.log('Real solution:', realSolution);
    
    // Compare structures
    expect(Object.keys(mockedSolution)).toEqual(Object.keys(realSolution));
    expect(mockedSolution.success).toBeDefined();
    expect(realSolution.success).toBeDefined();
  }, 90000);
});