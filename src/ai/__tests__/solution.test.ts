import { describe, expect, test, mock } from 'bun:test';
import { generateSolution } from '../solution.js';
import { IssueContext } from '../../types.js';
import { AIConfig, IssueAnalysis } from '../types.js';

// Mock the AI client
mock.module('../client', () => {
  return {
    getAIClient: () => ({
      generateSolution: async () => ({
        title: 'Fix: Update error handling in component',
        description: 'This PR fixes the error handling in the component',
        files: [
          {
            path: 'src/component.ts',
            changes: 'Updated component code with better error handling'
          },
          {
            path: 'src/util.ts',
            changes: 'Added validation functions'
          }
        ],
        tests: ['Test error handling', 'Test validation']
      })
    })
  };
});

describe('Solution Generator', () => {
  test('generateSolution should return solution from AI client', async () => {
    const issueContext: IssueContext = {
      id: '123',
      source: 'github',
      title: 'Test Issue',
      body: 'This is a test issue description',
      labels: ['bug', 'AUTOFIX'],
      repository: {
        owner: 'test-owner',
        name: 'test-repo',
        branch: 'main'
      },
      metadata: {},
      url: 'https://github.com/test-owner/test-repo/issues/123'
    };
    
    const analysis: IssueAnalysis = {
      summary: 'Test summary',
      complexity: 'medium',
      estimatedTime: 45,
      potentialFixes: ['Fix 1', 'Fix 2'],
      recommendedApproach: 'Fix 1',
      relatedFiles: ['src/component.ts', 'src/util.ts'],
      requiredChanges: ['Update error handling', 'Add validation']
    };
    
    const aiConfig: AIConfig = {
      provider: 'anthropic',
      apiKey: 'test-api-key'
    };
    
    const solution = await generateSolution(issueContext, analysis, aiConfig);
    
    expect(solution).toBeDefined();
    expect(solution.title).toBe('Fix: Update error handling in component');
    expect(solution.description).toContain('fixes the error handling');
    expect(solution.files).toHaveLength(2);
    expect(solution.files[0].path).toBe('src/component.ts');
    expect(solution.files[1].path).toBe('src/util.ts');
    expect(solution.tests).toContain('Test error handling');
  });
});