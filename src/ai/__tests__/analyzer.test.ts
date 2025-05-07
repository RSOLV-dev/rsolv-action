import { describe, expect, test, mock } from 'bun:test';
import { analyzeIssue } from '../analyzer.js';
import { IssueContext } from '../../types.js';
import { AIConfig } from '../types.js';

// Mock the AI client
mock.module('../client', () => {
  return {
    getAIClient: () => ({
      analyzeIssue: async () => ({
        summary: 'Test summary',
        complexity: 'medium' as const,
        estimatedTime: 45,
        potentialFixes: ['Fix 1', 'Fix 2'],
        recommendedApproach: 'Fix 1',
        relatedFiles: ['src/component.ts', 'src/util.ts'],
        requiredChanges: ['Update error handling', 'Add validation']
      })
    })
  };
});

describe('Issue Analyzer', () => {
  test('analyzeIssue should return analysis from AI client', async () => {
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
    
    const aiConfig: AIConfig = {
      provider: 'anthropic',
      apiKey: 'test-api-key'
    };
    
    const analysis = await analyzeIssue(issueContext, aiConfig);
    
    expect(analysis).toBeDefined();
    expect(analysis.summary).toBe('Test summary');
    expect(analysis.complexity).toBe('medium');
    expect(analysis.estimatedTime).toBe(45);
    expect(analysis.potentialFixes).toContain('Fix 1');
    expect(analysis.relatedFiles).toContain('src/component.ts');
    expect(analysis.requiredChanges).toContain('Update error handling');
  });
});