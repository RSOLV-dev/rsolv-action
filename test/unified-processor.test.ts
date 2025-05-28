import { describe, test, expect, beforeEach, mock } from 'bun:test';
import { processIssues } from '../src/ai/unified-processor';
import { IssueContext, ActionConfig } from '../src/types';
import * as analyzer from '../src/ai/analyzer';
import * as solution from '../src/ai/solution';
import * as pr from '../src/github/pr';

// Mock the dependencies
mock.module('../src/ai/analyzer', () => ({
  analyzeIssue: mock(() => Promise.resolve({
    canBeFixed: true,
    confidence: 0.9,
    suggestedApproach: 'Fix the bug',
    affectedFiles: ['src/test.ts']
  }))
}));

mock.module('../src/ai/solution', () => ({
  generateSolution: mock(() => Promise.resolve({
    files: [{
      path: 'src/test.ts',
      oldContent: 'bug',
      newContent: 'fixed',
      changes: []
    }],
    description: 'Fixed the bug'
  }))
}));

mock.module('../src/github/pr', () => ({
  createPullRequest: mock(() => Promise.resolve('https://github.com/test/repo/pull/1'))
}));

describe('Unified Processor', () => {
  let mockIssue: IssueContext;
  let mockConfig: ActionConfig;

  beforeEach(() => {
    mockIssue = {
      id: 'test-123',
      number: 123,
      title: 'Test issue',
      body: 'Test issue body',
      author: 'testuser',
      labels: ['bug'],
      url: 'https://github.com/test/repo/issues/123',
      repoOwner: 'test',
      repoName: 'repo',
      files: []
    };

    mockConfig = {
      githubToken: 'test-token',
      aiProvider: 'anthropic',
      aiApiKey: 'test-key',
      aiModel: 'claude-3',
      dryRun: true
    } as ActionConfig;
  });

  test('processes issues with basic configuration', async () => {
    const results = await processIssues([mockIssue], mockConfig);
    
    expect(results).toHaveLength(1);
    expect(results[0].success).toBe(true);
    expect(results[0].pullRequestUrl).toBe('https://github.com/test/repo/pull/1');
  });

  test('processes issues with security analysis enabled', async () => {
    const results = await processIssues([mockIssue], mockConfig, {
      enableSecurityAnalysis: true
    });
    
    expect(results).toHaveLength(1);
    expect(results[0].success).toBe(true);
    // Security analysis would be included if SecurityAwareAnalyzer was properly mocked
  });

  test('processes issues with enhanced context', async () => {
    const enhancedConfig = {
      ...mockConfig,
      aiProvider: 'claude-code' as const
    };
    
    const results = await processIssues([mockIssue], enhancedConfig, {
      enableEnhancedContext: true,
      contextDepth: 'deep'
    });
    
    expect(results).toHaveLength(1);
    expect(results[0].success).toBe(true);
    expect(results[0].enhancedSolution).toBe(true);
  });

  test('handles multiple issues', async () => {
    const issues = [
      { ...mockIssue, id: '1', number: 1 },
      { ...mockIssue, id: '2', number: 2 },
      { ...mockIssue, id: '3', number: 3 }
    ];
    
    const results = await processIssues(issues, mockConfig);
    
    expect(results).toHaveLength(3);
    expect(results.every(r => r.success)).toBe(true);
  });

  test('handles processing errors gracefully', async () => {
    // Mock an error
    const analyzeIssueMock = analyzer.analyzeIssue as any;
    analyzeIssueMock.mockImplementationOnce(() => 
      Promise.reject(new Error('Analysis failed'))
    );
    
    const results = await processIssues([mockIssue], mockConfig);
    
    expect(results).toHaveLength(1);
    expect(results[0].success).toBe(false);
    expect(results[0].message).toContain('Analysis failed');
  });

  test('respects processing options', async () => {
    const options = {
      enableEnhancedContext: false,
      enableSecurityAnalysis: false,
      contextDepth: 'basic' as const,
      verboseLogging: true
    };
    
    const results = await processIssues([mockIssue], mockConfig, options);
    
    expect(results).toHaveLength(1);
    expect(results[0].success).toBe(true);
    expect(results[0].enhancedSolution).toBeFalsy();
  });
});

console.log('✅ Unified processor tests defined');