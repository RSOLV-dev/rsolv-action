import { describe, expect, test, mock } from 'bun:test';
import { generateSolution } from '../solution.js';
import { IssueContext, ActionConfig, AnalysisData } from '../../types/index.js';

// Mock the AI client
mock.module('../client', () => {
  return {
    getAiClient: () => ({
      complete: async () => `Here's the solution:

--- src/component.ts ---
\`\`\`
Updated component code with better error handling
\`\`\`

--- src/util.ts ---
\`\`\`
Added validation functions
\`\`\`

This fixes the error handling in the component.`
    })
  };
});

// Mock the GitHub files module
mock.module('../../github/files', () => ({
  getRepositoryFiles: async () => ({
    'src/component.ts': '// Original component code',
    'src/util.ts': '// Original util code'
  })
}));

describe('Solution Generator', () => {
  test('generateSolution should return solution from AI client', async () => {
    const issueContext: IssueContext = {
      id: '123',
      number: 123,
      source: 'github',
      title: 'Test Issue',
      body: 'This is a test issue description',
      labels: ['bug', 'AUTOFIX'],
      assignees: [],
      repository: {
        owner: 'test-owner',
        name: 'test-repo',
        fullName: 'test-owner/test-repo',
        defaultBranch: 'main',
        language: 'JavaScript'
      },
      createdAt: '2023-01-01T00:00:00Z',
      updatedAt: '2023-01-01T00:00:00Z'
    };
    
    const analysis: AnalysisData = {
      issueType: 'bug',
      filesToModify: ['src/component.ts', 'src/util.ts'],
      estimatedComplexity: 'medium',
      requiredContext: [],
      suggestedApproach: 'Fix error handling',
      canBeFixed: true,
      confidenceScore: 0.8
    };
    
    const config: ActionConfig = {
      apiKey: 'test-api-key',
      configPath: '.github/rsolv.yml',
      issueLabel: 'rsolv',
      aiProvider: {
        provider: 'anthropic',
        apiKey: 'test-api-key',
        model: 'claude-3-sonnet'
      },
      containerConfig: {
        enabled: false
      },
      securitySettings: {
        disableNetworkAccess: true
      }
    };
    
    const solution = await generateSolution(issueContext, analysis, config);
    
    expect(solution).toBeDefined();
    expect(solution.success).toBe(true);
    expect(solution.message).toBeDefined();
    expect(solution.changes).toBeDefined();
    expect(solution.changes!['src/component.ts']).toBeDefined();
    expect(solution.changes!['src/util.ts']).toBeDefined();
    expect(solution.changes!['src/component.ts']).toContain('Updated component code');
  });
});