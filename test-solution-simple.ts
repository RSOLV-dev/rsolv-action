#!/usr/bin/env bun
// Simple test of solution generation
import { generateSolution } from './src/ai/solution.js';
import { IssueContext, ActionConfig, AnalysisData } from './src/types/index.js';

async function testSolution() {
  const config: ActionConfig = {
    apiKey: 'rsolv_prod_demo_key',
    configPath: '.github/rsolv.yml',
    issueLabel: 'rsolv:automate',
    enableSecurityAnalysis: true,
    aiProvider: {
      provider: 'anthropic',
      model: 'claude-3-sonnet-20240229',
      temperature: 0.2,
      maxTokens: 4000,
      useVendedCredentials: true
    },
    containerConfig: {
      enabled: false
    },
    securitySettings: {}
  };

  const issue: IssueContext = {
    id: '123',
    number: 1,
    title: 'Fix console.log statement',
    body: 'Change console.log to console.error in test.js',
    labels: ['bug'],
    assignees: [],
    repository: {
      owner: 'test',
      name: 'repo',
      fullName: 'test/repo',
      defaultBranch: 'main',
      language: 'JavaScript'
    },
    source: 'github',
    url: 'https://github.com/test/repo/issues/1',
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString()
  };

  const analysis: AnalysisData = {
    issueType: 'bug',
    filesToModify: ['test.js'],
    estimatedComplexity: 'simple',
    requiredContext: [],
    suggestedApproach: 'Change console.log to console.error',
    canBeFixed: true
  };

  console.log('Testing solution generation...\n');
  
  try {
    const result = await generateSolution(issue, analysis, config);
    
    console.log('Result:', {
      success: result.success,
      message: result.message,
      changesCount: result.changes ? Object.keys(result.changes).length : 0
    });
    
    if (result.changes) {
      console.log('\nChanges:');
      for (const [file, content] of Object.entries(result.changes)) {
        console.log(`\nFile: ${file}`);
        console.log('Content:', content.substring(0, 200) + '...');
      }
    }
  } catch (error) {
    console.error('Error:', error);
  }
}

testSolution();