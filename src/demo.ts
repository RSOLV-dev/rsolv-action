#!/usr/bin/env bun
/**
 * Demo script for RSOLV action
 * This script simulates the action functionality by processing a GitHub issue and generating a PR
 */
import { GitHubApiClient } from './github/api';
import { GitHubPRManager } from './github/pr';
import { generateSolution } from './ai/solution';
import { analyzeIssue } from './ai/analyzer';
import { AIConfig } from './ai/types';
import { IssueContext } from './types';

// Ensure GitHub token is set
const GITHUB_TOKEN = process.env.GITHUB_TOKEN;
if (!GITHUB_TOKEN) {
  console.error('❌ Error: GITHUB_TOKEN environment variable is not set');
  console.error('Please set it with: export GITHUB_TOKEN=your_github_token');
  process.exit(1);
}

// Get issue URL from command line arguments
const issueUrl = process.argv[2];
if (!issueUrl) {
  console.error('❌ Error: No issue URL provided');
  console.error('Usage: bun run demo <issue_url>');
  console.error('Example: bun run demo https://github.com/owner/repo/issues/123');
  process.exit(1);
}

// Parse the issue URL
const issueUrlRegex = /github\.com\/([^\/]+)\/([^\/]+)\/issues\/(\d+)/;
const match = issueUrl.match(issueUrlRegex);
if (!match) {
  console.error('❌ Error: Invalid GitHub issue URL');
  console.error('Expected format: https://github.com/owner/repo/issues/123');
  process.exit(1);
}

const [, owner, repo, issueNumber] = match;

async function main() {
  console.log(`🚀 Starting RSOLV demo for issue: ${owner}/${repo}#${issueNumber}`);
  
  // Initialize GitHub client
  const apiClient = new GitHubApiClient(GITHUB_TOKEN, owner, repo);
  
  try {
    // Get issue details
    console.log('📥 Fetching issue details...');
    const { data: issue } = await apiClient.getOctokit().rest.issues.get({
      owner,
      repo,
      issue_number: parseInt(issueNumber, 10)
    });
    
    // Create issue context
    const issueContext: IssueContext = {
      id: issueNumber,
      source: 'github',
      title: issue.title,
      body: issue.body || '',
      labels: issue.labels?.map((label: any) => 
        typeof label === 'string' ? label : label.name
      ) || [],
      repository: {
        owner,
        repo,
        branch: 'main' // Assuming main branch
      },
      metadata: {
        htmlUrl: issue.html_url,
        user: issue.user.login,
        state: issue.state,
        createdAt: issue.created_at,
        updatedAt: issue.updated_at
      },
      url: issue.html_url
    };
    
    // Create AI config (using default values for demo)
    // Allow selecting provider via environment variable
    const provider = process.env.AI_PROVIDER || 'anthropic';
    let apiKey = '';
    let modelName = '';
    
    // Set appropriate API key and model based on provider
    switch (provider) {
      case 'anthropic':
        apiKey = process.env.ANTHROPIC_API_KEY || '';
        modelName = 'claude-3-opus-20240229';
        break;
      case 'openrouter':
        apiKey = process.env.OPENROUTER_API_KEY || '';
        modelName = 'anthropic/claude-3-opus';
        break;
      case 'ollama':
        apiKey = process.env.OLLAMA_API_KEY || ''; // Can be URL:TOKEN format
        modelName = process.env.OLLAMA_MODEL || 'llama3';
        break;
      default:
        apiKey = process.env.ANTHROPIC_API_KEY || '';
        modelName = 'claude-3-opus-20240229';
    }
    
    const aiConfig: AIConfig = {
      provider: provider as any,
      apiKey,
      modelName
    };
    
    // Analyze the issue
    console.log('🔍 Analyzing issue...');
    const analysis = await analyzeIssue(issueContext, aiConfig);
    console.log('✅ Issue analysis complete:');
    console.log(`  Complexity: ${analysis.complexity}`);
    console.log(`  Estimated Time: ${analysis.estimatedTime} minutes`);
    console.log(`  Related Files: ${analysis.relatedFiles?.join(', ') || 'None'}`);
    
    // Generate solution
    console.log('🧠 Generating solution...');
    const solution = await generateSolution(issueContext, analysis, aiConfig);
    console.log('✅ Solution generated:');
    console.log(`  Title: ${solution.title}`);
    console.log(`  Files to change: ${solution.files.length}`);
    
    // Create PR manager
    const prManager = new GitHubPRManager(GITHUB_TOKEN, owner, repo);
    
    // Create pull request
    console.log('🔄 Creating pull request...');
    const { prNumber, prUrl } = await prManager.createPullRequestFromSolution(
      issueContext,
      solution
    );
    
    console.log(`✨ Demo completed successfully!`);
    console.log(`Pull request created: ${prUrl}`);
    
  } catch (error) {
    console.error('❌ Error during demo execution:', error);
    process.exit(1);
  }
}

main();