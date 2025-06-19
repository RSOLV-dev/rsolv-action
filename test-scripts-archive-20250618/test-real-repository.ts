#!/usr/bin/env bun
/**
 * Test RSOLV against a real repository
 * This script processes a specific issue and shows the generated changes
 * before creating a PR
 */

import { analyzeIssue } from './src/ai/analyzer.js';
import { generateSolution } from './src/ai/solution.js';
import { createPullRequest } from './src/github/pr.js';
import { getGitHubClient } from './src/github/api.js';
import { IssueContext, AIConfig } from './src/types/index.js';
import chalk from 'chalk';

async function processRealIssue(issueUrl: string) {
  console.log(chalk.blue('=== RSOLV Real Repository Test ==='));
  
  // Parse the issue URL
  const issueUrlRegex = /github\.com\/([^\/]+)\/([^\/]+)\/issues\/(\d+)/;
  const match = issueUrl.match(issueUrlRegex);
  
  if (!match) {
    throw new Error('Invalid GitHub issue URL format');
  }
  
  const [, owner, repo, issueNumber] = match;
  const githubToken = process.env.GITHUB_TOKEN;
  const anthropicApiKey = process.env.ANTHROPIC_API_KEY;
  
  if (!githubToken || !anthropicApiKey) {
    console.error(chalk.red('Missing required environment variables:'));
    console.log('- GITHUB_TOKEN');
    console.log('- ANTHROPIC_API_KEY');
    process.exit(1);
  }
  
  try {
    // 1. Fetch the issue
    console.log(chalk.yellow('\n1. Fetching issue...'));
    const octokit = getGitHubClient({ repoToken: githubToken });
    const { data: issue } = await octokit.rest.issues.get({
      owner,
      repo,
      issue_number: parseInt(issueNumber, 10)
    });
    
    // Get repository details
    const { data: repoData } = await octokit.rest.repos.get({
      owner,
      repo
    });
    
    const issueContext: IssueContext = {
      id: issueNumber,
      number: parseInt(issueNumber, 10),
      source: 'github',
      title: issue.title,
      body: issue.body || '',
      labels: issue.labels?.map((label: any) => 
        typeof label === 'string' ? label : label.name
      ) || [],
      assignees: issue.assignees?.map((assignee: any) => assignee.login) || [],
      repository: {
        owner,
        name: repo,
        fullName: `${owner}/${repo}`,
        defaultBranch: repoData.default_branch || 'main',
        language: repoData.language || undefined
      },
      createdAt: issue.created_at,
      updatedAt: issue.updated_at,
      metadata: {
        htmlUrl: issue.html_url,
        user: issue.user?.login,
        state: issue.state
      }
    };
    
    console.log(chalk.green('✅ Issue fetched:'), issue.title);
    
    // 2. Analyze the issue
    console.log(chalk.yellow('\n2. Analyzing issue...'));
    const aiConfig: AIConfig = {
      provider: 'anthropic',
      apiKey: anthropicApiKey,
      modelName: 'claude-3-sonnet-20240229'
    };
    
    const analysis = await analyzeIssue(issueContext, { aiProvider: aiConfig } as any);
    console.log(chalk.green('✅ Analysis complete:'));
    console.log('- Complexity:', chalk.cyan(analysis.estimatedComplexity));
    console.log('- Type:', chalk.cyan(analysis.issueType));
    console.log('- Files to modify:', chalk.cyan(analysis.filesToModify.join(', ')));
    
    // 3. Generate solution
    console.log(chalk.yellow('\n3. Generating solution...'));
    const solution = await generateSolution(issueContext, analysis, { aiProvider: aiConfig } as any);
    
    if (!solution.success) {
      console.error(chalk.red('❌ Solution generation failed:'), solution.message);
      return;
    }
    
    console.log(chalk.green('✅ Solution generated'));
    
    // 4. Display the changes for review
    console.log(chalk.yellow('\n4. Proposed changes:'));
    console.log(chalk.gray('='.repeat(50)));
    
    for (const [filePath, content] of Object.entries(solution.changes || {})) {
      console.log(chalk.blue(`\nFile: ${filePath}`));
      console.log(chalk.gray('-'.repeat(40)));
      console.log(content);
      console.log(chalk.gray('-'.repeat(40)));
    }
    
    console.log(chalk.gray('='.repeat(50)));
    
    // 5. Ask for confirmation
    console.log(chalk.yellow('\n5. Create PR with these changes?'));
    const readline = require('readline');
    const rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout
    });
    
    const createPR = await new Promise<boolean>((resolve) => {
      rl.question(chalk.yellow('Create PR? [y/N]: '), (answer) => {
        rl.close();
        resolve(answer.trim().toLowerCase() === 'y');
      });
    });
    
    if (!createPR) {
      console.log(chalk.yellow('PR creation cancelled'));
      return;
    }
    
    // 6. Create PR
    console.log(chalk.yellow('\n6. Creating pull request...'));
    const prResult = await createPullRequest(
      issueContext,
      solution.changes || {},
      analysis,
      { aiProvider: aiConfig } as any
    );
    
    if (prResult.success) {
      console.log(chalk.green('✅ PR created successfully!'));
      console.log('PR URL:', chalk.cyan(prResult.pullRequestUrl));
    } else {
      console.error(chalk.red('❌ PR creation failed:'), prResult.message);
    }
    
  } catch (error) {
    console.error(chalk.red('Error:'), error);
  }
}

// Run the test if called directly
if (require.main === module) {
  const issueUrl = process.argv[2];
  
  if (!issueUrl) {
    console.error(chalk.red('Usage: bun run test-real-repository.ts <github-issue-url>'));
    console.error(chalk.yellow('Example: bun run test-real-repository.ts https://github.com/owner/repo/issues/1'));
    process.exit(1);
  }
  
  processRealIssue(issueUrl);
}

export { processRealIssue };