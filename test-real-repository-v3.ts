#!/usr/bin/env bun
/**
 * Test RSOLV against a real repository - Version 3
 * This version includes better branch and SHA handling
 */

import { analyzeIssue } from './src/ai/analyzer.js';
import { generateSolution } from './src/ai/solution.js';
import { getGitHubClient } from './src/github/api.js';
import { IssueContext, AIConfig } from './src/types/index.js';
import { buildPrDescriptionPrompt } from './src/ai/prompts.js';
import { getAiClient } from './src/ai/client.js';
import chalk from 'chalk';

async function processRealIssue(issueUrl: string) {
  console.log(chalk.blue('=== RSOLV Real Repository Test V3 ==='));
  
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
    const octokit = getGitHubClient({ repoToken: githubToken });
    
    // 1. Fetch the issue
    console.log(chalk.yellow('\n1. Fetching issue...'));
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
    
    // List existing files in the repository
    const { data: repoContents } = await octokit.rest.repos.getContent({
      owner,
      repo,
      path: ''
    });
    
    const existingFiles = Array.isArray(repoContents) 
      ? repoContents.map(item => item.name)
      : [];
    
    console.log(chalk.gray('Repository files:', existingFiles.join(', ')));
    
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
    
    // 6. Create PR manually to have better control
    console.log(chalk.yellow('\n6. Creating pull request...'));
    
    // Create branch name
    const safeIssueName = issue.title
      .toLowerCase()
      .replace(/[^\w\s-]/g, '')
      .trim()
      .replace(/[\s]+/g, '-')
      .substring(0, 30);
    const branchName = `rsolv/${issueContext.number}-${safeIssueName}`;
    
    try {
      // Check if branch exists and delete it if it does
      try {
        await octokit.rest.git.getRef({
          owner,
          repo,
          ref: `heads/${branchName}`
        });
        
        console.log(chalk.yellow(`Branch ${branchName} exists, deleting it...`));
        await octokit.rest.git.deleteRef({
          owner,
          repo,
          ref: `heads/${branchName}`
        });
      } catch (e) {
        // Branch doesn't exist, which is fine
      }
      
      // Get the SHA of the default branch
      const { data: defaultBranchRef } = await octokit.rest.git.getRef({
        owner,
        repo,
        ref: `heads/${repoData.default_branch}`
      });
      
      // Create new branch
      console.log(chalk.blue(`Creating branch: ${branchName}`));
      await octokit.rest.git.createRef({
        owner,
        repo,
        ref: `refs/heads/${branchName}`,
        sha: defaultBranchRef.object.sha
      });
      
      // Apply changes
      for (const [filePath, content] of Object.entries(solution.changes || {})) {
        console.log(chalk.blue(`Updating ${filePath}...`));
        
        // Get the current file from default branch to get its SHA
        let currentSha: string | undefined;
        try {
          const { data: currentFile } = await octokit.rest.repos.getContent({
            owner,
            repo,
            path: filePath,
            ref: repoData.default_branch
          });
          
          if (!Array.isArray(currentFile)) {
            currentSha = currentFile.sha;
          }
        } catch (e) {
          // File doesn't exist
        }
        
        // Create or update the file
        await octokit.rest.repos.createOrUpdateFileContents({
          owner,
          repo,
          path: filePath,
          message: `Update ${filePath} for issue #${issueContext.number}`,
          content: Buffer.from(content).toString('base64'),
          branch: branchName,
          sha: currentSha
        });
      }
      
      // Generate PR description
      const aiClient = getAiClient(aiConfig);
      const prPrompt = buildPrDescriptionPrompt(issueContext, analysis, solution.changes || {});
      const prDescription = await aiClient.complete(prPrompt, {
        temperature: 0.3,
        maxTokens: 1000,
        model: aiConfig.modelName
      });
      
      // Create pull request
      const { data: pr } = await octokit.rest.pulls.create({
        owner,
        repo,
        title: `Fix: ${issue.title}`,
        body: prDescription,
        head: branchName,
        base: repoData.default_branch
      });
      
      console.log(chalk.green('✅ PR created successfully!'));
      console.log('PR URL:', chalk.cyan(pr.html_url));
      
    } catch (error) {
      console.error(chalk.red('❌ PR creation failed:'), error);
    }
    
  } catch (error) {
    console.error(chalk.red('Error:'), error);
  }
}

// Run the test if called directly
if (require.main === module) {
  const issueUrl = process.argv[2];
  
  if (!issueUrl) {
    console.error(chalk.red('Usage: bun run test-real-repository-v3.ts <github-issue-url>'));
    console.error(chalk.yellow('Example: bun run test-real-repository-v3.ts https://github.com/owner/repo/issues/1'));
    process.exit(1);
  }
  
  processRealIssue(issueUrl);
}

export { processRealIssue };