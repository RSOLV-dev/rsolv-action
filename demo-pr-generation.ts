#!/usr/bin/env bun
// Demo script to generate a PR for a security issue

import { getGitHubClient } from './src/github/api.js';
import { loadConfig } from './src/config/index.js';
import { processIssues } from './src/ai/unified-processor.js';
import { logger } from './src/utils/logger.js';
import { IssueContext } from './src/types/index.js';

// Force real AI responses
process.env.FORCE_REAL_AI = 'true';

async function generatePRForIssue(issueNumber: number) {
  logger.info(`🚀 Generating PR for issue #${issueNumber}`);
  
  const config = await loadConfig();
  const githubClient = getGitHubClient({ token: process.env.GITHUB_TOKEN! });
  
  // Fetch the issue
  const { data: issue } = await githubClient.issues.get({
    owner: 'RSOLV-dev',
    repo: 'nodegoat-vulnerability-demo',
    issue_number: issueNumber
  });
  
  logger.info(`📋 Issue: ${issue.title}`);
  
  // Create issue context
  const issueContext: IssueContext = {
    id: issue.id.toString(),
    number: issue.number,
    title: issue.title,
    body: issue.body || '',
    labels: issue.labels.map((l: any) => l.name),
    assignees: issue.assignees.map((a: any) => a.login),
    repository: {
      owner: 'RSOLV-dev',
      name: 'nodegoat-vulnerability-demo',
      fullName: 'RSOLV-dev/nodegoat-vulnerability-demo',
      defaultBranch: 'main',
      language: 'JavaScript'
    },
    source: 'github' as const,
    url: issue.html_url,
    createdAt: issue.created_at,
    updatedAt: issue.updated_at
  };
  
  // Process the issue
  const results = await processIssues(
    [issueContext],
    config,
    {
      enableSecurityAnalysis: true,
      enableEnhancedContext: true,
      contextDepth: 'deep'
    }
  );
  
  if (results.length > 0 && results[0].status === 'success') {
    logger.info(`✅ PR created: ${results[0].prUrl}`);
    return results[0];
  } else {
    logger.error('❌ Failed to create PR', results[0]?.error);
    return null;
  }
}

// Run the demo
if (import.meta.main) {
  const issueNumber = parseInt(process.argv[2] || '7');
  
  generatePRForIssue(issueNumber)
    .then((result) => {
      if (result) {
        logger.info('\n🎉 Demo complete!');
        logger.info(`View the PR at: ${result.prUrl}`);
      }
      process.exit(0);
    })
    .catch((error) => {
      logger.error('Fatal error:', error);
      process.exit(1);
    });
}