#!/usr/bin/env bun
// Script to process security issues and generate PRs

import { getGitHubClient } from './src/github/api.js';
import { processIssue } from './src/index.js';
import { logger } from './src/utils/logger.js';

async function processSecurityIssues() {
  const githubClient = getGitHubClient({ token: process.env.GITHUB_TOKEN! });
  
  logger.info('🔄 Processing security issues from NodeGoat demo...');
  
  // Get all open security issues
  const { data: issues } = await githubClient.issues.listForRepo({
    owner: 'RSOLV-dev',
    repo: 'nodegoat-vulnerability-demo',
    labels: 'rsolv:security',
    state: 'open'
  });
  
  logger.info(`Found ${issues.length} security issues to process`);
  
  // Process each issue
  for (const issue of issues) {
    logger.info(`\n📋 Processing issue #${issue.number}: ${issue.title}`);
    
    try {
      await processIssue({
        issueNumber: issue.number,
        repository: 'RSOLV-dev/nodegoat-vulnerability-demo',
        eventName: 'issues',
        eventAction: 'labeled',
        issueUrl: issue.html_url
      });
      
      logger.info(`✅ Successfully processed issue #${issue.number}`);
    } catch (error) {
      logger.error(`❌ Failed to process issue #${issue.number}:`, error);
    }
  }
  
  logger.info('\n🎉 Finished processing all security issues');
}

// Run the processor
if (import.meta.main) {
  processSecurityIssues()
    .then(() => process.exit(0))
    .catch((error) => {
      logger.error('Fatal error:', error);
      process.exit(1);
    });
}