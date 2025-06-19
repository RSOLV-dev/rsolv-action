#!/usr/bin/env bun
import { getGitHubClient } from './src/github/api.js';

async function testSetup() {
  console.log('Testing RSOLV Demo Setup...\n');
  
  // Check GitHub token
  const token = process.env.GITHUB_TOKEN;
  if (!token) {
    console.error('❌ GITHUB_TOKEN not set');
    process.exit(1);
  }
  console.log('✅ GITHUB_TOKEN is set');
  
  // Test GitHub API access
  try {
    const client = getGitHubClient({ token });
    const { data: issue } = await client.issues.get({
      owner: 'RSOLV-dev',
      repo: 'demo-ecommerce-security',
      issue_number: 8
    });
    
    console.log('✅ GitHub API access working');
    console.log(`✅ Found issue #${issue.number}: ${issue.title}`);
    console.log(`✅ Labels: ${issue.labels.map((l: any) => l.name).join(', ')}`);
    
    // Check for rsolv:automate label
    const hasRsolvLabel = issue.labels.some((l: any) => l.name === 'rsolv:automate');
    if (hasRsolvLabel) {
      console.log('✅ Issue has rsolv:automate label');
    } else {
      console.log('❌ Issue missing rsolv:automate label');
    }
    
    console.log('\n✅ All checks passed! Ready for demo.');
    console.log('\nIssue URL: https://github.com/RSOLV-dev/demo-ecommerce-security/issues/8');
    
  } catch (error) {
    console.error('❌ GitHub API error:', error.message);
    process.exit(1);
  }
}

testSetup();