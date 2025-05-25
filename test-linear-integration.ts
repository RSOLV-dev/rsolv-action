#!/usr/bin/env bun

import { LinearAdapter } from './src/platforms/linear/linear-adapter';
import { logger } from './src/utils/logger';

async function testLinearIntegration() {
  // Check if Linear API key is set
  const apiKey = process.env.LINEAR_API_KEY;
  if (!apiKey) {
    console.error('❌ LINEAR_API_KEY environment variable is not set');
    console.log('\nTo test Linear integration:');
    console.log('1. Go to https://linear.app/settings/api');
    console.log('2. Create a new personal API key');
    console.log('3. Run: export LINEAR_API_KEY="lin_api_YOUR_KEY_HERE"');
    console.log('4. Optionally set: export LINEAR_TEAM_ID="your-team-id"');
    return;
  }

  console.log('🔍 Testing Linear integration...\n');

  try {
    // Create Linear adapter
    const adapter = new LinearAdapter({
      apiKey,
      teamId: process.env.LINEAR_TEAM_ID,
      autofixLabel: process.env.LINEAR_AUTOFIX_LABEL || 'autofix',
      rsolvLabel: process.env.LINEAR_RSOLV_LABEL || 'rsolv'
    });

    // Test 1: Search for issues
    console.log('📋 Searching for issues with "autofix" or "rsolv" labels...');
    const issues = await adapter.searchRsolvIssues();
    
    if (issues.length === 0) {
      console.log('⚠️  No issues found with "autofix" or "rsolv" labels');
      console.log('\nTo test further:');
      console.log('1. Create an issue in Linear');
      console.log('2. Add the label "autofix" or "rsolv" to it');
      console.log('3. Run this test again');
    } else {
      console.log(`✅ Found ${issues.length} issue(s)\n`);
      
      // Display found issues
      issues.forEach((issue, index) => {
        console.log(`Issue ${index + 1}:`);
        console.log(`  ID: ${issue.id}`);
        console.log(`  Key: ${issue.key}`);
        console.log(`  Title: ${issue.title}`);
        console.log(`  Status: ${issue.status} (${issue.statusCategory})`);
        console.log(`  Labels: ${issue.labels.join(', ')}`);
        console.log(`  URL: ${issue.url}`);
        console.log('');
      });

      // Test 2: Get specific issue
      if (issues.length > 0) {
        const testIssueId = issues[0].id;
        console.log(`📄 Getting details for issue ${testIssueId}...`);
        const issue = await adapter.getIssue(testIssueId);
        
        if (issue) {
          console.log('✅ Successfully retrieved issue details\n');
          
          // Test 3: Add a comment
          console.log('💬 Adding a test comment...');
          const comment = await adapter.createComment(
            testIssueId,
            '🤖 Test comment from RSOLV Linear integration test'
          );
          
          if (comment) {
            console.log(`✅ Comment added successfully (ID: ${comment.id})\n`);
            
            // Test 4: Add a link
            console.log('🔗 Adding a test link...');
            const link = await adapter.addLink(
              testIssueId,
              'https://github.com/RSOLV-dev/rsolv-action',
              'RSOLV GitHub Repository'
            );
            
            if (link) {
              console.log(`✅ Link added successfully\n`);
            } else {
              console.log('❌ Failed to add link\n');
            }
            
            // Test 5: Add a label
            console.log('🏷️  Adding "rsolv-tested" label...');
            const labelAdded = await adapter.addLabel(testIssueId, 'rsolv-tested');
            
            if (labelAdded) {
              console.log('✅ Label added successfully\n');
            } else {
              console.log('❌ Failed to add label\n');
            }
          } else {
            console.log('❌ Failed to add comment\n');
          }
        } else {
          console.log('❌ Failed to retrieve issue\n');
        }
      }
    }

    console.log('🎉 Linear integration test completed!');
    
  } catch (error) {
    console.error('❌ Error during Linear integration test:', error);
    if (error instanceof Error && error.message.includes('401')) {
      console.log('\n⚠️  Authentication failed. Please check your LINEAR_API_KEY');
    }
  }
}

// Run the test
testLinearIntegration().catch(console.error);