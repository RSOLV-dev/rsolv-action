#!/usr/bin/env node

/**
 * Local test script for validation and mitigation modes
 * This simulates what happens in GitHub Actions but runs locally
 */

const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

// Set up environment
process.env.GITHUB_TOKEN = process.env.GITHUB_TOKEN || '';
process.env.RSOLV_TESTING_MODE = 'true';
process.env.GITHUB_REPOSITORY = 'RSOLV-dev/nodegoat-vulnerability-demo';
process.env.GITHUB_WORKSPACE = '/tmp/nodegoat-vulnerability-demo';

async function runTest() {
  console.log('🔍 Testing RSOLV Validation and Mitigation locally...\n');

  // Change to test repo
  process.chdir('/tmp/nodegoat-vulnerability-demo');

  // Copy latest RSOLV-action
  console.log('📦 Copying latest RSOLV-action...');
  execSync('rm -rf RSOLV-action', { stdio: 'inherit' });
  execSync('cp -r /home/dylan/dev/rsolv/RSOLV-action .', { stdio: 'inherit' });

  // Install dependencies
  console.log('\n📦 Installing dependencies...');
  execSync('cd RSOLV-action && npm install', { stdio: 'inherit' });

  // Import the modes
  const { ValidationMode } = require('/tmp/nodegoat-vulnerability-demo/RSOLV-action/dist/modes/validation-mode.js');
  const { MitigationMode } = require('/tmp/nodegoat-vulnerability-demo/RSOLV-action/dist/modes/mitigation-mode.js');

  // Build the action first
  console.log('\n🔨 Building RSOLV-action...');
  execSync('cd RSOLV-action && npm run build', { stdio: 'inherit' });

  // Test issues
  const testIssues = [
    {
      number: 1036,
      title: '🔒 Insecure_deserialization vulnerabilities found in 1 file',
      body: 'Security vulnerability detected',
      state: 'open'
    },
    {
      number: 1037,
      title: '🔒 Cross-Site Scripting (XSS) vulnerabilities found in 1 file',
      body: 'Security vulnerability detected',
      state: 'open'
    }
  ];

  // Configuration
  const config = {
    githubToken: process.env.GITHUB_TOKEN,
    environmentVariables: {
      RSOLV_TESTING_MODE: 'true',
      CLAUDE_CODE_API_KEY: process.env.CLAUDE_CODE_API_KEY,
      ANTHROPIC_API_KEY: process.env.ANTHROPIC_API_KEY
    }
  };

  console.log('\n========================================');
  console.log('         VALIDATION PHASE');
  console.log('========================================\n');

  const validationMode = new ValidationMode(config, '/tmp/nodegoat-vulnerability-demo');

  for (const issue of testIssues) {
    console.log(`\n📋 Validating issue #${issue.number}: ${issue.title}`);
    try {
      const result = await validationMode.validateVulnerability(issue);
      console.log(`✅ Validation result:`, {
        validated: result.validated,
        branchName: result.branchName,
        testingMode: result.testingMode,
        testingModeNote: result.testingModeNote
      });

      // Check if branch was created
      if (result.branchName) {
        try {
          const branches = execSync('git branch', { encoding: 'utf8' });
          if (branches.includes(result.branchName)) {
            console.log(`✅ Validation branch created: ${result.branchName}`);

            // Check if tests exist on the branch
            execSync(`git checkout ${result.branchName}`, { stdio: 'ignore' });
            const testFiles = execSync('find . -name "*.test.js" -o -name "*.spec.js" | head -5', { encoding: 'utf8' });
            if (testFiles) {
              console.log(`✅ Test files found on branch:\n${testFiles}`);
            }
            execSync('git checkout main', { stdio: 'ignore' });
          }
        } catch (e) {
          console.log(`⚠️ Could not verify branch: ${e.message}`);
        }
      }
    } catch (error) {
      console.error(`❌ Validation failed: ${error.message}`);
    }
  }

  console.log('\n========================================');
  console.log('         MITIGATION PHASE');
  console.log('========================================\n');

  const mitigationMode = new MitigationMode(config, '/tmp/nodegoat-vulnerability-demo');

  for (const issue of testIssues) {
    console.log(`\n🔧 Mitigating issue #${issue.number}: ${issue.title}`);
    try {
      const result = await mitigationMode.mitigateVulnerability(issue);
      console.log(`✅ Mitigation result:`, {
        skipReason: result.skipReason,
        branchCheckedOut: result.branchCheckedOut,
        prUrl: result.prUrl
      });

      // Check if PR branch was created
      if (result.prUrl) {
        const prBranch = `rsolv/fix-issue-${issue.number}`;
        const branches = execSync('git branch', { encoding: 'utf8' });
        if (branches.includes(prBranch)) {
          console.log(`✅ Mitigation branch created: ${prBranch}`);
        }
      }
    } catch (error) {
      console.error(`❌ Mitigation failed: ${error.message}`);
    }
  }

  console.log('\n========================================');
  console.log('         TEST COMPLETE');
  console.log('========================================\n');

  // Summary
  console.log('📊 Summary:');
  console.log('- Validation branches should contain generated tests');
  console.log('- Mitigation branches should contain fixes');
  console.log('- Both should work even in TESTING_MODE');
}

runTest().catch(console.error);