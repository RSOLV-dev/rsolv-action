#!/usr/bin/env bun
/**
 * Test script for PhaseDataClient platform integration
 * Tests real API endpoints deployed to production
 */

import { PhaseDataClient } from './src/modes/phase-data-client/index.js';

async function testPlatformIntegration() {
  console.log('🧪 Testing PhaseDataClient Platform Integration\n');
  
  // Use environment variables or test API key
  const apiKey = process.env.RSOLV_API_KEY || 'test-api-key';
  const baseUrl = process.env.RSOLV_API_URL || 'https://api.rsolv.dev';
  
  // Enable platform storage
  process.env.USE_PLATFORM_STORAGE = 'true';
  
  const client = new PhaseDataClient(apiKey, baseUrl);
  
  const testRepo = 'RSOLV-dev/test-phase-data';
  const testIssue = 999;
  const testCommit = 'test-' + Date.now();
  const testBranch = 'main';
  
  console.log('Configuration:');
  console.log(`  API URL: ${baseUrl}`);
  console.log(`  API Key: ${apiKey.substring(0, 10)}...`);
  console.log(`  Test Repo: ${testRepo}`);
  console.log(`  Test Issue: #${testIssue}`);
  console.log(`  Test Commit: ${testCommit}\n`);
  
  // Test 1: Store SCAN phase data
  console.log('📝 Test 1: Storing SCAN phase data...');
  try {
    const scanData = {
      scan: {
        vulnerabilities: [
          {
            type: 'sql-injection',
            file: 'test.js',
            line: 42,
            severity: 'high'
          },
          {
            type: 'xss',
            file: 'view.html',
            line: 10,
            severity: 'medium'
          }
        ],
        timestamp: new Date().toISOString(),
        commitHash: testCommit
      }
    };
    
    const scanResult = await client.storePhaseResults('scan', scanData, {
      repo: testRepo,
      commitSha: testCommit,
      branch: testBranch
    });
    
    console.log('  ✅ SCAN storage result:', scanResult);
    
    if (!scanResult.success) {
      throw new Error(`Failed to store scan data: ${scanResult.message}`);
    }
  } catch (error) {
    console.error('  ❌ SCAN storage failed:', error);
    process.exit(1);
  }
  
  // Test 2: Store VALIDATE phase data
  console.log('\n📝 Test 2: Storing VALIDATE phase data...');
  try {
    const validateData = {
      validation: {
        [`issue-${testIssue}`]: {
          validated: true,
          vulnerabilities: [
            {
              type: 'sql-injection',
              file: 'test.js',
              line: 42,
              severity: 'high'
            }
          ],
          redTests: { count: 2, passed: 2 },
          timestamp: new Date().toISOString()
        }
      }
    };
    
    const validateResult = await client.storePhaseResults('validate', validateData, {
      repo: testRepo,
      issueNumber: testIssue,
      commitSha: testCommit
    });
    
    console.log('  ✅ VALIDATE storage result:', validateResult);
    
    if (!validateResult.success) {
      throw new Error(`Failed to store validation data: ${validateResult.message}`);
    }
  } catch (error) {
    console.error('  ❌ VALIDATE storage failed:', error);
    process.exit(1);
  }
  
  // Test 3: Store MITIGATE phase data
  console.log('\n📝 Test 3: Storing MITIGATE phase data...');
  try {
    const mitigateData = {
      mitigation: {
        [`issue-${testIssue}`]: {
          fixed: true,
          prUrl: `https://github.com/${testRepo}/pull/123`,
          prNumber: 123,
          filesChanged: 3,
          timestamp: new Date().toISOString()
        }
      }
    };
    
    const mitigateResult = await client.storePhaseResults('mitigate', mitigateData, {
      repo: testRepo,
      issueNumber: testIssue,
      commitSha: testCommit
    });
    
    console.log('  ✅ MITIGATE storage result:', mitigateResult);
    
    if (!mitigateResult.success) {
      throw new Error(`Failed to store mitigation data: ${mitigateResult.message}`);
    }
  } catch (error) {
    console.error('  ❌ MITIGATE storage failed:', error);
    process.exit(1);
  }
  
  // Test 4: Retrieve all phase data
  console.log('\n🔍 Test 4: Retrieving all phase data...');
  try {
    const retrievedData = await client.retrievePhaseResults(
      testRepo,
      testIssue,
      testCommit
    );
    
    console.log('  ✅ Retrieved data:', JSON.stringify(retrievedData, null, 2));
    
    if (!retrievedData) {
      throw new Error('No data retrieved');
    }
    
    // Verify all phases are present
    if (!retrievedData.scan) {
      throw new Error('Missing scan data');
    }
    if (!retrievedData.validation) {
      throw new Error('Missing validation data');
    }
    if (!retrievedData.mitigation) {
      throw new Error('Missing mitigation data');
    }
    
    console.log('\n✨ All tests passed! Platform integration working correctly.');
  } catch (error) {
    console.error('  ❌ Retrieval failed:', error);
    process.exit(1);
  }
}

// Run the tests
testPlatformIntegration().catch(error => {
  console.error('Unexpected error:', error);
  process.exit(1);
});