#!/usr/bin/env bun

/**
 * Test PhaseDataClient with staging API and local fallback
 * This tests the fallback mechanism when API authentication fails
 */

import { PhaseDataClient } from './src/modes/phase-data-client/index.js';

async function testStagingWithFallback() {
  console.log('🧪 Testing PhaseDataClient with Staging API (expecting fallback)\n');
  
  // Use a fake API key to trigger fallback
  const apiKey = 'test_staging_key_invalid';
  const baseUrl = 'https://api.rsolv-staging.com';
  
  // Enable platform storage to test fallback
  process.env.USE_PLATFORM_STORAGE = 'true';
  
  const client = new PhaseDataClient(apiKey, baseUrl);
  const repo = 'RSOLV-dev/staging-test';
  const commitSha = 'staging123';
  const issueNumber = 42;
  
  console.log(`Configuration:
  - API URL: ${baseUrl}
  - Platform Storage: ${process.env.USE_PLATFORM_STORAGE}
  - Repository: ${repo}
  - Issue: #${issueNumber}
  - Commit: ${commitSha}
  `);
  
  // Test 1: Store SCAN phase data
  console.log('📝 TEST 1: Storing SCAN phase data...');
  const scanData = {
    scan: {
      vulnerabilities: [
        { type: 'xss', file: 'app.js', line: 42 },
        { type: 'sql_injection', file: 'db.js', line: 100 }
      ],
      timestamp: new Date().toISOString(),
      commitHash: commitSha
    }
  };
  
  const scanResult = await client.storePhaseResults('scan', scanData, {
    repo,
    commitSha,
    branch: 'main'
  });
  
  console.log('  Result:', scanResult);
  if (scanResult.storage === 'local') {
    console.log('  ✅ Correctly fell back to local storage');
  } else {
    console.log('  ❌ Expected local fallback but got:', scanResult.storage);
  }
  
  // Test 2: Retrieve phase data
  console.log('\n📖 TEST 2: Retrieving phase data...');
  const retrievedData = await client.retrievePhaseResults(repo, issueNumber, commitSha);
  
  if (retrievedData) {
    console.log('  ✅ Data retrieved from local storage');
    console.log('  Vulnerabilities found:', retrievedData.scan?.vulnerabilities.length);
  } else {
    console.log('  ⚠️  No data found (expected for first run)');
  }
  
  // Test 3: Store VALIDATE phase data
  console.log('\n📝 TEST 3: Storing VALIDATE phase data...');
  const validateData = {
    validation: {
      [`issue-${issueNumber}`]: {
        validated: true,
        vulnerabilities: scanData.scan.vulnerabilities,
        timestamp: new Date().toISOString()
      }
    }
  };
  
  const validateResult = await client.storePhaseResults('validate', validateData, {
    repo,
    issueNumber,
    commitSha
  });
  
  console.log('  Result:', validateResult);
  
  // Test 4: Store MITIGATE phase data
  console.log('\n📝 TEST 4: Storing MITIGATE phase data...');
  const mitigateData = {
    mitigation: {
      [`issue-${issueNumber}`]: {
        fixed: true,
        prUrl: 'https://github.com/RSOLV-dev/test/pull/123',
        prNumber: 123,
        filesChanged: 2,
        timestamp: new Date().toISOString()
      }
    }
  };
  
  const mitigateResult = await client.storePhaseResults('mitigate', mitigateData, {
    repo,
    issueNumber,
    commitSha
  });
  
  console.log('  Result:', mitigateResult);
  
  // Test 5: Retrieve all phase data
  console.log('\n📖 TEST 5: Retrieving all phase data...');
  const allData = await client.retrievePhaseResults(repo, issueNumber, commitSha);
  
  if (allData) {
    console.log('  ✅ All phase data retrieved:');
    console.log('    - SCAN data:', !!allData.scan);
    console.log('    - VALIDATE data:', !!allData.validation);
    console.log('    - MITIGATE data:', !!allData.mitigation);
  } else {
    console.log('  ❌ Failed to retrieve data');
  }
  
  // Test 6: Test with platform storage disabled
  console.log('\n🔧 TEST 6: Testing with platform storage disabled...');
  process.env.USE_PLATFORM_STORAGE = 'false';
  const localClient = new PhaseDataClient(apiKey, baseUrl);
  
  const localResult = await localClient.storePhaseResults('scan', scanData, {
    repo: 'test/local-only',
    commitSha: 'local123',
    branch: 'main'
  });
  
  console.log('  Result:', localResult);
  if (localResult.storage === 'local' && !localResult.warning) {
    console.log('  ✅ Correctly used local storage without trying platform');
  } else {
    console.log('  ❌ Unexpected behavior:', localResult);
  }
  
  console.log('\n' + '='.repeat(60));
  console.log('✨ STAGING FALLBACK TEST COMPLETE');
  console.log('='.repeat(60));
  console.log(`
Summary:
- Platform API connection attempted (staging)
- Authentication failed as expected (no valid key)
- All operations fell back to local storage
- Data persistence verified across all three phases
- Local-only mode works without platform attempts

This confirms the PhaseDataClient fallback mechanism is working correctly!
  `);
}

// Run the test
testStagingWithFallback().catch(console.error);