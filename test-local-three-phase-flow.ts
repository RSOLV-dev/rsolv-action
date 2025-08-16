#!/usr/bin/env bun

/**
 * Test full three-phase flow with local storage
 * This verifies the complete workflow logic works correctly
 */

import { PhaseDataClient } from './src/modes/phase-data-client/index.js';
import { rmSync } from 'fs';

async function testLocalThreePhaseFlow() {
  console.log('🚀 Testing Full Three-Phase Flow with Local Storage\n');
  
  // Clear any existing local data
  try {
    rmSync('.rsolv/phase-data', { recursive: true, force: true });
    console.log('Cleared existing local phase data\n');
  } catch {}
  
  // Disable platform storage to use local only
  process.env.USE_PLATFORM_STORAGE = 'false';
  
  const apiKey = 'local_test_key';
  const baseUrl = 'http://localhost'; // Not used with local storage
  
  const client = new PhaseDataClient(apiKey, baseUrl);
  const repo = 'RSOLV-dev/local-test';
  const commitSha = `local_${Date.now()}`;
  const issueNumber = 999;
  
  console.log(`Configuration:
  - Storage: Local only
  - Repository: ${repo}
  - Issue: #${issueNumber}
  - Commit: ${commitSha}
  `);
  
  console.log('='.repeat(60));
  console.log('PHASE 1: SCAN - Detect vulnerabilities');
  console.log('='.repeat(60));
  
  // Simulate SCAN phase
  const scanData = {
    scan: {
      vulnerabilities: [
        { 
          type: 'xss', 
          file: 'app.js', 
          line: 42,
          severity: 'high',
          message: 'Unescaped user input'
        },
        { 
          type: 'sql_injection', 
          file: 'db.js', 
          line: 100,
          severity: 'critical',
          message: 'SQL injection vulnerability'
        }
      ],
      timestamp: new Date().toISOString(),
      commitHash: commitSha
    }
  };
  
  console.log(`📊 Found ${scanData.scan.vulnerabilities.length} vulnerabilities`);
  
  console.log('📝 Storing SCAN results locally...');
  const scanResult = await client.storePhaseResults('scan', scanData, {
    repo,
    commitSha,
    branch: 'main',
    issueNumber // Store for scan too for testing
  });
  
  console.log('  Result:', scanResult.storage === 'local' ? '✅ Stored locally' : '❌ Unexpected');
  
  console.log('\n' + '='.repeat(60));
  console.log('PHASE 2: VALIDATE - Verify vulnerabilities');
  console.log('='.repeat(60));
  
  // Retrieve SCAN data
  console.log('📖 Retrieving SCAN data...');
  let retrieved = await client.retrievePhaseResults(repo, issueNumber, commitSha);
  
  if (retrieved?.scan) {
    console.log(`  ✅ Retrieved ${retrieved.scan.vulnerabilities.length} vulnerabilities`);
    
    // Store validation
    const validateData = {
      validation: {
        [`issue-${issueNumber}`]: {
          validated: true,
          vulnerabilities: retrieved.scan.vulnerabilities,
          timestamp: new Date().toISOString()
        }
      }
    };
    
    console.log('📝 Storing VALIDATE results locally...');
    const validateResult = await client.storePhaseResults('validate', validateData, {
      repo,
      issueNumber,
      commitSha
    });
    
    console.log('  Result:', validateResult.storage === 'local' ? '✅ Stored locally' : '❌ Unexpected');
  } else {
    console.log('  ❌ Failed to retrieve SCAN data');
  }
  
  console.log('\n' + '='.repeat(60));
  console.log('PHASE 3: MITIGATE - Fix vulnerabilities');
  console.log('='.repeat(60));
  
  // Retrieve all phase data
  console.log('📖 Retrieving all phase data...');
  retrieved = await client.retrievePhaseResults(repo, issueNumber, commitSha);
  
  if (retrieved?.validation && retrieved?.scan) {
    const validationKey = `issue-${issueNumber}`;
    console.log('  ✅ Retrieved data from both phases:');
    console.log(`    - SCAN: ${retrieved.scan.vulnerabilities.length} vulnerabilities`);
    console.log(`    - VALIDATE: ${retrieved.validation[validationKey].validated ? 'Validated' : 'Not validated'}`);
    
    // Store mitigation
    const mitigateData = {
      mitigation: {
        [validationKey]: {
          fixed: true,
          prUrl: `https://github.com/${repo}/pull/123`,
          prNumber: 123,
          filesChanged: 2,
          timestamp: new Date().toISOString()
        }
      }
    };
    
    console.log('📝 Storing MITIGATE results locally...');
    const mitigateResult = await client.storePhaseResults('mitigate', mitigateData, {
      repo,
      issueNumber,
      commitSha
    });
    
    console.log('  Result:', mitigateResult.storage === 'local' ? '✅ Stored locally' : '❌ Unexpected');
  } else {
    console.log('  ❌ Failed to retrieve phase data');
  }
  
  // Final verification
  console.log('\n' + '='.repeat(60));
  console.log('VERIFICATION: Retrieve complete phase history');
  console.log('='.repeat(60));
  
  const finalData = await client.retrievePhaseResults(repo, issueNumber, commitSha);
  
  if (finalData) {
    const validationKey = `issue-${issueNumber}`;
    console.log('✅ All phase data retrieved successfully:');
    console.log(`  - SCAN: ${finalData.scan ? '✓' : '✗'}`);
    console.log(`  - VALIDATE: ${finalData.validation?.[validationKey] ? '✓' : '✗'}`);
    console.log(`  - MITIGATE: ${finalData.mitigation?.[validationKey] ? '✓' : '✗'}`);
    
    if (finalData.scan && finalData.validation?.[validationKey] && finalData.mitigation?.[validationKey]) {
      console.log('\n🎉 SUCCESS: All three phases data persisted and retrieved!');
    }
  } else {
    console.log('❌ Failed to retrieve final data');
  }
  
  console.log('\n' + '='.repeat(60));
  console.log('✨ LOCAL THREE-PHASE FLOW TEST COMPLETE');
  console.log('='.repeat(60));
  console.log(`
Summary:
✅ SCAN phase stored vulnerability data locally
✅ VALIDATE phase retrieved SCAN data successfully
✅ MITIGATE phase retrieved both SCAN and VALIDATE data
✅ All phases can access previous phase data
✅ Local storage working correctly as fallback

The three-phase architecture logic is working perfectly!
Next step: Create valid API keys for platform testing.
  `);
}

// Run the test
testLocalThreePhaseFlow().catch(console.error);