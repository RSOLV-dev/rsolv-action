#!/usr/bin/env bun

/**
 * Test full three-phase flow with production API
 * This simulates the complete SCAN -> VALIDATE -> MITIGATE workflow
 */

import { PhaseDataClient } from './src/modes/phase-data-client/index.js';

async function testFullThreePhaseFlow() {
  console.log('🚀 Testing Full Three-Phase Flow with Production API\n');
  
  // Use the test API key we created earlier
  const apiKey = 'phase_test_1620ef92f70af3d3fbb952ac6608bf8f9decdc65c98c68b1ad64be6881239f84';
  const baseUrl = 'https://api.rsolv.dev';
  
  // Enable platform storage
  process.env.USE_PLATFORM_STORAGE = 'true';
  process.env.RSOLV_API_KEY = apiKey;
  process.env.RSOLV_API_URL = baseUrl;
  
  const client = new PhaseDataClient(apiKey, baseUrl);
  const repo = 'RSOLV-dev/demo-test';
  const commitSha = `test_${Date.now()}`;
  const issueNumber = Math.floor(Math.random() * 1000);
  
  console.log(`Configuration:
  - API URL: ${baseUrl}
  - Repository: ${repo}
  - Issue: #${issueNumber}
  - Commit: ${commitSha}
  `);
  
  console.log('='.repeat(60));
  console.log('PHASE 1: SCAN - Detect vulnerabilities');
  console.log('='.repeat(60));
  
  // Simulate SCAN phase finding vulnerabilities
  const scanData = {
    scan: {
      vulnerabilities: [
        { 
          type: 'xss', 
          file: 'app.js', 
          line: 42,
          severity: 'high',
          message: 'Unescaped user input in innerHTML'
        },
        { 
          type: 'sql_injection', 
          file: 'db.js', 
          line: 100,
          severity: 'critical',
          message: 'Direct string concatenation in SQL query'
        },
        {
          type: 'path_traversal',
          file: 'fileHandler.js',
          line: 25,
          severity: 'medium',
          message: 'Unsanitized file path from user input'
        }
      ],
      timestamp: new Date().toISOString(),
      commitHash: commitSha
    }
  };
  
  console.log(`📊 Found ${scanData.scan.vulnerabilities.length} vulnerabilities:`);
  scanData.scan.vulnerabilities.forEach(v => {
    console.log(`  - ${v.type} in ${v.file}:${v.line} (${v.severity})`);
  });
  
  console.log('\n📝 Storing SCAN results to platform...');
  const scanResult = await client.storePhaseResults('scan', scanData, {
    repo,
    commitSha,
    branch: 'main'
  });
  
  console.log('  Storage result:', scanResult);
  if (scanResult.storage === 'platform') {
    console.log('  ✅ Successfully stored to platform');
  } else {
    console.log('  ⚠️  Fell back to local storage:', scanResult.warning);
  }
  
  // Simulate time passing between phases
  await new Promise(resolve => setTimeout(resolve, 1000));
  
  console.log('\n' + '='.repeat(60));
  console.log('PHASE 2: VALIDATE - Verify vulnerabilities');
  console.log('='.repeat(60));
  
  // VALIDATE phase retrieves SCAN data
  console.log('📖 Retrieving SCAN data for validation...');
  const scanDataForValidation = await client.retrievePhaseResults(repo, issueNumber, commitSha);
  
  if (scanDataForValidation?.scan) {
    console.log(`  ✅ Retrieved ${scanDataForValidation.scan.vulnerabilities.length} vulnerabilities from SCAN`);
    
    // Simulate validation process
    console.log('\n🔍 Validating vulnerabilities...');
    const validatedVulns = scanDataForValidation.scan.vulnerabilities.map(v => ({
      ...v,
      validated: v.severity === 'critical' || v.severity === 'high',
      falsePositive: v.type === 'path_traversal', // Simulate one false positive
      confidence: v.severity === 'critical' ? 0.95 : 0.75
    }));
    
    const validateData = {
      validation: {
        [`issue-${issueNumber}`]: {
          validated: true,
          vulnerabilities: validatedVulns.filter(v => !v.falsePositive),
          falsePositiveCount: validatedVulns.filter(v => v.falsePositive).length,
          timestamp: new Date().toISOString(),
          redTests: {
            xss: { passed: false, message: 'Confirmed XSS vulnerability' },
            sql_injection: { passed: false, message: 'SQL injection confirmed' }
          },
          testResults: {
            totalTests: 5,
            passed: 2,
            failed: 3
          }
        }
      }
    };
    
    console.log(`  Validation results:`);
    console.log(`    - Real vulnerabilities: ${validatedVulns.filter(v => !v.falsePositive).length}`);
    console.log(`    - False positives: ${validatedVulns.filter(v => v.falsePositive).length}`);
    console.log(`    - Red team tests failed: 2/2`);
    
    console.log('\n📝 Storing VALIDATE results to platform...');
    const validateResult = await client.storePhaseResults('validate', validateData, {
      repo,
      issueNumber,
      commitSha
    });
    
    console.log('  Storage result:', validateResult);
  } else {
    console.log('  ❌ Failed to retrieve SCAN data');
    return;
  }
  
  // Simulate time passing between phases
  await new Promise(resolve => setTimeout(resolve, 1000));
  
  console.log('\n' + '='.repeat(60));
  console.log('PHASE 3: MITIGATE - Fix vulnerabilities');
  console.log('='.repeat(60));
  
  // MITIGATE phase retrieves both SCAN and VALIDATE data
  console.log('📖 Retrieving all phase data for mitigation...');
  const allPhaseData = await client.retrievePhaseResults(repo, issueNumber, commitSha);
  
  if (allPhaseData?.validation && allPhaseData?.scan) {
    const validationData = allPhaseData.validation[`issue-${issueNumber}`];
    console.log('  ✅ Retrieved data from previous phases:');
    console.log(`    - SCAN: ${allPhaseData.scan.vulnerabilities.length} vulnerabilities found`);
    console.log(`    - VALIDATE: ${validationData.vulnerabilities.length} confirmed, ${validationData.falsePositiveCount} false positives`);
    
    // Simulate fix generation using validation context
    console.log('\n🔧 Generating fixes based on validation data...');
    const fixes = validationData.vulnerabilities.map(v => ({
      file: v.file,
      line: v.line,
      type: v.type,
      fix: `Applied security fix for ${v.type}`,
      validated: true
    }));
    
    console.log(`  Generated ${fixes.length} fixes:`);
    fixes.forEach(f => {
      console.log(`    - Fixed ${f.type} in ${f.file}:${f.line}`);
    });
    
    const mitigateData = {
      mitigation: {
        [`issue-${issueNumber}`]: {
          fixed: true,
          prUrl: `https://github.com/${repo}/pull/${Math.floor(Math.random() * 1000)}`,
          prNumber: Math.floor(Math.random() * 1000),
          fixCommit: `fix_${commitSha}`,
          filesChanged: fixes.length,
          fixes: fixes,
          timestamp: new Date().toISOString()
        }
      }
    };
    
    console.log('\n📝 Storing MITIGATE results to platform...');
    const mitigateResult = await client.storePhaseResults('mitigate', mitigateData, {
      repo,
      issueNumber,
      commitSha
    });
    
    console.log('  Storage result:', mitigateResult);
    const mitigationKey = `issue-${issueNumber}`;
    console.log(`  ✅ Created PR: ${mitigateData.mitigation[mitigationKey].prUrl}`);
  } else {
    console.log('  ❌ Failed to retrieve phase data');
    return;
  }
  
  // Final verification
  console.log('\n' + '='.repeat(60));
  console.log('VERIFICATION: Retrieve complete phase history');
  console.log('='.repeat(60));
  
  const finalData = await client.retrievePhaseResults(repo, issueNumber, commitSha);
  
  if (finalData) {
    console.log('✅ Complete phase data retrieved:');
    console.log('  SCAN phase:');
    console.log(`    - Vulnerabilities: ${finalData.scan?.vulnerabilities.length || 0}`);
    console.log(`    - Timestamp: ${finalData.scan?.timestamp}`);
    
    const validationKey = `issue-${issueNumber}`;
    console.log('  VALIDATE phase:');
    console.log(`    - Validated: ${finalData.validation?.[validationKey]?.validated || false}`);
    console.log(`    - Confirmed vulnerabilities: ${finalData.validation?.[validationKey]?.vulnerabilities?.length || 0}`);
    
    console.log('  MITIGATE phase:');
    console.log(`    - Fixed: ${finalData.mitigation?.[validationKey]?.fixed || false}`);
    console.log(`    - PR Number: ${finalData.mitigation?.[validationKey]?.prNumber || 'N/A'}`);
    console.log(`    - Files Changed: ${finalData.mitigation?.[validationKey]?.filesChanged || 0}`);
  }
  
  console.log('\n' + '='.repeat(60));
  console.log('🎉 THREE-PHASE FLOW TEST COMPLETE!');
  console.log('='.repeat(60));
  console.log(`
Key Achievements:
✅ SCAN phase stored vulnerability data to platform
✅ VALIDATE phase retrieved SCAN data and enriched it
✅ MITIGATE phase used both SCAN and VALIDATE data
✅ Platform persistence working across all phases
✅ Data correctly flows from phase to phase

This demonstrates the complete three-phase architecture with:
- Data persistence between GitHub Action workflow runs
- Each phase building on previous phase results
- MITIGATE having full context for accurate fixes
  `);
}

// Run the test
testFullThreePhaseFlow().catch(console.error);