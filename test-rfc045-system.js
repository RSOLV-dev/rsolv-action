#!/usr/bin/env node

/**
 * System-level test for RFC-045: Validation Confidence Scoring
 * Tests the full integration of confidence scoring in the RSOLV action
 */

import { execSync } from 'child_process';
import fs from 'fs';
import path from 'path';

const ISSUES_TO_TEST = [
  { number: 320, type: 'COMMAND_INJECTION', description: 'Command injection' },
  { number: 323, type: 'XSS', description: 'Cross-Site Scripting' },
  { number: 321, type: 'INSECURE_DESERIALIZATION', description: 'Insecure Deserialization' },
  { number: 327, type: 'WEAK_CRYPTOGRAPHY', description: 'Weak Cryptography' }
];

const results = [];

console.log('🧪 RFC-045 System Test: Validation Confidence Scoring\n');
console.log('=' . repeat(60));

for (const issue of ISSUES_TO_TEST) {
  console.log(`\n📋 Testing Issue #${issue.number}: ${issue.description}`);
  console.log('-'.repeat(40));
  
  try {
    const output = execSync(
      `GITHUB_REPOSITORY=RSOLV-dev/nodegoat-vulnerability-demo ` +
      `RSOLV_MODE=validate ` +
      `GITHUB_TOKEN=$GITHUB_CR_PAT ` +
      `RSOLV_API_KEY=$RSOLV_INTERNAL_API_KEY ` +
      `RSOLV_ISSUE_NUMBER=${issue.number} ` +
      `timeout 30s node dist/index.js 2>&1`,
      { encoding: 'utf8', stdio: 'pipe' }
    );
    
    // Check for enriched vulnerabilities
    const enrichedMatch = output.match(/Enriched issue #\d+ with (\d+) specific vulnerabilities/);
    const vulnCount = enrichedMatch ? parseInt(enrichedMatch[1]) : 0;
    
    // Check phase data storage (local file)
    const phaseDataPath = `.rsolv/phase-data/RSOLV-dev-nodegoat-vulnerability-demo-${issue.number}-validate.json`;
    let confidence = 'unknown';
    let hasVulnerabilities = false;
    let vulnerabilities = [];
    
    if (fs.existsSync(phaseDataPath)) {
      const fileData = JSON.parse(fs.readFileSync(phaseDataPath, 'utf8'));
      const phaseData = fileData.data?.validation?.[`issue-${issue.number}`] || {};
      confidence = phaseData.confidence || 'unknown';
      hasVulnerabilities = phaseData.hasSpecificVulnerabilities || false;
      vulnerabilities = phaseData.vulnerabilities || [];
      
      // Check specific vulnerability details
      if (vulnerabilities.length > 0) {
        const vuln = vulnerabilities[0];
        console.log(`  ✅ Vulnerability found: ${vuln.type}`);
        console.log(`  📊 Confidence: ${vuln.confidence || confidence}`);
        console.log(`  📁 File: ${vuln.file || 'unknown'}`);
        console.log(`  📍 Line: ${vuln.line || 'unknown'}`);
      }
    }
    
    const testResult = {
      issue: issue.number,
      type: issue.type,
      success: vulnCount > 0 && hasVulnerabilities,
      vulnerabilityCount: vulnCount,
      confidence: confidence,
      hasSpecificVulnerabilities: hasVulnerabilities,
      vulnerabilities: vulnerabilities
    };
    
    results.push(testResult);
    
    if (testResult.success) {
      console.log(`  ✅ SUCCESS: Found ${vulnCount} vulnerabilities with confidence: ${confidence}`);
    } else {
      console.log(`  ❌ FAILED: No vulnerabilities found (this should not happen!)`);
    }
    
  } catch (error) {
    console.log(`  ⚠️ ERROR: ${error.message.split('\n')[0]}`);
    results.push({
      issue: issue.number,
      type: issue.type,
      success: false,
      error: error.message.split('\n')[0]
    });
  }
}

// Summary
console.log('\n' + '='.repeat(60));
console.log('📊 TEST SUMMARY\n');

const successful = results.filter(r => r.success).length;
const failed = results.filter(r => !r.success).length;

console.log(`Total tests: ${results.length}`);
console.log(`✅ Successful: ${successful}`);
console.log(`❌ Failed: ${failed}`);
console.log(`Success rate: ${((successful / results.length) * 100).toFixed(1)}%`);

console.log('\n📈 Confidence Distribution:');
const confidenceCounts = {};
results.forEach(r => {
  if (r.confidence) {
    confidenceCounts[r.confidence] = (confidenceCounts[r.confidence] || 0) + 1;
  }
});
Object.entries(confidenceCounts).forEach(([level, count]) => {
  console.log(`  ${level}: ${count} issues`);
});

// Key validations
console.log('\n🔍 Key Validations:');
console.log(`  1. No zero vulnerability returns: ${failed === 0 ? '✅ PASS' : '❌ FAIL'}`);
console.log(`  2. Confidence scoring active: ${Object.keys(confidenceCounts).length > 0 ? '✅ PASS' : '❌ FAIL'}`);
console.log(`  3. Command injection works: ${results.find(r => r.issue === 320)?.success ? '✅ PASS' : '❌ FAIL'}`);

// Cleanup phase data
console.log('\n🧹 Cleaning up phase data...');
try {
  execSync('rm -rf .rsolv/phase-data/*', { stdio: 'ignore' });
} catch (e) {
  // Ignore cleanup errors
}

console.log('\n✨ RFC-045 System Test Complete!\n');
process.exit(failed > 0 ? 1 : 0);