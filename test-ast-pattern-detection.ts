#!/usr/bin/env bun

/**
 * Test AST pattern detection in RSOLV-action
 * Verifies that AST-enhanced patterns reduce false positives
 */

import { SecurityDetectorV2 } from './src/security/detector-v2';
import { ApiPatternSource } from './src/security/pattern-source';
import { writeFileSync, mkdirSync, rmSync } from 'fs';
import { join } from 'path';

const testDir = './test-ast-detection';

// Create test directory
mkdirSync(testDir, { recursive: true });

async function testASTPatternDetection() {
  console.log('Testing AST Pattern Detection in RSOLV-action\n');
  
  const apiUrl = process.env.RSOLV_API_URL || 'http://localhost:4000';
  const apiKey = process.env.RSOLV_API_KEY || 'test-api-key';
  
  // Initialize pattern source
  const patternSource = new ApiPatternSource(apiKey, apiUrl);
  
  // Initialize detector with API patterns
  const detector = new SecurityDetectorV2(patternSource);
  
  // Test Case 1: SQL Injection - Should be detected
  const sqlInjectionCode = `
const express = require('express');
const mysql = require('mysql2');

app.get('/user', (req, res) => {
  const userId = req.query.id;
  // VULNERABLE: Direct string concatenation in SQL query
  const query = "SELECT * FROM users WHERE id = " + userId;
  db.query(query, (err, results) => {
    res.json(results);
  });
});
`;
  
  const sqlFile = join(testDir, 'sql-injection.js');
  writeFileSync(sqlFile, sqlInjectionCode);
  
  // Test Case 2: False positive - console.log with SQL string
  const consoleLogCode = `
function debugQuery() {
  const userId = "123";
  // NOT VULNERABLE: Just logging, not executing
  console.log("SELECT * FROM users WHERE id = " + userId);
}
`;
  
  const consoleFile = join(testDir, 'console-log.js');
  writeFileSync(consoleFile, consoleLogCode);
  
  // Test Case 3: Safe parameterized query
  const safeCode = `
app.get('/user', (req, res) => {
  const userId = req.query.id;
  // SAFE: Using parameterized query
  const query = "SELECT * FROM users WHERE id = ?";
  db.query(query, [userId], (err, results) => {
    res.json(results);
  });
});
`;
  
  const safeFile = join(testDir, 'safe-query.js');
  writeFileSync(safeFile, safeCode);
  
  try {
    // Detect vulnerabilities
    console.log('1. Detecting SQL injection (should find vulnerability)...');
    const sqlResults = await detector.detect(sqlInjectionCode, 'javascript', sqlFile);
    console.log(`   Found ${sqlResults.length} vulnerabilities`);
    if (sqlResults.length > 0) {
      console.log(`   ✅ Correctly detected: ${sqlResults[0].message}`);
      console.log(`   Confidence: ${sqlResults[0].confidence || 'N/A'}`);
    } else {
      console.log('   ❌ Failed to detect SQL injection!');
    }
    
    console.log('\n2. Checking console.log false positive (should NOT find vulnerability)...');
    const consoleResults = await detector.detect(consoleLogCode, 'javascript', consoleFile);
    console.log(`   Found ${consoleResults.length} vulnerabilities`);
    if (consoleResults.length === 0) {
      console.log('   ✅ Correctly ignored console.log statement');
    } else {
      console.log('   ❌ False positive detected in console.log!');
    }
    
    console.log('\n3. Checking safe parameterized query (should NOT find vulnerability)...');
    const safeResults = await detector.detect(safeCode, 'javascript', safeFile);
    console.log(`   Found ${safeResults.length} vulnerabilities`);
    if (safeResults.length === 0) {
      console.log('   ✅ Correctly recognized safe parameterized query');
    } else {
      console.log('   ❌ False positive detected in safe code!');
    }
    
    // Summary
    const totalTests = 3;
    const passed = 
      (sqlResults.length > 0 ? 1 : 0) +
      (consoleResults.length === 0 ? 1 : 0) +
      (safeResults.length === 0 ? 1 : 0);
    
    console.log(`\n📊 Summary: ${passed}/${totalTests} tests passed`);
    
    if (passed === totalTests) {
      console.log('✅ AST pattern detection is working correctly!');
    } else {
      console.log('❌ Some tests failed - AST patterns may not be working properly');
      process.exit(1);
    }
    
  } catch (error) {
    console.error('Error during testing:', error);
    process.exit(1);
  } finally {
    // Cleanup
    rmSync(testDir, { recursive: true, force: true });
  }
}

// Run the test
testASTPatternDetection();