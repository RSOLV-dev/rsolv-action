#!/usr/bin/env bun
/**
 * Pattern Integration Test Script
 * Tests the end-to-end flow of pattern retrieval and application
 * between RSOLV-api and RSOLV-action
 */

import { PatternAPIClient } from './src/security/pattern-api-client';
import { SecurityDetectorV2 } from './src/security/detector-v2';
import { ApiPatternSource } from './src/security/pattern-source';
import type { SecurityPattern } from './src/security/types';

// Configuration
const API_URL = process.env.RSOLV_API_URL || 'http://localhost:4000';
const API_KEY = process.env.RSOLV_API_KEY || '';

// Test vulnerable code samples
const vulnerableCode = {
  javascript: `
    // SQL Injection via concatenation
    const query = db.query("SELECT * FROM users WHERE id = " + req.params.id);
    
    // XSS via innerHTML
    document.getElementById('content').innerHTML = req.body.userInput;
    
    // Command injection via exec
    const exec = require('child_process').exec;
    exec('ls -la ' + userProvidedPath, (err, stdout) => {
      console.log(stdout);
    });
    
    // Path traversal
    const filePath = path.join('/uploads', req.query.filename);
    fs.readFile(filePath, 'utf8', callback);
    
    // Weak crypto - MD5
    const hash = crypto.createHash('md5').update(password).digest('hex');
    
    // Hardcoded API key
    const API_KEY = "sk_live_4242424242424242";
    
    // eval with user input
    eval("var result = " + userInput);
    
    // Open redirect
    res.redirect(req.query.returnUrl);
    
    // XXE - XML parsing
    const parser = new DOMParser();
    const xmlDoc = parser.parseFromString(userXml, "text/xml");
    
    // Prototype pollution
    function merge(target, source) {
      for (let key in source) {
        target[key] = source[key];
      }
    }
  `,
  
  python: `
    # SQL Injection
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    
    # Command injection
    import os
    os.system(f"ping {user_input}")
    
    # Path traversal
    with open(f"/data/{filename}", 'r') as f:
        content = f.read()
  `
};

async function testPatternRetrieval() {
  console.log('\n🔍 Testing Pattern Retrieval from API...\n');
  
  const client = new PatternAPIClient({
    apiUrl: API_URL,
    apiKey: API_KEY,
    cacheEnabled: false
  });
  
  try {
    // Test JavaScript patterns
    console.log('📦 Fetching JavaScript patterns...');
    const jsPatterns = await client.fetchPatterns('javascript');
    console.log(`✅ Retrieved ${jsPatterns.length} JavaScript patterns`);
    
    // Show sample pattern structure
    if (jsPatterns.length > 0) {
      const sample = jsPatterns[0];
      console.log('\n📋 Sample pattern structure:');
      console.log(`  ID: ${sample.id}`);
      console.log(`  Name: ${sample.name}`);
      console.log(`  Type: ${sample.type}`);
      console.log(`  Severity: ${sample.severity}`);
      console.log(`  Regex patterns: ${sample.patterns.regex.length}`);
      console.log(`  CWE: ${sample.cweId}`);
      console.log(`  OWASP: ${sample.owaspCategory}`);
      
      // Check for AST enhancements
      if (sample.astRules) {
        console.log(`  ✨ AST Rules: Present`);
      }
      if (sample.contextRules) {
        console.log(`  ✨ Context Rules: Present`);
      }
    }
    
    // Test pattern by tier
    if (API_KEY) {
      console.log('\n📦 Testing tier-based access...');
      const publicPatterns = await client.fetchPatternsByTier('public');
      console.log(`✅ Public tier: ${publicPatterns.length} patterns`);
      
      try {
        const protectedPatterns = await client.fetchPatternsByTier('protected');
        console.log(`✅ Protected tier: ${protectedPatterns.length} patterns`);
      } catch (e) {
        console.log(`⚠️  Protected tier: ${e.message}`);
      }
    }
    
    return jsPatterns;
  } catch (error) {
    console.error('❌ Pattern retrieval failed:', error);
    throw error;
  }
}

async function testMetadataEndpoint() {
  console.log('\n🔍 Testing Metadata Endpoint...\n');
  
  const patternIds = [
    'js-sql-injection-concat',
    'js-xss-innerhtml',
    'js-xxe-external-entities'
  ];
  
  for (const patternId of patternIds) {
    try {
      const response = await fetch(`${API_URL}/api/v1/patterns/${patternId}/metadata`, {
        headers: API_KEY ? { 'Authorization': `Bearer ${API_KEY}` } : {}
      });
      
      if (response.ok) {
        const metadata = await response.json();
        console.log(`✅ ${patternId}:`);
        console.log(`   Description: ${metadata.description.substring(0, 80)}...`);
        console.log(`   References: ${metadata.references.length}`);
        console.log(`   Attack vectors: ${metadata.attack_vectors.length}`);
        console.log(`   CVE examples: ${metadata.cve_examples.length}`);
      } else {
        console.log(`⚠️  ${patternId}: ${response.status} ${response.statusText}`);
      }
    } catch (error) {
      console.log(`❌ ${patternId}: ${error.message}`);
    }
  }
}

async function testPatternApplication(patterns: SecurityPattern[]) {
  console.log('\n🔍 Testing Pattern Application...\n');
  
  // Create detector with API source
  const patternSource = new ApiPatternSource(API_KEY, API_URL);
  const detector = new SecurityDetectorV2(patternSource);
  
  console.log('🔍 Analyzing JavaScript code...');
  const vulnerabilities = await detector.detect(vulnerableCode.javascript, 'javascript');
  
  console.log(`\n✅ Detected ${vulnerabilities.length} vulnerabilities:\n`);
  
  // Group by type for better display
  const byType = new Map<string, typeof vulnerabilities>();
  for (const vuln of vulnerabilities) {
    const list = byType.get(vuln.type) || [];
    list.push(vuln);
    byType.set(vuln.type, list);
  }
  
  // Display results
  for (const [type, vulns] of byType) {
    console.log(`\n🔴 ${type} (${vulns.length} found)`);
    for (const vuln of vulns) {
      console.log(`   Line ${vuln.line}: ${vuln.message}`);
      console.log(`   Severity: ${vuln.severity}`);
      console.log(`   CWE: ${vuln.cweId || 'N/A'}`);
      if (vuln.remediation) {
        console.log(`   Fix: ${vuln.remediation}`);
      }
    }
  }
  
  return vulnerabilities;
}

async function testSpecificPatterns() {
  console.log('\n🔍 Testing Specific Pattern Detection...\n');
  
  const testCases = [
    {
      name: 'SQL Injection (concat)',
      code: 'db.query("SELECT * FROM users WHERE id = " + userId)',
      expectedPattern: 'js-sql-injection-concat'
    },
    {
      name: 'XSS (innerHTML)', 
      code: 'element.innerHTML = userInput',
      expectedPattern: 'js-xss-innerhtml'
    },
    {
      name: 'XXE (DOMParser)',
      code: 'const parser = new DOMParser()',
      expectedPattern: 'js-xxe-external-entities'
    },
    {
      name: 'Open Redirect',
      code: 'res.redirect(req.query.returnUrl)',
      expectedPattern: 'js-open-redirect'
    },
    {
      name: 'Prototype Pollution',
      code: 'target[key] = source[key]',
      expectedPattern: 'js-prototype-pollution'
    }
  ];
  
  const patternSource = new ApiPatternSource(API_KEY, API_URL);
  const detector = new SecurityDetectorV2(patternSource);
  
  for (const testCase of testCases) {
    const vulns = await detector.detect(testCase.code, 'javascript');
    if (vulns.length > 0) {
      console.log(`✅ ${testCase.name}: Detected`);
    } else {
      console.log(`❌ ${testCase.name}: Not detected`);
    }
  }
}

async function testEnhancedPatterns() {
  console.log('\n🔍 Testing Enhanced Pattern Features...\n');
  
  const response = await fetch(`${API_URL}/api/v1/patterns/javascript?format=enhanced`, {
    headers: API_KEY ? { 'Authorization': `Bearer ${API_KEY}` } : {}
  });
  
  if (response.ok) {
    const data = await response.json();
    console.log(`✅ Enhanced format returned ${data.count} patterns`);
    console.log(`   Format: ${data.format}`);
    
    // Check for AST-enhanced patterns
    const astPatterns = data.patterns.filter(p => p.ast_rules);
    console.log(`   AST-enhanced patterns: ${astPatterns.length}`);
    
    const contextPatterns = data.patterns.filter(p => p.context_rules);
    console.log(`   Context-aware patterns: ${contextPatterns.length}`);
    
    const confidencePatterns = data.patterns.filter(p => p.confidence_rules);
    console.log(`   Confidence rules: ${confidencePatterns.length}`);
  } else {
    console.log(`❌ Enhanced format request failed: ${response.status}`);
  }
}

// Main execution
async function main() {
  console.log('🚀 RSOLV Pattern Integration Test');
  console.log('================================\n');
  console.log(`API URL: ${API_URL}`);
  console.log(`API Key: ${API_KEY ? 'Provided' : 'Not provided (public patterns only)'}`);
  
  try {
    // Test 1: Pattern Retrieval
    const patterns = await testPatternRetrieval();
    
    // Test 2: Metadata Endpoint
    await testMetadataEndpoint();
    
    // Test 3: Pattern Application
    await testPatternApplication(patterns);
    
    // Test 4: Specific Pattern Detection
    await testSpecificPatterns();
    
    // Test 5: Enhanced Patterns
    await testEnhancedPatterns();
    
    console.log('\n✅ All tests completed successfully!');
    
  } catch (error) {
    console.error('\n❌ Test failed:', error);
    process.exit(1);
  }
}

// Run the tests
main().catch(console.error);