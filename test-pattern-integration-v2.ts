#!/usr/bin/env bun

/**
 * Test RSOLV pattern integration - Version 2
 * Tests both PatternAPIClient and SecurityDetectorV2
 */

import { PatternAPIClient } from './src/security/pattern-api-client';
import { SecurityDetectorV2 } from './src/security/detector-v2';
import { ApiPatternSource } from './src/security/pattern-source';

const TEST_API_KEY = 'rsolv_test_abc123';
const API_URL = process.env.RSOLV_API_URL || 'http://localhost:4001';

console.log('🔍 Testing RSOLV Pattern Integration V2\n');

// Test vulnerable code samples
const vulnerableCode = `
// SQL Injection (protected tier)
const query = db.query("SELECT * FROM users WHERE id = " + userId);
const query2 = connection.execute(\`SELECT * FROM products WHERE name = '\${productName}'\`);

// XSS (public tier)
element.innerHTML = userInput;
document.write(data);

// Command Injection (protected tier)
const exec = require('child_process').exec;
exec('ls ' + userInput);
spawn('git', ['clone', userRepo], {shell: true});

// Path Traversal (protected tier)
const file = path.join('./uploads', req.params.filename);
fs.readFile("./data/" + userFile);

// Weak Crypto (public tier)
crypto.createHash('md5').update(password);
const hash = crypto.createHash('sha1');

// Hardcoded Secrets (public tier)
const password = "admin123";
const apiKey = "sk-1234567890abcdef";

// Eval (protected tier)
eval(userCode);

// XXE (protected tier)
const parser = new DOMParser();
const doc = parser.parseFromString(xmlString, 'text/xml');

// Open Redirect (public tier)
res.redirect(req.query.url);

// Unsafe Regex (public tier)
const pattern = new RegExp("(a+)+$");

// Prototype Pollution (protected tier)
obj[key] = value;

// Insecure Deserialization (protected tier)
const data = JSON.parse(userInput);
unserialize(userData);
`;

async function testPatternAPI() {
  console.log('1️⃣ Testing PatternAPIClient directly...');
  
  const client = new PatternAPIClient({
    apiUrl: API_URL,
    apiKey: TEST_API_KEY
  });

  try {
    const patterns = await client.fetchPatterns('javascript');
    console.log(`✅ Retrieved ${patterns.length} patterns from API`);
    
    // Analyze pattern distribution
    const bySeverity = patterns.reduce((acc, p) => {
      acc[p.severity] = (acc[p.severity] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);
    
    console.log('📊 Pattern distribution by severity:', bySeverity);
    
    // Check for protected patterns
    const protectedTypes = ['SQL_INJECTION', 'COMMAND_INJECTION', 'XXE', 'PATH_TRAVERSAL'];
    const protectedPatterns = patterns.filter(p => 
      protectedTypes.includes(p.type) || 
      ['critical', 'high'].includes(p.severity)
    );
    
    console.log(`🔒 Protected tier patterns: ${protectedPatterns.length}`);
    console.log('');
    
    return patterns;
  } catch (error) {
    console.error('❌ PatternAPIClient error:', error);
    return [];
  }
}

async function testDetectorWithAPI() {
  console.log('2️⃣ Testing SecurityDetectorV2 with API patterns...');
  
  // Create pattern source with API key
  const patternSource = new ApiPatternSource(TEST_API_KEY, API_URL);
  
  // Create detector with our pattern source
  const detector = new SecurityDetectorV2(patternSource);
  
  try {
    const vulnerabilities = await detector.detect(vulnerableCode, 'javascript');
    console.log(`✅ Detected ${vulnerabilities.length} vulnerabilities`);
    
    // Group by type
    const byType = vulnerabilities.reduce((acc, v) => {
      acc[v.type] = (acc[v.type] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);
    
    console.log('📊 Vulnerabilities by type:', byType);
    
    // Show some examples
    console.log('\n🔍 Sample findings:');
    vulnerabilities.slice(0, 5).forEach(v => {
      console.log(`  - Line ${v.lineNumber}: ${v.type} (${v.severity})`);
      console.log(`    ${v.line}`);
    });
    
    return vulnerabilities;
  } catch (error) {
    console.error('❌ Detector error:', error);
    return [];
  }
}

async function testTierAccess() {
  console.log('\n3️⃣ Testing tier-specific access...');
  
  const client = new PatternAPIClient({
    apiUrl: API_URL,
    apiKey: TEST_API_KEY
  });
  
  // Test different endpoints
  const endpoints = [
    { path: '/api/v1/patterns/javascript', name: 'Default endpoint' },
    { path: '/api/v1/patterns/public/javascript', name: 'Public tier' },
    { path: '/api/v1/patterns/protected/javascript', name: 'Protected tier' },
    { path: '/api/v1/patterns/ai/javascript', name: 'AI tier' },
    { path: '/api/v1/patterns/enterprise/javascript', name: 'Enterprise tier' }
  ];
  
  for (const endpoint of endpoints) {
    try {
      const response = await fetch(`${API_URL}${endpoint.path}`, {
        headers: {
          'Authorization': `Bearer ${TEST_API_KEY}`,
          'Content-Type': 'application/json'
        }
      });
      
      if (response.ok) {
        const data = await response.json();
        console.log(`  ✅ ${endpoint.name}: ${data.count || data.patterns?.length || 0} patterns`);
      } else {
        console.log(`  ❌ ${endpoint.name}: ${response.status} ${response.statusText}`);
      }
    } catch (error: any) {
      console.log(`  ❌ ${endpoint.name}: ${error.message}`);
    }
  }
}

async function testEnhancedFormat() {
  console.log('\n4️⃣ Testing enhanced pattern format...');
  
  try {
    const response = await fetch(`${API_URL}/api/v1/patterns/javascript?format=enhanced`, {
      headers: {
        'Authorization': `Bearer ${TEST_API_KEY}`,
        'Content-Type': 'application/json'
      }
    });
    
    if (response.ok) {
      const data = await response.json();
      const enhanced = data.patterns.filter((p: any) => 
        p.ast_rules || p.context_rules || p.confidence_rules
      );
      
      console.log(`  ✅ Enhanced patterns: ${enhanced.length}/${data.patterns.length}`);
      
      if (enhanced.length > 0) {
        const sample = enhanced[0];
        console.log(`  📋 Sample enhanced pattern: ${sample.id}`);
        if (sample.ast_rules) console.log('    - Has AST rules');
        if (sample.context_rules) console.log('    - Has context rules');
        if (sample.confidence_rules) console.log('    - Has confidence rules');
      }
    }
  } catch (error) {
    console.error('  ❌ Enhanced format error:', error);
  }
}

async function runAllTests() {
  // Test 1: Pattern API
  const patterns = await testPatternAPI();
  
  // Test 2: Detector with API
  const vulnerabilities = await testDetectorWithAPI();
  
  // Test 3: Tier access
  await testTierAccess();
  
  // Test 4: Enhanced format
  await testEnhancedFormat();
  
  // Summary
  console.log('\n📊 Test Summary:');
  console.log(`  - Patterns fetched: ${patterns.length}`);
  console.log(`  - Vulnerabilities detected: ${vulnerabilities.length}`);
  console.log(`  - Test customer has ${patterns.length > 10 ? '✅ FULL' : '❌ LIMITED'} pattern access`);
  
  if (patterns.length > 10 && vulnerabilities.length > 5) {
    console.log('\n✅ All tests passed! Pattern integration is working correctly.');
  } else {
    console.log('\n⚠️  Some tests may have issues. Check the output above.');
  }
}

// Run all tests
runAllTests().catch(console.error);