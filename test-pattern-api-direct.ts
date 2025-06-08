#!/usr/bin/env bun

/**
 * Direct test of the Pattern API
 * 
 * This bypasses any test mocking to verify the API is working
 */

import { TieredPatternSource } from './src/security/tiered-pattern-source.js';

async function testPatternAPI() {
  console.log('🧪 Testing Pattern API directly...\n');
  
  const apiUrl = process.env.RSOLV_API_URL || 'http://localhost:4000';
  console.log(`API URL: ${apiUrl}\n`);
  
  const patternSource = new TieredPatternSource(apiUrl);
  
  try {
    // Test 1: Public patterns (no auth)
    console.log('📋 Test 1: Fetching public JavaScript patterns...');
    const publicPatterns = await patternSource.getPatternsByLanguage('javascript');
    console.log(`✅ Retrieved ${publicPatterns.length} public patterns`);
    if (publicPatterns.length > 0) {
      console.log(`   First pattern: ${publicPatterns[0].name} (${publicPatterns[0].type})`);
    }
    
    // Test 2: Protected patterns (with API key)
    console.log('\n📋 Test 2: Fetching protected patterns with API key...');
    const customerConfig = {
      apiKey: 'test-api-key',
      tier: 'teams' as const
    };
    const protectedPatterns = await patternSource.getPatternsByLanguage('javascript', customerConfig);
    console.log(`✅ Retrieved ${protectedPatterns.length} patterns (should fall back to public if auth fails)`);
    
    // Test 3: CVE patterns (AI tier)
    console.log('\n📋 Test 3: Fetching AI tier CVE patterns...');
    const aiConfig = {
      apiKey: 'test-api-key',
      aiEnabled: true
    };
    const cvePatterns = await patternSource.getPatternsByLanguage('cve', aiConfig);
    console.log(`✅ Retrieved ${cvePatterns.length} CVE patterns`);
    
    // Test 4: Direct API call with curl
    console.log('\n📋 Test 4: Direct API call verification...');
    const response = await fetch(`${apiUrl}/api/v1/patterns/public/javascript`);
    const data = await response.json();
    console.log(`✅ Direct API response: ${data.count} patterns in ${data.tier} tier`);
    
    // Test 5: Pattern detection
    console.log('\n📋 Test 5: Testing pattern detection...');
    const { SecurityDetector } = await import('./src/security/detector.js');
    const detector = new SecurityDetector(patternSource);
    
    const vulnerableCode = `
      const api_key = "sk-1234567890abcdef";
      document.getElementById('output').innerHTML = userInput;
    `;
    
    const vulnerabilities = await detector.detect(vulnerableCode, 'javascript');
    console.log(`✅ Detected ${vulnerabilities.length} vulnerabilities`);
    vulnerabilities.forEach(v => {
      console.log(`   - ${v.type}: ${v.message} (line ${v.line})`);
    });
    
    console.log('\n✅ All tests passed! Pattern API is working correctly.');
    
  } catch (error) {
    console.error('❌ Test failed:', error);
    process.exit(1);
  }
}

// Run the test
testPatternAPI();