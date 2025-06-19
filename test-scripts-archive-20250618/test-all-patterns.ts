#!/usr/bin/env bun

/**
 * Test script to verify all pattern tiers can be accessed
 * Uses test API key for authentication
 */

import { PatternAPIClient } from './src/security/pattern-api-client';
import { SecurityDetectorV2 } from './src/security/detector-v2';

const TEST_API_KEY = 'rsolv_test_abc123';
const API_URL = process.env.RSOLV_API_URL || 'http://localhost:4001';

console.log('🔍 Testing Pattern Access Across All Tiers\n');

async function testPatternAccess() {
  // Test 1: Public tier (no auth)
  console.log('1️⃣ Testing PUBLIC tier (no auth)...');
  const publicClient = new PatternAPIClient({ 
    apiUrl: API_URL,
    apiKey: undefined 
  });
  
  try {
    const publicPatterns = await publicClient.getPatterns('javascript');
    console.log(`   ✅ Retrieved ${publicPatterns.length} public patterns`);
    console.log(`   Examples: ${publicPatterns.slice(0, 3).map(p => p.id).join(', ')}\n`);
  } catch (error) {
    console.error('   ❌ Failed to get public patterns:', error.message);
  }

  // Test 2: With test API key
  console.log('2️⃣ Testing with TEST API KEY...');
  const authClient = new PatternAPIClient({ 
    apiUrl: API_URL,
    apiKey: TEST_API_KEY 
  });
  
  try {
    const authPatterns = await authClient.getPatterns('javascript');
    console.log(`   ✅ Retrieved ${authPatterns.length} patterns with auth`);
    
    // Group by severity to see tier distribution
    const bySeverity = authPatterns.reduce((acc, p) => {
      acc[p.severity] = (acc[p.severity] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);
    
    console.log(`   Severity distribution:`, bySeverity);
    
    // Show some protected patterns
    const protectedPatterns = authPatterns.filter(p => 
      ['critical', 'high'].includes(p.severity) && 
      ['sql_injection', 'command_injection', 'xxe'].includes(p.type)
    );
    console.log(`   Protected patterns found: ${protectedPatterns.map(p => p.id).join(', ')}\n`);
  } catch (error) {
    console.error('   ❌ Failed with auth:', error.message);
  }

  // Test 3: Use test endpoint for all tiers
  console.log('3️⃣ Testing ALL TIERS via test endpoint...');
  try {
    const response = await fetch(`${API_URL}/api/v1/test/patterns/javascript`);
    const data = await response.json();
    
    console.log(`   ✅ Total patterns available: ${data.total_count}`);
    console.log(`   Tier distribution:`, data.tier_distribution);
    
    // Test specific tier access
    console.log('\n4️⃣ Testing specific tier access...');
    for (const tier of ['public', 'protected', 'ai', 'enterprise']) {
      const tierResponse = await fetch(`${API_URL}/api/v1/test/patterns/javascript/${tier}`);
      const tierData = await tierResponse.json();
      console.log(`   ${tier}: ${tierData.count} patterns`);
    }
  } catch (error) {
    console.error('   ❌ Test endpoint failed:', error.message);
  }

  // Test 4: Pattern detection with all patterns
  console.log('\n5️⃣ Testing pattern detection with protected patterns...');
  const detector = new SecurityDetectorV2();
  
  const vulnerableCode = `
    // SQL Injection (protected pattern)
    const query = db.query("SELECT * FROM users WHERE id = " + userId);
    
    // XXE (protected pattern)
    const parser = new DOMParser();
    const doc = parser.parseFromString(xmlString, 'text/xml');
    
    // Open Redirect (public pattern)
    res.redirect(req.query.url);
  `;
  
  try {
    // Get all patterns from test endpoint
    const allPatternsResponse = await fetch(`${API_URL}/api/v1/test/patterns/javascript`);
    const allPatternsData = await allPatternsResponse.json();
    
    // Apply patterns
    const findings = await detector.detectVulnerabilities(
      vulnerableCode,
      'test.js',
      allPatternsData.patterns
    );
    
    console.log(`   ✅ Detected ${findings.length} vulnerabilities:`);
    findings.forEach(f => {
      console.log(`      - ${f.pattern.id} (line ${f.lineNumber})`);
    });
  } catch (error) {
    console.error('   ❌ Detection failed:', error.message);
  }
}

// Run the tests
testPatternAccess().catch(console.error);