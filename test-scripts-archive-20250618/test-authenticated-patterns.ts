#!/usr/bin/env bun

/**
 * Test authenticated access to protected/AI/enterprise patterns
 * This simulates how RSOLV-action would access patterns with proper API key
 */

import { TieredPatternSource, CustomerConfig } from './src/security/tiered-pattern-source.js';
import { SecurityDetector } from './src/security/detector.js';

async function testAuthenticatedPatterns() {
  console.log('🧪 Testing Authenticated Pattern Access...\n');
  
  const apiUrl = process.env.RSOLV_API_URL || 'https://api.rsolv.dev';
  const apiKey = process.env.RSOLV_API_KEY || 'test-api-key';
  
  console.log(`API URL: ${apiUrl}`);
  console.log(`API Key: ${apiKey.substring(0, 10)}...${apiKey.substring(apiKey.length - 4)}\n`);
  
  const patternSource = new TieredPatternSource(apiUrl);
  
  // Test 1: Public patterns (baseline)
  console.log('📋 Test 1: Public patterns (no auth)...');
  try {
    const publicPatterns = await patternSource.getPatternsByLanguage('javascript');
    console.log(`✅ Retrieved ${publicPatterns.length} public patterns`);
  } catch (error) {
    console.error('❌ Failed to get public patterns:', error);
  }
  
  // Test 2: Protected tier patterns
  console.log('\n📋 Test 2: Protected tier patterns (with API key)...');
  try {
    const protectedConfig: CustomerConfig = {
      apiKey: apiKey,
      tier: 'teams'
    };
    const protectedPatterns = await patternSource.getPatternsByLanguage('javascript', protectedConfig);
    console.log(`✅ Retrieved ${protectedPatterns.length} patterns from protected tier`);
  } catch (error) {
    console.error('❌ Failed to get protected patterns:', error);
  }
  
  // Test 3: AI tier patterns
  console.log('\n📋 Test 3: AI tier patterns (with API key + AI flag)...');
  try {
    const aiConfig: CustomerConfig = {
      apiKey: apiKey,
      tier: 'teams',
      aiEnabled: true
    };
    const aiPatterns = await patternSource.getPatternsByLanguage('javascript', aiConfig);
    console.log(`✅ Retrieved ${aiPatterns.length} patterns from AI tier`);
  } catch (error) {
    console.error('❌ Failed to get AI patterns:', error);
  }
  
  // Test 4: Enterprise tier patterns
  console.log('\n📋 Test 4: Enterprise tier patterns...');
  try {
    const enterpriseConfig: CustomerConfig = {
      apiKey: apiKey,
      tier: 'enterprise'
    };
    const enterprisePatterns = await patternSource.getPatternsByLanguage('javascript', enterpriseConfig);
    console.log(`✅ Retrieved ${enterprisePatterns.length} patterns from enterprise tier`);
  } catch (error) {
    console.error('❌ Failed to get enterprise patterns:', error);
  }
  
  // Test 5: CVE patterns (usually in AI/enterprise tier)
  console.log('\n📋 Test 5: CVE patterns...');
  try {
    const cveConfig: CustomerConfig = {
      apiKey: apiKey,
      tier: 'enterprise',
      aiEnabled: true
    };
    const cvePatterns = await patternSource.getPatternsByLanguage('cve', cveConfig);
    console.log(`✅ Retrieved ${cvePatterns.length} CVE patterns`);
  } catch (error) {
    console.error('❌ Failed to get CVE patterns:', error);
  }
  
  // Test 6: Full security detection with authenticated patterns
  console.log('\n📋 Test 6: Security detection with authenticated patterns...');
  try {
    const customerConfig: CustomerConfig = {
      apiKey: apiKey,
      tier: 'enterprise',
      aiEnabled: true
    };
    
    const detector = new SecurityDetector(patternSource, customerConfig);
    
    const vulnerableCode = `
      // Advanced vulnerabilities that require proprietary patterns
      const jwt = require('jsonwebtoken');
      const token = jwt.sign({ id: userId }, 'hardcoded-secret');
      
      app.get('/api/users/:id', (req, res) => {
        db.query(\`SELECT * FROM users WHERE id = \${req.params.id}\`);
      });
      
      // CVE-2021-44228 Log4Shell pattern
      logger.info("User input: " + userInput);
    `;
    
    const vulnerabilities = await detector.detect(vulnerableCode, 'javascript');
    console.log(`✅ Detected ${vulnerabilities.length} vulnerabilities with authenticated patterns`);
    vulnerabilities.forEach(v => {
      console.log(`   - ${v.type}: ${v.message} (severity: ${v.severity})`);
    });
  } catch (error) {
    console.error('❌ Detection with authenticated patterns failed:', error);
  }
  
  console.log('\n🔍 Authentication Test Summary:');
  console.log('- Public patterns should always work');
  console.log('- Protected/AI/Enterprise tiers require valid RSOLV_API_KEY');
  console.log('- If authentication fails, system falls back to public patterns');
}

// Run the test
testAuthenticatedPatterns();