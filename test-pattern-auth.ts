#!/usr/bin/env bun

/**
 * Test Pattern API authentication with RSOLV_API_KEY
 * 
 * This script tests if RSOLV-action can properly authenticate
 * and access protected/AI/enterprise tier patterns.
 */

import { TieredPatternSource, CustomerConfig } from './src/security/tiered-pattern-source.js';
import { SecurityDetector } from './src/security/detector.js';

async function testPatternAuthentication() {
  console.log('🔐 Testing Pattern API Authentication\n');
  
  // Get API key from environment or use test key
  const apiKey = process.env.RSOLV_API_KEY || 'test-api-key';
  const apiUrl = process.env.RSOLV_API_URL || 'https://api.rsolv.dev';
  
  console.log(`API URL: ${apiUrl}`);
  console.log(`API Key: ${apiKey.substring(0, 8)}... (${apiKey.length} chars)\n`);
  
  const patternSource = new TieredPatternSource(apiUrl);
  
  // Test different customer configurations
  const configs: { name: string; config: CustomerConfig }[] = [
    {
      name: 'No Auth (Public)',
      config: {}
    },
    {
      name: 'Basic Tier',
      config: {
        apiKey,
        tier: 'basic'
      }
    },
    {
      name: 'Teams Tier',
      config: {
        apiKey,
        tier: 'teams'
      }
    },
    {
      name: 'Enterprise Tier',
      config: {
        apiKey,
        tier: 'enterprise'
      }
    },
    {
      name: 'AI-Enabled',
      config: {
        apiKey,
        aiEnabled: true
      }
    }
  ];
  
  // Test each configuration
  for (const { name, config } of configs) {
    console.log(`\n📋 Testing ${name} Configuration:`);
    console.log(`   Config: ${JSON.stringify(config)}`);
    
    try {
      // Test JavaScript patterns
      const jsPatterns = await patternSource.getPatternsByLanguage('javascript', config);
      console.log(`   ✅ JavaScript patterns: ${jsPatterns.length} patterns retrieved`);
      
      // Test CVE patterns (usually AI/Enterprise tier only)
      const cvePatterns = await patternSource.getPatternsByLanguage('cve', config);
      console.log(`   ✅ CVE patterns: ${cvePatterns.length} patterns retrieved`);
      
      // Show sample pattern details
      if (jsPatterns.length > 0) {
        const pattern = jsPatterns[0];
        console.log(`   📌 Sample pattern: ${pattern.name}`);
        console.log(`      - Type: ${pattern.type}`);
        console.log(`      - Severity: ${pattern.severity}`);
        console.log(`      - Tags: ${pattern.tags.join(', ')}`);
      }
      
    } catch (error) {
      console.error(`   ❌ Error: ${error}`);
    }
  }
  
  // Test pattern detection with authentication
  console.log('\n\n🔍 Testing Pattern Detection with Authentication:');
  
  const vulnerableCode = `
    // Potential vulnerabilities
    const api_key = "sk-1234567890abcdef";
    const password = "admin123";
    
    // SQL Injection
    const query = "SELECT * FROM users WHERE id = " + userId;
    db.query(query);
    
    // XSS
    document.getElementById('output').innerHTML = userInput;
    
    // Path Traversal
    const file = fs.readFileSync('../../../' + userFile);
    
    // Command Injection
    exec('ls ' + userPath);
  `;
  
  // Test with different configurations
  for (const { name, config } of configs.slice(0, 3)) { // Test first 3 configs
    console.log(`\n📋 Detection with ${name}:`);
    
    const detector = new SecurityDetector(patternSource, config);
    const vulnerabilities = await detector.detect(vulnerableCode, 'javascript');
    
    console.log(`   Found ${vulnerabilities.length} vulnerabilities:`);
    const typeCount: Record<string, number> = {};
    vulnerabilities.forEach(v => {
      typeCount[v.type] = (typeCount[v.type] || 0) + 1;
    });
    
    Object.entries(typeCount).forEach(([type, count]) => {
      console.log(`   - ${type}: ${count} occurrences`);
    });
  }
  
  // Test direct API endpoints
  console.log('\n\n🌐 Testing Direct API Endpoints:');
  
  const endpoints = [
    '/api/v1/patterns/public/javascript',
    '/api/v1/patterns/protected/javascript',
    '/api/v1/patterns/ai/javascript',
    '/api/v1/patterns/enterprise/javascript',
    '/api/v1/patterns/public/cve',
    '/api/v1/patterns/ai/cve'
  ];
  
  for (const endpoint of endpoints) {
    try {
      const headers: Record<string, string> = {
        'Content-Type': 'application/json'
      };
      
      // Add auth for non-public endpoints
      if (!endpoint.includes('/public/')) {
        headers['Authorization'] = `Bearer ${apiKey}`;
      }
      
      const response = await fetch(`${apiUrl}${endpoint}`, { headers });
      const data = await response.json();
      
      if (response.ok) {
        console.log(`   ✅ ${endpoint}: ${data.count} patterns (${data.tier} tier)`);
      } else {
        console.log(`   ❌ ${endpoint}: ${response.status} - ${data.error || 'Access denied'}`);
      }
    } catch (error) {
      console.log(`   ❌ ${endpoint}: Failed - ${error}`);
    }
  }
  
  console.log('\n\n✅ Authentication test complete!');
}

// Run the test
testPatternAuthentication().catch(console.error);