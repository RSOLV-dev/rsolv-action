#!/usr/bin/env bun

/**
 * Real E2E test against production RSOLV API
 * No mocking - tests actual pattern access with the new 3-tier structure
 */

import { PatternAPIClient } from './src/security/pattern-api-client';
import { SecurityDetectorV2 } from './src/security/detector-v2';
import { HybridPatternSource } from './src/security/pattern-source';
import { logger } from './src/utils/logger';

async function testRealAPI() {
  console.log('🚀 Testing REAL RSOLV API - No Mocks\n');
  
  // Test with different API keys
  const testCases = [
    {
      name: 'No API Key (Public Access Only)',
      apiKey: undefined,
      expectedTiers: ['public']
    },
    {
      name: 'Test API Key',
      apiKey: 'test',
      expectedTiers: ['public', 'protected'] // May have more access
    },
    {
      name: 'Enterprise API Key', 
      apiKey: process.env.RSOLV_ENTERPRISE_KEY || 'rsolv_enterprise_test_448patterns',
      expectedTiers: ['public', 'ai', 'enterprise']
    }
  ];

  for (const testCase of testCases) {
    console.log(`\n📋 Test Case: ${testCase.name}`);
    console.log('=' . repeat(50));
    
    try {
      // 1. Test Pattern API Client directly
      const apiClient = new PatternAPIClient({
        apiUrl: 'https://api.rsolv.dev',
        apiKey: testCase.apiKey
      });

      // Test health check
      console.log('\n1️⃣ Testing API Health Check...');
      const health = await apiClient.checkHealth();
      console.log(`   Health Status: ${health.status}`);
      if (health.message) {
        console.log(`   Message: ${health.message}`);
      }

      // Test fetching patterns by language
      console.log('\n2️⃣ Testing Pattern Fetch by Language...');
      const languages = ['javascript', 'python', 'ruby', 'java', 'php', 'elixir'];
      
      for (const lang of languages) {
        try {
          const patterns = await apiClient.fetchPatterns(lang);
          console.log(`   ${lang}: ${patterns.length} patterns`);
          
          // Show pattern distribution by severity
          const bySeverity = patterns.reduce((acc, p) => {
            acc[p.severity] = (acc[p.severity] || 0) + 1;
            return acc;
          }, {} as Record<string, number>);
          console.log(`     Severity: ${JSON.stringify(bySeverity)}`);
          
          // Show first pattern as example
          if (patterns.length > 0) {
            const first = patterns[0];
            console.log(`     Example: ${first.id} - ${first.name}`);
          }
        } catch (error) {
          console.log(`   ${lang}: ERROR - ${error.message}`);
        }
      }

      // Test tier access  
      console.log('\n3️⃣ Testing Tier Access...');
      const tiers = ['public', 'ai', 'enterprise'] as const;
      
      for (const tier of tiers) {
        try {
          const patterns = await apiClient.fetchPatternsByTier(tier);
          console.log(`   ${tier}: ${patterns.length} patterns accessible`);
        } catch (error) {
          console.log(`   ${tier}: ACCESS DENIED - ${error.message}`);
        }
      }

      // 4. Test with SecurityDetectorV2
      console.log('\n4️⃣ Testing SecurityDetectorV2 Integration...');
      const patternSource = new HybridPatternSource({
        apiKey: testCase.apiKey
      });
      const detector = new SecurityDetectorV2(patternSource);

      // Test with vulnerable code
      const vulnerableCode = `
        // SQL Injection
        const query = "SELECT * FROM users WHERE id = " + req.params.id;
        db.execute(query);
        
        // XSS
        document.getElementById('output').innerHTML = req.query.message;
        
        // Command Injection
        const cmd = "ls " + userInput;
        exec(cmd);
        
        // Hardcoded Secret
        const API_KEY = "sk_live_abcdef123456789";
        
        // Path Traversal
        const file = fs.readFile("./uploads/" + req.params.filename);
      `;

      const vulnerabilities = await detector.detect(vulnerableCode, 'javascript');
      console.log(`   Detected ${vulnerabilities.length} vulnerabilities`);
      
      // Group by type
      const byType = vulnerabilities.reduce((acc, v) => {
        acc[v.type] = (acc[v.type] || 0) + 1;
        return acc;
      }, {} as Record<string, number>);
      console.log(`   By Type: ${JSON.stringify(byType)}`);
      
      // Show unique vulnerability types found
      const uniqueTypes = [...new Set(vulnerabilities.map(v => v.type))];
      console.log(`   Types Found: ${uniqueTypes.join(', ')}`);
      
    } catch (error) {
      console.error(`\n❌ Test failed: ${error.message}`);
      if (error.stack) {
        console.error(error.stack);
      }
    }
  }

  // 5. Test Pattern Count Summary
  console.log('\n\n📊 Pattern Count Summary');
  console.log('=' . repeat(50));
  
  try {
    const apiClient = new PatternAPIClient({
      apiUrl: 'https://api.rsolv.dev',
      apiKey: process.env.RSOLV_ENTERPRISE_KEY || 'rsolv_enterprise_test_448patterns'
    });
    
    const allLanguages = ['javascript', 'python', 'ruby', 'java', 'php', 'elixir'];
    let totalPatterns = 0;
    
    for (const lang of allLanguages) {
      try {
        const patterns = await apiClient.fetchPatterns(lang);
        totalPatterns += patterns.length;
        console.log(`${lang.padEnd(12)}: ${patterns.length} patterns`);
      } catch (error) {
        console.log(`${lang.padEnd(12)}: ERROR`);
      }
    }
    
    console.log('-'.repeat(30));
    console.log(`TOTAL        : ${totalPatterns} patterns`);
    
    // Check if we're getting the expected 170+ patterns with the new tier structure
    if (totalPatterns < 100) {
      console.log('\n⚠️  WARNING: Pattern count seems low. Expected 170+ patterns.');
      console.log('   This might indicate an issue with tier access or pattern migration.');
    } else {
      console.log('\n✅ Pattern count looks good!');
    }
    
  } catch (error) {
    console.error('Failed to get pattern summary:', error.message);
  }

  console.log('\n✅ Real API testing complete!\n');
}

// Run the test
testRealAPI().catch(console.error);