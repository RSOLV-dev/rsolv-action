#!/usr/bin/env bun

// E2E test to verify RSOLV-action and RSOLV-api have the same API contract

import { PatternApiClient } from './src/security/pattern-api-client';

const STAGING_API_URL = 'https://api.rsolv-staging.com';

// Test with different API keys
const testScenarios = [
  { 
    name: 'Public tier (no API key)', 
    apiKey: undefined,
    expectedTiers: ['public']
  },
  { 
    name: 'Basic tier', 
    apiKey: 'test-basic-key',
    expectedTiers: ['public', 'standard']
  },
  { 
    name: 'Pro tier', 
    apiKey: 'test-pro-key',
    expectedTiers: ['public', 'standard', 'critical']
  },
  { 
    name: 'Enterprise tier', 
    apiKey: 'test-enterprise-key',
    expectedTiers: ['public', 'standard', 'critical', 'proprietary']
  }
];

async function testPatternApiContract() {
  console.log('Running E2E tests for RSOLV-action <-> RSOLV-api contract...\n');

  for (const scenario of testScenarios) {
    console.log(`\n=== Testing ${scenario.name} ===`);
    
    const client = new PatternApiClient({
      apiUrl: STAGING_API_URL,
      apiKey: scenario.apiKey,
      timeout: 30000
    });

    try {
      // Test 1: Get patterns
      console.log('\n1. Testing getPatterns()...');
      const patterns = await client.getPatterns();
      console.log(`   ✓ Received ${patterns.length} patterns`);
      
      // Verify tier field exists
      if (patterns.length > 0) {
        const pattern = patterns[0];
        if (!pattern.tier) {
          throw new Error('Pattern missing tier field!');
        }
        console.log(`   ✓ Pattern has tier field: ${pattern.tier}`);
        
        // Verify pattern structure
        const requiredFields = ['id', 'name', 'type', 'severity', 'description'];
        for (const field of requiredFields) {
          if (!pattern[field]) {
            throw new Error(`Pattern missing required field: ${field}`);
          }
        }
        console.log('   ✓ Pattern has all required fields');
      }

      // Test 2: Get patterns by language
      console.log('\n2. Testing getPatterns(language)...');
      const jsPatterns = await client.getPatterns('javascript');
      console.log(`   ✓ Received ${jsPatterns.length} JavaScript patterns`);

      // Test 3: Get patterns by tier
      console.log('\n3. Testing tier filtering...');
      for (const tier of ['public', 'standard', 'critical']) {
        try {
          const tierPatterns = await client.getPatterns(undefined, tier);
          console.log(`   ✓ Tier ${tier}: ${tierPatterns.length} patterns`);
        } catch (error) {
          console.log(`   ✗ Tier ${tier}: ${error.message}`);
        }
      }

      // Test 4: Get pattern by ID
      console.log('\n4. Testing getPatternById()...');
      const patternId = 'js-xss-jquery-html';
      const pattern = await client.getPatternById(patternId);
      console.log(`   ✓ Retrieved pattern: ${pattern.name}`);
      console.log(`   ✓ Pattern tier: ${pattern.tier}`);

      // Test 5: Get metadata
      console.log('\n5. Testing getMetadata()...');
      const metadata = await client.getMetadata();
      console.log(`   ✓ Total patterns: ${metadata.total_patterns}`);
      console.log(`   ✓ Languages: ${metadata.languages?.join(', ')}`);
      console.log(`   ✓ Accessible tiers: ${metadata.accessible_tiers?.join(', ')}`);
      
      if (metadata.patterns_by_tier) {
        console.log('   ✓ Patterns by tier:');
        Object.entries(metadata.patterns_by_tier).forEach(([tier, count]) => {
          console.log(`     - ${tier}: ${count}`);
        });
      }

    } catch (error) {
      console.error(`   ✗ Error: ${error.message}`);
      if (error.response) {
        console.error(`   ✗ Response status: ${error.response.status}`);
        console.error(`   ✗ Response body: ${JSON.stringify(error.response.data)}`);
      }
    }
  }

  console.log('\n=== E2E Contract Test Complete ===\n');
}

// Run the tests
testPatternApiContract().catch(console.error);