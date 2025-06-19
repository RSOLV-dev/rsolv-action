#!/usr/bin/env bun

import { PatternAPIClient } from './src/security/pattern-api-client';

async function testPatternAccess() {
  const apiKeys = [
    { name: 'Test Key', key: 'test' },
    { name: 'Enterprise Key', key: 'rsolv_enterprise_test_448patterns' }
  ];
  
  const languages = ['javascript', 'python', 'ruby', 'java', 'php', 'elixir'];
  
  for (const apiKeyInfo of apiKeys) {
    console.log(`\n🔑 Testing with ${apiKeyInfo.name}: ${apiKeyInfo.key}`);
    console.log('=' .repeat(50));
    
    const client = new PatternAPIClient({
      apiUrl: 'https://api.rsolv.dev',
      apiKey: apiKeyInfo.key
    });
    
    let totalPatterns = 0;
    
    for (const lang of languages) {
      try {
        const patterns = await client.fetchPatterns(lang);
        const count = patterns?.length || 0;
        totalPatterns += count;
        console.log(`  ${lang}: ${count} patterns`);
      } catch (error) {
        console.log(`  ${lang}: ❌ Error - ${error.message}`);
      }
    }
    
    console.log(`\n  Total: ${totalPatterns} patterns`);
  }
  
  // Test specific tier endpoints
  console.log('\n\n🔍 Testing Tier-Specific Endpoints');
  console.log('=' .repeat(50));
  
  const tiers = ['public', 'protected', 'ai', 'enterprise'];
  
  for (const tier of tiers) {
    console.log(`\n${tier.toUpperCase()} Tier:`);
    
    try {
      const response = await fetch(`https://api.rsolv.dev/api/v1/patterns/${tier}/javascript`, {
        headers: {
          'Authorization': 'Bearer rsolv_enterprise_test_448patterns'
        }
      });
      
      if (response.ok) {
        const data = await response.json();
        console.log(`  JavaScript: ${data.count || data.patterns?.length || 0} patterns`);
      } else {
        const error = await response.text();
        console.log(`  JavaScript: ❌ ${response.status} - ${error}`);
      }
    } catch (error) {
      console.log(`  JavaScript: ❌ Error - ${error.message}`);
    }
  }
}

testPatternAccess().catch(console.error);