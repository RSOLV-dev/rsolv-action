#!/usr/bin/env bun

// Simple integration test to verify RSOLV API pattern serving
import { PatternAPIClient } from './src/security/pattern-api-client';

async function testPatternAPI() {
  console.log('Testing RSOLV API pattern integration...\n');
  
  const apiUrl = process.env.RSOLV_API_URL || 'http://localhost:4000';
  const apiKey = process.env.RSOLV_API_KEY || 'test-api-key';
  
  console.log(`API URL: ${apiUrl}`);
  console.log(`API Key: ${apiKey ? '***' + apiKey.slice(-4) : 'not set'}\n`);
  
  const client = new PatternAPIClient({
    apiUrl,
    apiKey
  });
  
  try {
    // Test 1: Health check with retries
    console.log('1. Testing health check...');
    let healthResponse;
    let retries = 5;
    while (retries > 0) {
      try {
        healthResponse = await fetch(`${apiUrl}/health`);
        break;
      } catch (error) {
        retries--;
        if (retries === 0) throw error;
        console.log(`   Connection failed, retrying... (${retries} attempts left)`);
        await new Promise(resolve => setTimeout(resolve, 2000));
      }
    }
    console.log(`   Health status: ${healthResponse!.status} ${healthResponse!.statusText}`);
    
    // Test 2: Fetch patterns
    console.log('\n2. Fetching security patterns...');
    const patterns = await client.fetchPatterns();
    console.log(`   Total patterns fetched: ${patterns.length}`);
    
    // Debug: Show what we're getting
    if (patterns.length === 0) {
      console.log('   DEBUG: No patterns returned. Checking API response...');
      const debugResponse = await fetch(`${apiUrl}/api/v1/patterns`, {
        headers: apiKey ? { 'Authorization': `Bearer ${apiKey}` } : {}
      });
      const debugData = await debugResponse.json();
      console.log('   DEBUG: API Response:', JSON.stringify(debugData, null, 2));
    }
    
    // Test 3: Language breakdown
    const languageGroups = patterns.reduce((acc, pattern) => {
      pattern.languages.forEach(lang => {
        acc[lang] = (acc[lang] || 0) + 1;
      });
      return acc;
    }, {} as Record<string, number>);
    
    console.log('\n   Patterns by language:');
    Object.entries(languageGroups)
      .sort(([, a], [, b]) => b - a)
      .forEach(([lang, count]) => {
        console.log(`   - ${lang}: ${count}`);
      });
    
    // Test 4: Check for enhanced patterns
    console.log('\n3. Checking for enhanced patterns...');
    // The client automatically requests enhanced format when API key is present
    const hasAstRules = patterns.some(p => p.astRules || p.ast_rules);
    console.log(`   Enhanced patterns available: ${hasAstRules ? 'YES' : 'NO'}`);
    
    if (hasAstRules) {
      const withAst = patterns.filter(p => p.astRules || p.ast_rules).length;
      console.log(`   Patterns with AST rules: ${withAst}/${patterns.length}`);
      
      // Show example AST pattern
      const astPattern = patterns.find(p => p.astRules || p.ast_rules);
      if (astPattern) {
        console.log(`\n   Example AST-enhanced pattern: ${astPattern.name}`);
        console.log(`   - Has AST rules: ${!!(astPattern.astRules || astPattern.ast_rules)}`);
        console.log(`   - Has confidence rules: ${!!(astPattern.confidenceRules || astPattern.confidence_rules)}`);
        console.log(`   - Has context rules: ${!!(astPattern.contextRules || astPattern.context_rules)}`);
      }
    }
    
    console.log('\n✅ All tests passed!');
    
  } catch (error) {
    console.error('\n❌ Test failed:', error);
    process.exit(1);
  }
}

// Run the test
testPatternAPI();