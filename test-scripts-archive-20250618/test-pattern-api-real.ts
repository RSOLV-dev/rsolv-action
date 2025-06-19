#!/usr/bin/env bun

/**
 * Real E2E test for Pattern API integration
 * Runs outside test framework to avoid fetch mocking
 */

import { PatternAPIClient } from './src/security/pattern-api-client';
import type { SecurityPattern } from './src/security/types';

const API_URL = 'http://localhost:4000';
const TEST_API_KEY = 'rsolv_test_abc123';

let testsPassed = 0;
let testsFailed = 0;

function assert(condition: boolean, message: string) {
  if (condition) {
    console.log(`✅ ${message}`);
    testsPassed++;
  } else {
    console.log(`❌ ${message}`);
    testsFailed++;
  }
}

async function runTests() {
  console.log('Running Pattern API Integration Tests...\n');

  const client = new PatternAPIClient({
    apiUrl: API_URL,
    apiKey: TEST_API_KEY
  });

  // Test 1: Fetch JavaScript patterns with authentication
  console.log('Test 1: Fetch JavaScript patterns with authentication');
  try {
    const patterns = await client.fetchPatterns('javascript');
    assert(patterns !== undefined, 'Patterns should be defined');
    assert(Array.isArray(patterns), 'Patterns should be an array');
    assert(patterns.length > 10, `Should have more than 10 patterns (got ${patterns.length})`);
    
    // Verify pattern structure
    if (patterns.length > 0) {
      const firstPattern = patterns[0];
      assert(firstPattern.id !== undefined, 'Pattern should have id');
      assert(firstPattern.name !== undefined, 'Pattern should have name');
      assert(firstPattern.type !== undefined, 'Pattern should have type');
      assert(firstPattern.severity !== undefined, 'Pattern should have severity');
      assert(Array.isArray(firstPattern.patterns.regex), 'Pattern should have regex array');
    }
  } catch (error) {
    console.error('Test 1 failed:', error);
    testsFailed++;
  }

  // Test 2: Access multiple pattern tiers
  console.log('\nTest 2: Access multiple pattern tiers');
  try {
    const patterns = await client.fetchPatterns('javascript');
    
    // Group patterns by severity (proxy for tier)
    const bySeverity = patterns.reduce((acc, p) => {
      acc[p.severity] = (acc[p.severity] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);
    
    assert(Object.keys(bySeverity).length > 2, `Should have patterns of multiple severities (got ${Object.keys(bySeverity).length})`);
    assert((bySeverity['critical'] || 0) > 0, 'Should have critical severity patterns');
    assert((bySeverity['high'] || 0) > 0, 'Should have high severity patterns');
    
    console.log('Pattern severity distribution:', bySeverity);
  } catch (error) {
    console.error('Test 2 failed:', error);
    testsFailed++;
  }

  // Test 3: Fetch patterns for different languages
  console.log('\nTest 3: Fetch patterns for different languages');
  const languages = ['javascript', 'python', 'ruby', 'java'];
  
  for (const lang of languages) {
    try {
      const patterns = await client.fetchPatterns(lang);
      assert(patterns !== undefined, `${lang} patterns should be defined`);
      assert(Array.isArray(patterns), `${lang} patterns should be an array`);
      assert(patterns.length > 0, `${lang} should have patterns (got ${patterns.length})`);
      
      // Verify language-specific patterns
      const langPatterns = patterns.filter(p => p.languages.includes(lang));
      assert(langPatterns.length > 0, `Should have ${lang}-specific patterns`);
    } catch (error) {
      console.error(`Test 3 failed for ${lang}:`, error);
      testsFailed++;
    }
  }

  // Test 4: AST-Enhanced patterns
  console.log('\nTest 4: AST-Enhanced patterns');
  try {
    const response = await fetch(`${API_URL}/api/v1/patterns/javascript?format=enhanced`, {
      headers: {
        'Authorization': `Bearer ${TEST_API_KEY}`,
        'Content-Type': 'application/json'
      }
    });
    
    assert(response.ok, 'Enhanced patterns endpoint should return OK');
    const data = await response.json();
    
    assert(data.patterns !== undefined, 'Response should have patterns');
    assert(data.format === 'enhanced', 'Format should be enhanced');
    
    // Check for AST-enhanced patterns
    const enhancedPatterns = data.patterns.filter((p: any) => 
      p.ast_rules || p.context_rules || p.confidence_rules
    );
    
    assert(enhancedPatterns.length > 0, `Should have AST-enhanced patterns (got ${enhancedPatterns.length})`);
    
    if (enhancedPatterns.length > 0) {
      const astPattern = enhancedPatterns[0];
      console.log('Sample AST pattern:', {
        id: astPattern.id,
        has_ast_rules: !!astPattern.ast_rules,
        has_context_rules: !!astPattern.context_rules,
        has_confidence_rules: !!astPattern.confidence_rules
      });
    }
  } catch (error) {
    console.error('Test 4 failed:', error);
    testsFailed++;
  }

  // Test 5: Tier-specific access
  console.log('\nTest 5: Tier-specific access');
  try {
    // Test public access (no auth)
    const publicClient = new PatternAPIClient({
      apiUrl: API_URL,
      apiKey: undefined
    });
    
    const publicPatterns = await publicClient.fetchPatterns('javascript');
    assert(publicPatterns.length > 0, 'Public access should return patterns');
    
    // Test authenticated access
    const authPatterns = await client.fetchPatterns('javascript');
    assert(authPatterns.length > publicPatterns.length, `Authenticated access should return more patterns (auth: ${authPatterns.length}, public: ${publicPatterns.length})`);
    
    // Verify we have patterns from multiple tiers
    const criticalPatterns = authPatterns.filter(p => p.severity === 'critical');
    const highPatterns = authPatterns.filter(p => p.severity === 'high');
    
    assert(criticalPatterns.length > 0, `Should have critical patterns (got ${criticalPatterns.length})`);
    assert(highPatterns.length > 0, `Should have high patterns (got ${highPatterns.length})`);
  } catch (error) {
    console.error('Test 5 failed:', error);
    testsFailed++;
  }

  // Summary
  console.log('\n' + '='.repeat(50));
  console.log(`Tests Passed: ${testsPassed}`);
  console.log(`Tests Failed: ${testsFailed}`);
  console.log('='.repeat(50));
  
  process.exit(testsFailed > 0 ? 1 : 0);
}

// Run the tests
runTests().catch(error => {
  console.error('Test runner failed:', error);
  process.exit(1);
});