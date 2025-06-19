#!/usr/bin/env bun

// Simple E2E test to verify RSOLV-api pattern responses

const STAGING_API_URL = 'https://api.rsolv-staging.com';

async function testPatternApi() {
  console.log('Testing RSOLV-api pattern endpoints in staging...\n');

  // Test 1: Basic pattern listing
  console.log('1. Testing pattern listing...');
  try {
    const response = await fetch(`${STAGING_API_URL}/api/v1/patterns?limit=3`);
    const data = await response.json();
    
    console.log(`   Status: ${response.status}`);
    console.log(`   Total patterns: ${data.count || data.patterns?.length || 0}`);
    
    if (data.patterns && data.patterns.length > 0) {
      const pattern = data.patterns[0];
      console.log('\n   First pattern structure:');
      console.log(`   - ID: ${pattern.id}`);
      console.log(`   - Name: ${pattern.name}`);
      console.log(`   - Tier: ${pattern.tier || 'NOT FOUND!'}`);
      console.log(`   - Type: ${pattern.type}`);
      console.log(`   - Severity: ${pattern.severity}`);
      
      // Check required fields
      const requiredFields = ['id', 'name', 'type', 'severity', 'description', 'tier'];
      const missingFields = requiredFields.filter(field => !pattern[field]);
      
      if (missingFields.length > 0) {
        console.error(`   ✗ Missing required fields: ${missingFields.join(', ')}`);
      } else {
        console.log('   ✓ All required fields present');
      }
    }
  } catch (error) {
    console.error(`   ✗ Error: ${error.message}`);
  }

  // Test 2: Tier filtering
  console.log('\n2. Testing tier filtering...');
  const tiers = ['public', 'standard', 'critical', 'proprietary'];
  
  for (const tier of tiers) {
    try {
      const response = await fetch(`${STAGING_API_URL}/api/v1/patterns?tier=${tier}&limit=1`);
      const data = await response.json();
      
      if (response.status === 200) {
        console.log(`   ✓ Tier ${tier}: ${data.patterns?.length || 0} patterns returned`);
        if (data.patterns && data.patterns[0]) {
          console.log(`     Pattern tier: ${data.patterns[0].tier}`);
        }
      } else {
        console.log(`   ✗ Tier ${tier}: HTTP ${response.status}`);
      }
    } catch (error) {
      console.error(`   ✗ Tier ${tier}: ${error.message}`);
    }
  }

  // Test 3: Metadata endpoint
  console.log('\n3. Testing metadata endpoint...');
  try {
    const response = await fetch(`${STAGING_API_URL}/api/v1/patterns/metadata`);
    const data = await response.json();
    
    console.log(`   Status: ${response.status}`);
    console.log(`   Total patterns: ${data.total_patterns || data.count}`);
    console.log(`   Accessible tiers: ${data.accessible_tiers?.join(', ') || 'none'}`);
    
    if (data.patterns_by_tier) {
      console.log('   Patterns by tier:');
      Object.entries(data.patterns_by_tier).forEach(([tier, count]) => {
        console.log(`   - ${tier}: ${count}`);
      });
    }
  } catch (error) {
    console.error(`   ✗ Error: ${error.message}`);
  }

  // Test 4: v2 metadata endpoint
  console.log('\n4. Testing v2 metadata endpoint...');
  try {
    const response = await fetch(`${STAGING_API_URL}/api/v2/patterns/metadata`);
    const data = await response.json();
    
    console.log(`   Status: ${response.status}`);
    console.log(`   Format: ${data.format || 'unknown'}`);
    
    if (data.patterns && data.patterns.length > 0) {
      const pattern = data.patterns[0];
      console.log(`   First pattern has tier: ${pattern.tier ? 'YES' : 'NO'}`);
    }
  } catch (error) {
    console.error(`   ✗ Error: ${error.message}`);
  }

  // Test 5: Specific pattern retrieval
  console.log('\n5. Testing specific pattern retrieval...');
  try {
    const response = await fetch(`${STAGING_API_URL}/api/v1/patterns/js-xss-jquery-html`);
    const data = await response.json();
    
    console.log(`   Status: ${response.status}`);
    if (data.data || data.pattern) {
      const pattern = data.data || data.pattern;
      console.log(`   Pattern: ${pattern.name}`);
      console.log(`   Tier: ${pattern.tier || 'NOT FOUND!'}`);
    }
  } catch (error) {
    console.error(`   ✗ Error: ${error.message}`);
  }

  console.log('\n=== Test Complete ===\n');
}

// Run the test
testPatternApi().catch(console.error);