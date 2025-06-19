// Test pattern API in staging environment with new tier structure

const STAGING_API_URL = 'https://api.rsolv-staging.com';

async function testPatternEndpoints() {
  console.log('Testing pattern endpoints in staging...\n');

  // Test listing all patterns
  console.log('1. Testing GET /api/v1/patterns...');
  try {
    const response = await fetch(`${STAGING_API_URL}/api/v1/patterns`);
    const data = await response.json();
    
    console.log(`Status: ${response.status}`);
    console.log(`Total patterns: ${data.data?.length || 0}`);
    
    if (data.data && data.data.length > 0) {
      const pattern = data.data[0];
      console.log('\nFirst pattern structure:');
      console.log(`- ID: ${pattern.id}`);
      console.log(`- Name: ${pattern.name}`);
      console.log(`- Tier: ${pattern.tier}`);
      console.log(`- Categories: ${pattern.categories?.join(', ') || 'none'}`);
      console.log(`- Severity: ${pattern.severity}`);
      console.log(`- Language: ${pattern.language}`);
    }
  } catch (error) {
    console.error('Error:', error);
  }

  // Test filtering by tier
  console.log('\n2. Testing tier filtering...');
  for (const tier of ['critical', 'important', 'standard', 'experimental']) {
    try {
      const response = await fetch(`${STAGING_API_URL}/api/v1/patterns?tier=${tier}`);
      const data = await response.json();
      console.log(`Tier ${tier}: ${data.data?.length || 0} patterns`);
    } catch (error) {
      console.error(`Error fetching ${tier}:`, error);
    }
  }

  // Test filtering by category
  console.log('\n3. Testing category filtering...');
  try {
    const response = await fetch(`${STAGING_API_URL}/api/v1/patterns?category=sql-injection`);
    const data = await response.json();
    console.log(`SQL Injection patterns: ${data.data?.length || 0}`);
  } catch (error) {
    console.error('Error:', error);
  }

  // Test metadata endpoint
  console.log('\n4. Testing GET /api/v1/patterns/metadata...');
  try {
    const response = await fetch(`${STAGING_API_URL}/api/v1/patterns/metadata`);
    const data = await response.json();
    
    console.log(`Status: ${response.status}`);
    console.log('\nMetadata:');
    console.log(`Total patterns: ${data.total_patterns}`);
    console.log(`Languages: ${data.languages?.length || 0}`);
    console.log(`Categories: ${data.categories?.length || 0}`);
    
    if (data.patterns_by_tier) {
      console.log('\nPatterns by tier:');
      Object.entries(data.patterns_by_tier).forEach(([tier, count]) => {
        console.log(`- ${tier}: ${count}`);
      });
    }
  } catch (error) {
    console.error('Error:', error);
  }

  // Test specific pattern
  console.log('\n5. Testing GET /api/v1/patterns/js-001...');
  try {
    const response = await fetch(`${STAGING_API_URL}/api/v1/patterns/js-001`);
    const data = await response.json();
    
    console.log(`Status: ${response.status}`);
    if (data.data) {
      console.log(`Pattern: ${data.data.name}`);
      console.log(`Tier: ${data.data.tier}`);
      console.log(`Categories: ${data.data.categories?.join(', ') || 'none'}`);
    }
  } catch (error) {
    console.error('Error:', error);
  }
}

// Run the tests
testPatternEndpoints().catch(console.error);