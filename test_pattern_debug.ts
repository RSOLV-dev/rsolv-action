#!/usr/bin/env bun

/**
 * Pattern API Debug Test
 * Focuses on diagnosing the pattern loading issue
 */

async function testPatternVariations() {
  console.log('🔍 Testing different pattern API endpoints...');
  
  const variations = [
    'http://localhost:4000/api/v1/patterns',
    'http://localhost:4000/api/v1/patterns?language=python',
    'http://localhost:4000/api/v1/patterns?format=standard',
    'http://localhost:4000/api/v1/patterns?format=enhanced',
    'http://localhost:4000/api/v1/patterns?language=python&format=standard',
    'http://localhost:4000/api/v1/patterns?language=python&format=enhanced',
    'http://localhost:4000/api/v1/patterns?language=javascript&format=enhanced',
  ];
  
  for (const url of variations) {
    try {
      console.log(`\n📡 Testing: ${url}`);
      
      const response = await fetch(url, {
        headers: {
          'Accept': 'application/json'
        }
      });
      
      console.log(`   Status: ${response.status} ${response.statusText}`);
      
      if (response.ok) {
        const data = await response.json();
        console.log(`   ✅ Success: ${data.patterns?.length || 0} patterns`);
      } else {
        const text = await response.text();
        console.log(`   ❌ Error: ${text.substring(0, 100)}...`);
      }
      
      // Small delay to avoid overwhelming the server
      await new Promise(resolve => setTimeout(resolve, 100));
      
    } catch (error) {
      console.log(`   💥 Exception: ${error}`);
    }
  }
}

async function testDifferentMethods() {
  console.log('\n🔧 Testing different HTTP methods...');
  
  const methods = ['GET', 'POST', 'HEAD'];
  const url = 'http://localhost:4000/api/v1/patterns?language=python&format=enhanced';
  
  for (const method of methods) {
    try {
      console.log(`\n🌐 Testing ${method}: ${url}`);
      
      const options: any = {
        method,
        headers: {
          'Accept': 'application/json'
        }
      };
      
      if (method === 'POST') {
        options.headers['Content-Type'] = 'application/json';
        options.body = JSON.stringify({ language: 'python', format: 'enhanced' });
      }
      
      const response = await fetch(url, options);
      console.log(`   Status: ${response.status} ${response.statusText}`);
      
      if (response.ok && method !== 'HEAD') {
        const text = await response.text();
        console.log(`   Response size: ${text.length} characters`);
      }
      
    } catch (error) {
      console.log(`   💥 Exception: ${error}`);
    }
  }
}

async function testWithAPIKey() {
  console.log('\n🔑 Testing with API key...');
  
  const url = 'http://localhost:4000/api/v1/patterns?language=python&format=enhanced';
  
  try {
    const response = await fetch(url, {
      headers: {
        'Accept': 'application/json',
        'X-API-Key': 'rsolv_test_abc123'
      }
    });
    
    console.log(`   Status: ${response.status} ${response.statusText}`);
    
    if (response.ok) {
      const data = await response.json();
      console.log(`   ✅ Success with API key: ${data.patterns?.length || 0} patterns`);
    } else {
      const text = await response.text();
      console.log(`   ❌ Error with API key: ${text.substring(0, 100)}...`);
    }
    
  } catch (error) {
    console.log(`   💥 Exception: ${error}`);
  }
}

async function testCORS() {
  console.log('\n🌐 Testing CORS headers...');
  
  const url = 'http://localhost:4000/api/v1/patterns?language=python&format=enhanced';
  
  try {
    const response = await fetch(url, {
      headers: {
        'Accept': 'application/json',
        'Origin': 'http://localhost:3000'
      }
    });
    
    console.log(`   Status: ${response.status} ${response.statusText}`);
    console.log(`   CORS headers:`);
    console.log(`     Access-Control-Allow-Origin: ${response.headers.get('access-control-allow-origin')}`);
    console.log(`     Access-Control-Allow-Methods: ${response.headers.get('access-control-allow-methods')}`);
    
  } catch (error) {
    console.log(`   💥 Exception: ${error}`);
  }
}

async function main() {
  console.log('🚀 Pattern API Debug Test');
  console.log('='.repeat(40));
  
  await testPatternVariations();
  await testDifferentMethods();
  await testWithAPIKey();
  await testCORS();
  
  console.log('\n✅ Pattern debug completed');
  console.log('\nSuggestions:');
  console.log('- If all pattern API calls fail, check pattern server startup');
  console.log('- If some work, focus on the failing parameters');
  console.log('- Check server logs for detailed error messages');
}

main().catch(console.error);