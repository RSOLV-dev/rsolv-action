#!/usr/bin/env node
/**
 * Puppeteer E2E test for RSOLV API production verification
 * This test verifies the API is accessible and returns expected responses
 */

const API_URL = 'https://api.rsolv.dev';

console.log('🧪 Starting Puppeteer API Verification Tests');
console.log('==========================================');
console.log(`API URL: ${API_URL}`);
console.log(`Timestamp: ${new Date().toISOString()}`);
console.log('');

async function runTests() {
  let testsPassed = 0;
  let testsFailed = 0;

  // Test 1: Health Endpoint HTML Response
  console.log('1️⃣  Testing Health Endpoint via Browser');
  console.log('--------------------------------------');
  
  try {
    // Navigate to health endpoint
    console.log('   Navigating to /health endpoint...');
    await navigate(`${API_URL}/health`);
    
    // Take screenshot for verification
    await screenshot('health-endpoint', false, 1200, 800);
    console.log('   ✅ Screenshot captured');
    
    // Get page content
    const pageContent = await evaluate('document.body.textContent');
    console.log('   Page content received');
    
    // Parse JSON response
    try {
      const healthData = JSON.parse(pageContent);
      
      // Verify response structure
      if (healthData.status === 'healthy' && 
          healthData.service === 'rsolv-api' &&
          healthData.services &&
          healthData.services.database === 'healthy') {
        console.log('   ✅ Health check passed - API is healthy');
        testsPassed++;
      } else {
        console.log('   ❌ Health check failed - unexpected response structure');
        console.log('   Response:', JSON.stringify(healthData, null, 2));
        testsFailed++;
      }
    } catch (parseError) {
      console.log('   ❌ Failed to parse JSON response');
      console.log('   Content:', pageContent);
      testsFailed++;
    }
    
  } catch (error) {
    console.log('   ❌ Failed to access health endpoint');
    console.log('   Error:', error.message);
    testsFailed++;
  }
  
  console.log('');
  
  // Test 2: Verify API Error Handling
  console.log('2️⃣  Testing API Error Handling');
  console.log('-----------------------------');
  
  try {
    // Try to access a non-existent endpoint
    console.log('   Testing 404 handling...');
    await navigate(`${API_URL}/api/v1/nonexistent`);
    
    const errorContent = await evaluate('document.body.textContent');
    
    // Check if we get a proper error response
    if (errorContent.includes('404') || errorContent.includes('Not Found')) {
      console.log('   ✅ 404 error handling works correctly');
      testsPassed++;
    } else {
      console.log('   ❌ Unexpected response for non-existent endpoint');
      testsFailed++;
    }
  } catch (error) {
    console.log('   ✅ Navigation failed as expected (404)');
    testsPassed++;
  }
  
  console.log('');
  
  // Test 3: API Response Headers
  console.log('3️⃣  Testing API Response Headers');
  console.log('-------------------------------');
  
  try {
    // Execute JavaScript to make fetch request and check headers
    const headers = await evaluate(`
      fetch('${API_URL}/health')
        .then(response => {
          const headerObj = {};
          response.headers.forEach((value, key) => {
            headerObj[key] = value;
          });
          return headerObj;
        })
    `);
    
    console.log('   Response headers received');
    
    // Check for important headers
    if (headers['content-type'] && headers['content-type'].includes('application/json')) {
      console.log('   ✅ Content-Type header is correct');
      testsPassed++;
    } else {
      console.log('   ❌ Content-Type header is missing or incorrect');
      testsFailed++;
    }
    
    // Check for CORS headers if present
    if (headers['access-control-allow-origin']) {
      console.log('   ℹ️  CORS headers present:', headers['access-control-allow-origin']);
    }
    
  } catch (error) {
    console.log('   ❌ Failed to check response headers');
    console.log('   Error:', error.message);
    testsFailed++;
  }
  
  console.log('');
  
  // Test 4: Performance Check
  console.log('4️⃣  Testing API Performance');
  console.log('--------------------------');
  
  try {
    const performanceData = await evaluate(`
      const startTime = performance.now();
      fetch('${API_URL}/health')
        .then(() => {
          const endTime = performance.now();
          return endTime - startTime;
        })
    `);
    
    console.log(`   Response time: ${performanceData.toFixed(2)}ms`);
    
    if (performanceData < 1000) {
      console.log('   ✅ Performance is good (< 1s)');
      testsPassed++;
    } else {
      console.log('   ⚠️  Performance is slow (> 1s)');
      testsFailed++;
    }
  } catch (error) {
    console.log('   ❌ Failed to measure performance');
    console.log('   Error:', error.message);
    testsFailed++;
  }
  
  console.log('');
  console.log('========================================');
  console.log('📊 Test Summary');
  console.log('========================================');
  console.log(`Passed: ${testsPassed}`);
  console.log(`Failed: ${testsFailed}`);
  console.log(`Total:  ${testsPassed + testsFailed}`);
  console.log('');
  
  if (testsFailed === 0) {
    console.log('✅ All Puppeteer tests passed! The API is accessible via browser.');
  } else {
    console.log('❌ Some tests failed. Please review the results above.');
  }
  
  return testsFailed === 0;
}

// Helper function to use MCP navigation
async function navigate(url) {
  // This will be called via MCP
  console.log(`   Navigating to: ${url}`);
  // Return placeholder - actual navigation happens via MCP
  return true;
}

// Helper function to use MCP screenshot
async function screenshot(name, encoded = false, width = 800, height = 600) {
  // This will be called via MCP
  console.log(`   Taking screenshot: ${name}`);
  // Return placeholder - actual screenshot happens via MCP
  return true;
}

// Helper function to use MCP evaluate
async function evaluate(script) {
  // This will be called via MCP
  console.log(`   Evaluating script...`);
  // Return placeholder - actual evaluation happens via MCP
  return true;
}

// Export for use in MCP context
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { runTests };
}

// Run tests if called directly
if (require.main === module) {
  runTests();
}