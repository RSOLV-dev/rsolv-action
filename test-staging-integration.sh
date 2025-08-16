#!/bin/bash
# Test RSOLV-action against staging environment with three-phase flow

set -e

echo "=================================="
echo "RSOLV-action Staging Integration Test"
echo "=================================="

# Set staging environment variables
export RSOLV_API_URL="https://api.rsolv-staging.com"
export RSOLV_API_KEY="staging_working_1755309826_817a3a5f74749a58948b3ad6"
export USE_PLATFORM_STORAGE="true"
export GITHUB_TOKEN="${GITHUB_TOKEN:-$GITHUB_CR_PAT}"
export NODE_ENV="test"

# Test repository details
export TEST_REPO="RSOLV-dev/test-staging-$(date +%s)"
export TEST_COMMIT="abc123"
export TEST_ISSUE="99"

echo ""
echo "Configuration:"
echo "  API URL: $RSOLV_API_URL"
echo "  Platform Storage: $USE_PLATFORM_STORAGE"
echo "  Test Repo: $TEST_REPO"
echo "  Test Issue: #$TEST_ISSUE"
echo ""

# Build the action locally
echo "Building RSOLV-action..."
npm run build

echo ""
echo "Testing Phase Data Client directly..."
echo "======================================"

# Create a test script to exercise the PhaseDataClient
cat > test-phase-client.ts << 'EOF'
import { PhaseDataClient } from './src/modes/phase-data-client';

async function testPhaseDataClient() {
  const client = new PhaseDataClient(
    process.env.RSOLV_API_KEY!,
    process.env.RSOLV_API_URL
  );

  const testRepo = process.env.TEST_REPO!;
  const testIssue = parseInt(process.env.TEST_ISSUE!);
  const testCommit = process.env.TEST_COMMIT!;

  console.log('\n1. Testing SCAN phase storage...');
  const scanData = {
    vulnerabilities: [
      {
        type: 'xss',
        file: 'app.js',
        line: 42,
        severity: 'high',
        description: 'Cross-site scripting vulnerability'
      }
    ],
    timestamp: new Date().toISOString(),
    commitHash: testCommit
  };

  const scanPhaseData = { scan: scanData };
  await client.storePhaseResults('scan', scanPhaseData, {
    repo: testRepo,
    issueNumber: testIssue,
    commitSha: testCommit,
    branch: 'main'
  });
  console.log('   ✅ SCAN data stored');

  console.log('\n2. Testing VALIDATE phase retrieval and storage...');
  const retrievedScan = await client.retrievePhaseResults(testRepo, testIssue, testCommit);
  
  if (!retrievedScan?.scan) {
    throw new Error('SCAN data not retrieved in VALIDATE phase');
  }
  console.log('   ✅ Retrieved SCAN data:', JSON.stringify(retrievedScan.scan).substring(0, 100) + '...');

  const validationData = {
    [`issue-${testIssue}`]: {
      validated: true,
      confidence: 0.95,
      vulnerabilities: retrievedScan.scan.vulnerabilities,
      testResults: 'All validation tests passed',
      timestamp: new Date().toISOString()
    }
  };

  const validatePhaseData = { validation: validationData };
  await client.storePhaseResults('validate', validatePhaseData, {
    repo: testRepo,
    issueNumber: testIssue,
    commitSha: testCommit,
    branch: 'main'
  });
  console.log('   ✅ VALIDATION data stored');

  console.log('\n3. Testing MITIGATE phase retrieval...');
  const allData = await client.retrievePhaseResults(testRepo, testIssue, testCommit);
  
  if (!allData?.scan) {
    throw new Error('SCAN data not retrieved in MITIGATE phase');
  }
  if (!allData?.validation?.[`issue-${testIssue}`]) {
    throw new Error('VALIDATION data not retrieved in MITIGATE phase');
  }
  
  console.log('   ✅ Retrieved all phase data:');
  console.log('      - SCAN: ', !!allData.scan);
  console.log('      - VALIDATION: ', !!allData.validation);
  
  const mitigationData = {
    [`issue-${testIssue}`]: {
      fixed: true,
      prUrl: 'https://github.com/' + testRepo + '/pull/123',
      prNumber: 123,
      filesChanged: 1,
      timestamp: new Date().toISOString()
    }
  };

  const mitigatePhaseData = { mitigation: mitigationData };
  await client.storePhaseResults('mitigate', mitigatePhaseData, {
    repo: testRepo,
    issueNumber: testIssue,
    commitSha: testCommit,
    branch: 'main'
  });
  console.log('   ✅ MITIGATION data stored');

  console.log('\n4. Final verification - retrieve all data...');
  const finalData = await client.retrievePhaseResults(testRepo, testIssue, testCommit);
  
  if (!finalData?.scan || !finalData?.validation || !finalData?.mitigation) {
    throw new Error('Not all phase data retrieved in final check');
  }

  console.log('   ✅ All three phases data available:');
  console.log('      - SCAN vulnerabilities:', finalData.scan.vulnerabilities?.length || 0);
  console.log('      - VALIDATION validated:', finalData.validation[`issue-${testIssue}`]?.validated);
  console.log('      - MITIGATION PR:', finalData.mitigation[`issue-${testIssue}`]?.prUrl);

  console.log('\n✅ SUCCESS! Three-phase data flow working on staging!');
  return true;
}

testPhaseDataClient()
  .then(() => {
    console.log('\n================================');
    console.log('Staging integration test PASSED!');
    console.log('================================\n');
    process.exit(0);
  })
  .catch((error) => {
    console.error('\n❌ Test failed:', error);
    process.exit(1);
  });
EOF

# Run the test
echo ""
echo "Running three-phase integration test..."
echo "========================================"
npx tsx test-phase-client.ts

# Clean up
rm -f test-phase-client.ts

echo ""
echo "Test completed successfully!"
echo ""
echo "Next steps:"
echo "1. Run with act for full GitHub Action simulation:"
echo "   act -j test-staging --env-file .env.staging"
echo ""
echo "2. Or deploy to a test repository and trigger manually"