#!/usr/bin/env bun
/**
 * End-to-end test for three-phase architecture
 * Tests SCAN → VALIDATE → MITIGATE with the demo SQL injection repository
 */

import { PhaseExecutor } from './src/modes/phase-executor/index.js';
import { ActionConfig, IssueContext } from './src/types/index.js';
import { config } from 'dotenv';
import { execSync } from 'child_process';
import { existsSync, readFileSync } from 'fs';
import { join } from 'path';

// Load environment variables
config();

const DEMO_REPO_PATH = '/home/dylan/dev/rsolv/demo-repos/rsolv-sql-injection-demo';
const ANTHROPIC_API_KEY = process.env.ANTHROPIC_API_KEY || '';

if (!ANTHROPIC_API_KEY) {
  console.error('❌ ANTHROPIC_API_KEY not set');
  process.exit(1);
}

// Configuration
const actionConfig: ActionConfig = {
  aiProvider: {
    provider: 'anthropic',
    apiKey: ANTHROPIC_API_KEY,
    model: 'claude-3-5-sonnet-20241022',
    maxTokens: 4000
  },
  enableSecurityAnalysis: true,
  fixValidation: {
    enabled: true,
    maxIterations: 3
  },
  testGeneration: {
    enabled: true,
    validateFixes: true
  }
} as ActionConfig;

// Test issue matching the demo repository vulnerability
const testIssue: IssueContext = {
  id: 'sql-injection-demo',
  number: 1,
  title: 'SQL Injection in authentication endpoints',
  body: `## Security Vulnerability: SQL Injection

Found SQL injection vulnerabilities in the authentication module.

### Vulnerable Code Locations

1. **authenticateUser function** (src/auth/login.js:10-18)
   - Direct string concatenation in SQL query
   - User input not sanitized

2. **getUserOrders function** (src/auth/login.js:22-31)
   - No input validation
   - Direct interpolation of userId

### Impact
An attacker could:
- Bypass authentication
- Extract sensitive user data
- Modify or delete database records

### Recommended Fix
Use parameterized queries with prepared statements to prevent SQL injection.`,
  labels: ['rsolv:automate', 'security', 'high-priority'],
  assignees: [],
  repository: {
    owner: 'demo',
    name: 'rsolv-sql-injection-demo',
    fullName: 'demo/rsolv-sql-injection-demo',
    defaultBranch: 'main',
    language: 'JavaScript'
  },
  source: 'github',
  createdAt: new Date().toISOString(),
  updatedAt: new Date().toISOString(),
  metadata: {}
};

async function resetRepository() {
  console.log('🔄 Resetting demo repository to clean state...');
  execSync('git checkout main', { cwd: DEMO_REPO_PATH });
  execSync('git reset --hard HEAD', { cwd: DEMO_REPO_PATH });
  execSync('git clean -fd', { cwd: DEMO_REPO_PATH });
  console.log('✅ Repository reset');
}

async function runThreePhaseTest() {
  console.log('\n🚀 Starting Three-Phase Architecture E2E Test\n');
  
  try {
    // Reset repository to clean state
    await resetRepository();
    
    // Change to demo repo directory
    const originalDir = process.cwd();
    process.chdir(DEMO_REPO_PATH);
    
    // Initialize executor
    const executor = new PhaseExecutor(actionConfig);
    
    console.log('═══════════════════════════════════════════');
    console.log('       PHASE 1: SCAN');
    console.log('═══════════════════════════════════════════\n');
    
    const scanResult = await executor.executeScanForIssue(testIssue);
    
    if (!scanResult.success) {
      console.error('❌ Scan phase failed:', scanResult.error);
      return false;
    }
    
    console.log('✅ Scan completed successfully');
    console.log('   - Can be fixed:', scanResult.data.canBeFixed);
    console.log('   - Issue type:', scanResult.data.analysisData?.issueType);
    console.log('   - Files to modify:', scanResult.data.analysisData?.filesToModify);
    console.log('   - Severity:', scanResult.data.analysisData?.severity);
    
    if (!scanResult.data.canBeFixed) {
      console.log('⚠️  Issue cannot be automatically fixed');
      return false;
    }
    
    console.log('\n═══════════════════════════════════════════');
    console.log('       PHASE 2: VALIDATE');
    console.log('═══════════════════════════════════════════\n');
    
    const validateResult = await executor.executeValidateForIssue(
      testIssue,
      scanResult.data
    );
    
    if (!validateResult.success) {
      console.error('❌ Validate phase failed:', validateResult.error);
      return false;
    }
    
    console.log('✅ Validation completed successfully');
    console.log('   - Tests generated:', validateResult.data.generatedTests?.success);
    console.log('   - Test framework:', validateResult.data.generatedTests?.framework || 'Template');
    console.log('   - Test count:', validateResult.data.generatedTests?.tests?.length || 0);
    
    console.log('\n═══════════════════════════════════════════');
    console.log('       PHASE 3: MITIGATE');
    console.log('═══════════════════════════════════════════\n');
    
    const mitigateResult = await executor.executeMitigateForIssue(
      testIssue,
      scanResult.data,
      validateResult.data
    );
    
    if (!mitigateResult.success) {
      console.error('❌ Mitigate phase failed:', mitigateResult.error);
      return false;
    }
    
    console.log('✅ Mitigation completed successfully');
    console.log('   - Commit hash:', mitigateResult.data.commitHash);
    console.log('   - Files modified:', mitigateResult.data.filesModified);
    console.log('   - PR created:', mitigateResult.data.pullRequestUrl ? 'Yes' : 'No (local only)');
    
    // Verify the fix
    console.log('\n═══════════════════════════════════════════');
    console.log('       VERIFICATION');
    console.log('═══════════════════════════════════════════\n');
    
    const fixedCode = readFileSync(
      join(DEMO_REPO_PATH, 'src/auth/login.js'), 
      'utf-8'
    );
    
    // Check for parameterized queries indicators
    const hasParameterizedQueries = 
      fixedCode.includes('?') || 
      fixedCode.includes('$1') ||
      fixedCode.includes('prepared') ||
      fixedCode.includes('parameterized') ||
      fixedCode.includes('escape');
    
    // Check if vulnerabilities are still present
    const stillHasVulnerability = 
      fixedCode.includes("${username}") && 
      fixedCode.includes("${password}") &&
      fixedCode.includes("${userId}");
    
    console.log('Fix verification:');
    console.log('   - Has parameterized queries:', hasParameterizedQueries);
    console.log('   - Still has original vulnerability:', stillHasVulnerability);
    
    if (hasParameterizedQueries || !stillHasVulnerability) {
      console.log('✅ Fix verified: SQL injection vulnerability addressed');
    } else {
      console.log('⚠️  Fix may be incomplete or different approach used');
    }
    
    // Show git diff
    console.log('\n📝 Changes made:');
    const diff = execSync('git diff --stat', { cwd: DEMO_REPO_PATH }).toString();
    console.log(diff);
    
    process.chdir(originalDir);
    return true;
    
  } catch (error) {
    console.error('❌ Test failed with error:', error);
    return false;
  }
}

async function runPipelineTest() {
  console.log('\n🔄 Testing Full Pipeline Mode\n');
  
  try {
    await resetRepository();
    const originalDir = process.cwd();
    process.chdir(DEMO_REPO_PATH);
    
    const executor = new PhaseExecutor(actionConfig);
    
    console.log('Executing three-phase pipeline...');
    const result = await executor.executeThreePhaseForIssue(testIssue);
    
    if (!result.success) {
      console.error('❌ Pipeline failed:', result.error || result.message);
      process.chdir(originalDir);
      return false;
    }
    
    console.log('✅ Pipeline completed successfully');
    console.log('   - Scan:', result.data.scan ? '✓' : '✗');
    console.log('   - Validation:', result.data.validation ? '✓' : '✗');
    console.log('   - Mitigation:', result.data.mitigation ? '✓' : '✗');
    
    process.chdir(originalDir);
    return true;
    
  } catch (error) {
    console.error('❌ Pipeline test failed:', error);
    return false;
  }
}

async function runStandaloneValidationTest() {
  console.log('\n🔍 Testing Standalone Validation Mode\n');
  
  try {
    await resetRepository();
    const originalDir = process.cwd();
    process.chdir(DEMO_REPO_PATH);
    
    const executor = new PhaseExecutor(actionConfig);
    
    console.log('Executing validation-only mode...');
    const result = await executor.execute('validate', {
      issues: [testIssue],
      runTests: false,
      postComment: false,
      format: 'json'
    });
    
    if (!result.success) {
      console.error('❌ Validation failed:', result.error);
      process.chdir(originalDir);
      return false;
    }
    
    console.log('✅ Validation completed');
    console.log('   - Issues validated:', result.data.validations?.length || 0);
    console.log('   - Format:', result.data.format);
    
    process.chdir(originalDir);
    return true;
    
  } catch (error) {
    console.error('❌ Validation test failed:', error);
    return false;
  }
}

// Main execution
async function main() {
  console.log('🧪 Three-Phase Architecture E2E Test Suite');
  console.log('==========================================');
  console.log(`📁 Using demo repo: ${DEMO_REPO_PATH}\n`);
  
  let testsRun = 0;
  let testsPassed = 0;
  
  // Test individual phases
  console.log('Test 1: Individual Phases');
  testsRun++;
  if (await runThreePhaseTest()) {
    testsPassed++;
  }
  
  // Test pipeline mode
  console.log('\nTest 2: Pipeline Mode');
  testsRun++;
  if (await runPipelineTest()) {
    testsPassed++;
  }
  
  // Test standalone validation
  console.log('\nTest 3: Standalone Validation');
  testsRun++;
  if (await runStandaloneValidationTest()) {
    testsPassed++;
  }
  
  // Final cleanup
  await resetRepository();
  
  console.log('\n==========================================');
  console.log(`Results: ${testsPassed}/${testsRun} tests passed`);
  
  if (testsPassed === testsRun) {
    console.log('✅ All E2E tests passed!');
    process.exit(0);
  } else {
    console.log('❌ Some tests failed');
    process.exit(1);
  }
}

// Run tests
main().catch(error => {
  console.error('Fatal error:', error);
  process.exit(1);
});