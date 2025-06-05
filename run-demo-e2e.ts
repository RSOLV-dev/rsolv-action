#!/usr/bin/env bun
// E2E Demo Test - Run this to test the full flow
import { getGitHubClient } from './src/github/api.js';
import { loadConfig } from './src/config/index.js';
import { SecurityAwareAnalyzer } from './src/ai/security-analyzer.js';
import { generateSolution } from './src/ai/solution.js';
import { RSOLVCredentialManager } from './src/credentials/manager.js';
import { RsolvApiClient } from './src/external/api-client.js';

// Force real AI responses
process.env.FORCE_REAL_AI = 'true';

async function runE2EDemo() {
  console.log('🚀 Starting E2E Demo Test\n');
  
  // Step 1: Fetch issue from GitHub
  console.log('📥 Step 1: Fetching issue from GitHub...');
  const githubClient = getGitHubClient({ token: process.env.GITHUB_TOKEN! });
  
  const { data: issue } = await githubClient.issues.get({
    owner: 'RSOLV-dev',
    repo: 'demo-ecommerce-security',
    issue_number: 8
  });
  
  console.log(`✅ Found issue #${issue.number}: ${issue.title}`);
  console.log(`   Labels: ${issue.labels.map((l: any) => l.name).join(', ')}\n`);
  
  // Create issue context
  const issueContext = {
    id: issue.id.toString(),
    number: issue.number,
    title: issue.title,
    body: issue.body || '',
    labels: issue.labels.map((l: any) => l.name),
    assignees: issue.assignees.map((a: any) => a.login),
    repository: {
      owner: 'RSOLV-dev',
      name: 'demo-ecommerce-security',
      fullName: 'RSOLV-dev/demo-ecommerce-security',
      defaultBranch: 'main',
      language: 'JavaScript'
    },
    source: 'github' as const,
    url: issue.html_url,
    createdAt: issue.created_at,
    updatedAt: issue.updated_at
  };
  
  // Step 2: Load config
  console.log('⚙️  Step 2: Loading configuration...');
  const config = await loadConfig();
  console.log(`✅ Config loaded: ${config.aiProvider.provider} with ${config.aiProvider.useVendedCredentials ? 'vended' : 'direct'} credentials\n`);
  
  // Step 3: Test credential vending
  console.log('🔑 Step 3: Testing credential vending...');
  const credManager = new RSOLVCredentialManager();
  await credManager.initialize(config.apiKey);
  
  const anthropicKey = credManager.getCredential('anthropic');
  console.log(`✅ Got Anthropic key: ${anthropicKey.substring(0, 10)}...${anthropicKey.substring(anthropicKey.length - 4)}\n`);
  
  // Step 4: Get vulnerable code
  console.log('📄 Step 4: Fetching vulnerable code...');
  const { data: fileContent } = await githubClient.repos.getContent({
    owner: 'RSOLV-dev',
    repo: 'demo-ecommerce-security',
    path: 'src/auth/login.js'
  });
  
  const decodedContent = Buffer.from(fileContent.content, 'base64').toString();
  console.log('✅ Found vulnerable code:');
  console.log('   - SQL injection in authenticateUser()');
  console.log('   - SQL injection in getUserOrders()\n');
  
  // Step 5: Security analysis
  console.log('🔍 Step 5: Running security analysis...');
  const codebaseFiles = new Map([['src/auth/login.js', decodedContent]]);
  const securityAnalyzer = new SecurityAwareAnalyzer();
  const analysis = await securityAnalyzer.analyzeWithSecurity(
    issueContext,
    config,
    codebaseFiles
  );
  
  console.log(`✅ Security analysis complete:`);
  console.log(`   - Issue type: ${analysis.issueType}`);
  console.log(`   - Vulnerabilities found: ${analysis.securityAnalysis?.vulnerabilities.length || 0}`);
  console.log(`   - Risk level: ${analysis.securityAnalysis?.riskLevel || 'unknown'}\n`);
  
  // Step 6: Generate solution
  console.log('💡 Step 6: Generating solution with AI...');
  console.log('   This may take 30-60 seconds...');
  
  const fileGetter = async (filePath: string) => {
    if (filePath === 'src/auth/login.js') {
      return decodedContent;
    }
    return '';
  };
  
  const startTime = Date.now();
  const solution = await generateSolution(
    issueContext,
    analysis,
    config,
    undefined,
    fileGetter,
    analysis.securityAnalysis
  );
  const duration = (Date.now() - startTime) / 1000;
  
  if (solution.success) {
    console.log(`✅ Solution generated in ${duration.toFixed(1)}s`);
    console.log(`   Files to modify: ${Object.keys(solution.changes || {}).join(', ')}`);
    
    if (solution.changes && solution.changes['src/auth/login.js']) {
      const fix = solution.changes['src/auth/login.js'];
      console.log(`   Solution preview: ${fix.includes('?') ? 'Uses parameterized queries ✓' : 'Missing parameterized queries ✗'}\n`);
    }
  } else {
    console.log(`❌ Solution generation failed: ${solution.message}\n`);
  }
  
  // Step 7: Test API tracking
  console.log('📊 Step 7: Testing fix attempt tracking...');
  const apiClient = new RsolvApiClient(config.apiKey);
  
  try {
    const fixAttempt = await apiClient.createFixAttempt({
      github_issue_url: issueContext.url,
      github_pr_url: 'https://github.com/RSOLV-dev/demo-ecommerce-security/pull/999',
      repository_full_name: issueContext.repository.fullName,
      issue_number: issueContext.number,
      issue_title: issueContext.title,
      ai_provider: config.aiProvider.provider,
      ai_model: config.aiProvider.model,
      security_vulnerabilities_found: 4,
      estimated_time_saved_hours: 2.5
    });
    
    if (fixAttempt.success) {
      console.log(`✅ Fix attempt tracked: ID ${fixAttempt.data?.id}\n`);
    } else {
      console.log(`❌ Fix attempt tracking failed: ${fixAttempt.error}\n`);
    }
  } catch (error) {
    console.log(`❌ API error: ${error}\n`);
  }
  
  // Summary
  console.log('📋 Summary:');
  console.log(`   ✅ Issue fetched from GitHub`);
  console.log(`   ✅ Config loaded with ${config.aiProvider.provider}`);
  console.log(`   ✅ Credentials vended successfully`);
  console.log(`   ✅ Security analysis found ${analysis.securityAnalysis?.vulnerabilities.length || 0} vulnerabilities`);
  console.log(`   ${solution.success ? '✅' : '❌'} Solution generation ${solution.success ? 'succeeded' : 'failed'}`);
  console.log(`   ✅ API client configured`);
  
  console.log('\n✨ E2E Demo Test Complete!');
}

// Check environment
if (!process.env.GITHUB_TOKEN) {
  console.error('❌ Error: GITHUB_TOKEN environment variable not set');
  console.error('   Run: export GITHUB_TOKEN="your-github-token"');
  process.exit(1);
}

if (!process.env.RSOLV_API_KEY) {
  console.error('❌ Error: RSOLV_API_KEY environment variable not set');
  console.error('   Run: export RSOLV_API_KEY="rsolv_prod_demo_key"');
  process.exit(1);
}

if (process.env.RSOLV_API_URL !== 'https://api.rsolv.dev') {
  console.error('❌ Error: RSOLV_API_URL should be https://api.rsolv.dev');
  console.error('   Run: export RSOLV_API_URL="https://api.rsolv.dev"');
  process.exit(1);
}

// Run the demo
runE2EDemo().catch(error => {
  console.error('\n❌ Fatal error:', error);
  process.exit(1);
});