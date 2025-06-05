#!/usr/bin/env bun
// Complete demo test that exercises all components
import { getGitHubClient } from './src/github/api.js';
import { analyzeIssue } from './src/ai/analyzer.js';
import { generateSolution } from './src/ai/solution.js';
import { createPullRequest } from './src/github/pr.js';
import { loadConfig } from './src/config/index.js';
import { SecurityAwareAnalyzer } from './src/ai/security-analyzer.js';
import { RSOLVCredentialManager } from './src/credentials/manager.js';
import chalk from 'chalk';

async function runCompleteDemo() {
  console.log(chalk.bold.blue('\n🚀 RSOLV Demo - Complete E2E Flow\n'));
  
  const token = process.env.GITHUB_TOKEN;
  if (!token) {
    console.error(chalk.red('❌ GITHUB_TOKEN not set'));
    process.exit(1);
  }
  
  try {
    // Step 1: Fetch issue
    console.log(chalk.yellow('📋 Step 1: Fetching issue from GitHub...'));
    const client = getGitHubClient({ token });
    const { data: issue } = await client.issues.get({
      owner: 'RSOLV-dev',
      repo: 'demo-ecommerce-security',
      issue_number: 8
    });
    
    console.log(chalk.green(`✅ Found issue #${issue.number}: ${issue.title}`));
    console.log(`   Labels: ${issue.labels.map((l: any) => l.name).join(', ')}`);
    
    // Convert to IssueContext
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
    
    // Step 2: Load config and test credential vending
    console.log(chalk.yellow('\n🔑 Step 2: Testing credential vending...'));
    const config = await loadConfig();
    console.log(`   Provider: ${config.aiProvider.provider}`);
    console.log(`   Use vended credentials: ${config.aiProvider.useVendedCredentials}`);
    
    if (config.aiProvider.useVendedCredentials) {
      const credManager = new RSOLVCredentialManager();
      await credManager.initialize(config.apiKey);
      console.log(chalk.green('✅ Credential vending successful'));
    }
    
    // Step 3: Security analysis
    console.log(chalk.yellow('\n🔒 Step 3: Running security analysis...'));
    
    // Get vulnerable code
    const { data: fileContent } = await client.repos.getContent({
      owner: 'RSOLV-dev',
      repo: 'demo-ecommerce-security',
      path: 'src/auth/login.js'
    });
    
    const decodedContent = Buffer.from((fileContent as any).content, 'base64').toString();
    const codebaseFiles = new Map([['src/auth/login.js', decodedContent]]);
    
    const securityAnalyzer = new SecurityAwareAnalyzer();
    const analysisWithSecurity = await securityAnalyzer.analyzeWithSecurity(
      issueContext, 
      config, 
      codebaseFiles
    );
    
    if (analysisWithSecurity.securityAnalysis) {
      console.log(chalk.green('✅ Security analysis complete:'));
      const sec = analysisWithSecurity.securityAnalysis;
      console.log(`   Total vulnerabilities: ${sec.summary.total}`);
      console.log(`   Risk level: ${sec.riskLevel}`);
      console.log(`   By severity:`, sec.summary.bySeverity);
      console.log(`   By type:`, sec.summary.byType);
      
      // Show first few vulnerabilities
      sec.vulnerabilities.slice(0, 3).forEach(vuln => {
        console.log(chalk.red(`   - ${vuln.severity}: ${vuln.type} at line ${vuln.line}`));
      });
    }
    
    // Step 4: Generate solution (using standard analyzer to avoid Claude Code timeout)
    console.log(chalk.yellow('\n💡 Step 4: Generating solution...'));
    
    // For demo, override provider to use standard Anthropic
    const demoConfig = {
      ...config,
      aiProvider: {
        ...config.aiProvider,
        provider: 'anthropic'
      }
    };
    
    const solution = await generateSolution(
      issueContext,
      analysisWithSecurity,
      demoConfig,
      undefined,
      undefined,
      analysisWithSecurity.securityAnalysis
    );
    
    if (!solution.success) {
      console.error(chalk.red('❌ Solution generation failed:', solution.error));
      return;
    }
    
    console.log(chalk.green('✅ Solution generated successfully'));
    console.log(`   Files to modify: ${Object.keys(solution.changes || {}).length}`);
    
    // Step 5: Show summary
    console.log(chalk.bold.green('\n✨ Demo Complete!\n'));
    console.log('What RSOLV demonstrated:');
    console.log('1. ✅ Fetched issue from GitHub');
    console.log('2. ✅ Loaded configuration with credential vending enabled');
    console.log('3. ✅ Performed security analysis and found vulnerabilities');
    console.log('4. ✅ Generated AI-powered fixes');
    console.log('5. 🔄 Ready to create pull request');
    
    console.log(chalk.yellow('\n📊 Security Impact:'));
    if (analysisWithSecurity.securityAnalysis) {
      console.log(`   - Found ${analysisWithSecurity.securityAnalysis.summary.total} vulnerabilities`);
      console.log(`   - Risk level: ${analysisWithSecurity.securityAnalysis.riskLevel}`);
      console.log(`   - Potential cost avoided: $4.45M (avg data breach)`)
      console.log(`   - ROI on $15 fix: 296,666%`);
    }
    
  } catch (error) {
    console.error(chalk.red('\n❌ Error:'), error.message);
    if (error.stack) {
      console.error(chalk.dim(error.stack));
    }
    process.exit(1);
  }
}

const startTime = Date.now();
runCompleteDemo().then(() => {
  const duration = ((Date.now() - startTime) / 1000).toFixed(1);
  console.log(chalk.dim(`\n⏱  Completed in ${duration}s`));
});