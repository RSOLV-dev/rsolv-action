#!/usr/bin/env bun
import { getGitHubClient } from './src/github/api.js';
import { analyzeIssue } from './src/ai/analyzer.js';
import { generateSolution } from './src/ai/solution.js';
import { createPullRequest } from './src/github/pr.js';
import { SecurityAwareAnalyzer } from './src/ai/security-analyzer.js';
import { loadConfig } from './src/config/index.js';
import chalk from 'chalk';

async function runFullDemo() {
  console.log(chalk.bold.blue('\n🚀 RSOLV Demo - Full Non-Interactive Flow\n'));
  
  const token = process.env.GITHUB_TOKEN;
  if (!token) {
    console.error(chalk.red('❌ GITHUB_TOKEN not set'));
    process.exit(1);
  }
  
  try {
    // Step 1: Fetch the issue
    console.log(chalk.yellow('📋 Step 1: Fetching issue...'));
    const client = getGitHubClient({ token });
    const { data: issue } = await client.issues.get({
      owner: 'RSOLV-dev',
      repo: 'demo-ecommerce-security',
      issue_number: 8
    });
    
    console.log(chalk.green(`✅ Found issue #${issue.number}: ${issue.title}`));
    console.log(`   Labels: ${issue.labels.map((l: any) => l.name).join(', ')}`);
    
    // Convert to IssueContext format
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
    
    // Step 2: Analyze the issue
    console.log(chalk.yellow('\n🔍 Step 2: Analyzing issue...'));
    const config = await loadConfig();
    config.enableSecurityAnalysis = true;
    
    const analysis = await analyzeIssue(issueContext, config);
    console.log(chalk.green('✅ Analysis complete:'));
    console.log(`   Issue Type: ${analysis.issueType}`);
    console.log(`   Complexity: ${analysis.estimatedComplexity}`);
    console.log(`   Files to modify: ${analysis.filesToModify.join(', ')}`);
    console.log(`   Can be fixed: ${analysis.canBeFixed}`);
    
    // Step 3: Security Analysis
    console.log(chalk.yellow('\n🔒 Step 3: Running security analysis...'));
    const securityAnalyzer = new SecurityAwareAnalyzer();
    
    // Fetch the vulnerable file
    const { data: fileContent } = await client.repos.getContent({
      owner: 'RSOLV-dev',
      repo: 'demo-ecommerce-security',
      path: 'src/auth/login.js'
    });
    
    const decodedContent = Buffer.from((fileContent as any).content, 'base64').toString();
    const codebaseFiles = new Map([['src/auth/login.js', decodedContent]]);
    
    const securityResult = await securityAnalyzer.analyzeWithSecurity(issueContext, config, codebaseFiles);
    
    if (securityResult.securityAnalysis) {
      console.log(chalk.green('✅ Security vulnerabilities found:'));
      securityResult.securityAnalysis.vulnerabilities.forEach(vuln => {
        console.log(chalk.red(`   - ${vuln.severity} Severity: ${vuln.type} in ${vuln.file}:${vuln.line}`));
        console.log(`     Risk: ${vuln.risk}`);
      });
      console.log(chalk.green(`   Total: ${securityResult.securityAnalysis.summary.total} vulnerabilities`));
    }
    
    // Step 4: Generate solution
    console.log(chalk.yellow('\n💡 Step 4: Generating solution...'));
    const solution = await generateSolution(
      issueContext, 
      securityResult,
      config,
      undefined,
      undefined,
      securityResult.securityAnalysis
    );
    
    if (!solution.success) {
      console.error(chalk.red('❌ Solution generation failed:', solution.error));
      process.exit(1);
    }
    
    console.log(chalk.green('✅ Solution generated successfully'));
    console.log(`   Files modified: ${Object.keys(solution.changes || {}).length}`);
    
    // Step 5: Create pull request
    console.log(chalk.yellow('\n🚀 Step 5: Creating pull request...'));
    
    const prResult = await createPullRequest(
      issueContext,
      solution.changes || {},
      securityResult,
      config,
      securityResult.securityAnalysis,
      solution.explanations
    );
    
    console.log(chalk.green(`✅ Pull request created: ${prResult.url}`));
    console.log(`   PR #${prResult.number}: ${prResult.title}`);
    
    // Summary
    console.log(chalk.bold.green('\n✨ Demo Complete!'));
    console.log(chalk.cyan('Summary:'));
    console.log(`- Analyzed critical security issue in authentication system`);
    console.log(`- Found ${securityResult.securityAnalysis?.vulnerabilities.length || 0} SQL injection vulnerabilities`);
    console.log(`- Generated fixes using parameterized queries`);
    console.log(`- Created PR with comprehensive documentation`);
    console.log(`- Time taken: ~${Math.round((Date.now() - startTime) / 1000)} seconds`);
    console.log(chalk.cyan(`\nView the PR at: ${prResult.url}`));
    
  } catch (error) {
    console.error(chalk.red('\n❌ Error during demo:'), error);
    console.error(chalk.red('Stack trace:'), error.stack);
    process.exit(1);
  }
}

const startTime = Date.now();
runFullDemo();