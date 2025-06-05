#!/usr/bin/env bun
import { getGitHubClient } from './src/github/api.js';
import { analyzeIssue } from './src/ai/analyzer.js';
import { generateSolution } from './src/ai/solution.js';
import { createPullRequest } from './src/github/pr.js';
import { SecurityAwareAnalyzer } from './src/ai/security-analyzer.js';
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
    
    // Step 2: Create config without needing vended credentials
    console.log(chalk.yellow('\n🔍 Step 2: Analyzing issue...'));
    const config = {
      configPath: '.github/rsolv.yml',
      issueLabel: 'rsolv:automate',
      rsolvApiKey: 'test-key',
      aiProvider: {
        provider: 'anthropic' as const,
        model: 'claude-3-sonnet-20240229',
        apiKey: process.env.ANTHROPIC_API_KEY,
        temperature: 0.2,
        maxTokens: 4000,
        contextLimit: 100000,
        timeout: 60000,
        useVendedCredentials: false
      },
      enableSecurityAnalysis: true,
      containerConfig: {
        enabled: false,
        image: 'rsolv/code-analysis:latest',
        memoryLimit: '2g',
        cpuLimit: '1',
        timeout: 300,
        securityProfile: 'default'
      }
    };
    
    // Create a mock AI client for the analyzer
    const mockAiClient = {
      complete: async (prompt: string) => {
        console.log(chalk.dim('   Using mock AI response for analysis...'));
        return `Based on my analysis, this is a critical security issue in the authentication system.

The main issue is SQL injection vulnerability in the authentication code that could allow attackers to bypass login and access sensitive data.

Files to modify:
- \`src/auth/login.js\`

Suggested Approach:
The authentication functions are using direct string concatenation for SQL queries, which allows SQL injection attacks. We need to update these functions to use parameterized queries instead of string concatenation. This will prevent malicious SQL code from being executed.`;
      }
    };
    
    const analysis = await analyzeIssue(issueContext, config, mockAiClient);
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
    
    // Create a mock solution for demo
    const mockSolution = {
      complete: async () => {
        console.log(chalk.dim('   Using mock AI response for solution...'));
        return JSON.stringify({
          success: true,
          changes: {
            'src/auth/login.js': `const mysql = require('mysql');
const connection = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: 'password',
  database: 'ecommerce'
});

// FIXED: Use parameterized queries to prevent SQL injection
function authenticateUser(username, password) {
  const query = 'SELECT * FROM users WHERE username = ? AND password = ?';
  
  return new Promise((resolve, reject) => {
    connection.query(query, [username, password], (error, results) => {
      if (error) {
        reject(error);
        return;
      }
      resolve(results.length > 0 ? results[0] : null);
    });
  });
}

// FIXED: Added input validation and parameterized query
function getUserOrders(userId) {
  // Validate input
  if (!userId || isNaN(parseInt(userId))) {
    throw new Error('Invalid user ID provided');
  }
  
  const query = 'SELECT * FROM orders WHERE user_id = ?';
  
  return new Promise((resolve, reject) => {
    connection.query(query, [parseInt(userId)], (error, results) => {
      if (error) {
        reject(error);
        return;
      }
      resolve(results);
    });
  });
}

module.exports = { authenticateUser, getUserOrders };`
          }
        });
      }
    };
    
    const solution = await generateSolution(
      issueContext, 
      securityResult,
      config,
      mockSolution,
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