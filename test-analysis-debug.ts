#!/usr/bin/env bun
// Debug analysis step
import { SecurityAwareAnalyzer } from './src/ai/security-analyzer.js';
import { loadConfig } from './src/config/index.js';

async function testAnalysis() {
  const config = await loadConfig();
  
  const issueContext = {
    id: '3119450136',
    number: 8,
    title: 'Critical: Security audit needed for authentication system',
    body: `Our security team has flagged potential vulnerabilities in our authentication system. 
We need to review and fix any SQL injection vulnerabilities in the login flow.

This is critical as we process over $10M in daily transactions and any breach 
could result in significant financial and reputational damage.

Priority: CRITICAL`,
    labels: ['security', 'high-priority', 'rsolv:automate'],
    assignees: [],
    repository: {
      owner: 'RSOLV-dev',
      name: 'demo-ecommerce-security',
      fullName: 'RSOLV-dev/demo-ecommerce-security',
      defaultBranch: 'main',
      language: 'JavaScript'
    },
    source: 'github' as const,
    url: 'https://github.com/RSOLV-dev/demo-ecommerce-security/issues/8',
    createdAt: '2025-06-05T02:53:21Z',
    updatedAt: '2025-06-05T02:53:21Z'
  };

  const vulnerableCode = `const mysql = require('mysql');
const connection = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: 'password',
  database: 'ecommerce'
});

// VULNERABLE: Direct string concatenation allows SQL injection
function authenticateUser(username, password) {
  const query = \`SELECT * FROM users WHERE username = '\${username}' AND password = '\${password}'\`;
  
  return new Promise((resolve, reject) => {
    connection.query(query, (error, results) => {
      if (error) reject(error);
      resolve(results.length > 0 ? results[0] : null);
    });
  });
}

// Additional vulnerable endpoint
function getUserOrders(userId) {
  // VULNERABLE: No input validation
  const query = \`SELECT * FROM orders WHERE user_id = \${userId}\`;
  
  return new Promise((resolve, reject) => {
    connection.query(query, (error, results) => {
      if (error) reject(error);
      resolve(results);
    });
  });
}

module.exports = { authenticateUser, getUserOrders };`;

  const codebaseFiles = new Map([['src/auth/login.js', vulnerableCode]]);
  
  console.log('Testing security-aware analysis...\n');
  
  const analyzer = new SecurityAwareAnalyzer();
  const analysis = await analyzer.analyzeWithSecurity(
    issueContext,
    config,
    codebaseFiles
  );
  
  console.log('Analysis result:');
  console.log('- Issue type:', analysis.issueType);
  console.log('- Files to modify:', analysis.filesToModify);
  console.log('- Suggested approach:', analysis.suggestedApproach);
  console.log('- Security analysis:', analysis.securityAnalysis?.summary);
  console.log('- Vulnerabilities found:', analysis.securityAnalysis?.vulnerabilities.length || 0);
}

testAnalysis().catch(console.error);