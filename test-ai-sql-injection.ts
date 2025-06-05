#!/usr/bin/env bun
// Test AI response for SQL injection fix
import { getAiClient } from './src/ai/client.js';
import { RSOLVCredentialManager } from './src/credentials/manager.js';
import { buildSolutionPrompt } from './src/ai/prompts.js';

async function testAI() {
  console.log('Testing AI response for SQL injection fix...\n');
  
  const credManager = new RSOLVCredentialManager();
  await credManager.initialize('rsolv_prod_demo_key');
  
  const aiClient = await getAiClient({
    provider: 'anthropic',
    model: 'claude-3-5-sonnet-20241022',
    temperature: 0.2,
    maxTokens: 4000,
    useVendedCredentials: true
  }, credManager);
  
  const issue = {
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

  const analysisData = {
    issueType: 'security_vulnerability' as const,
    filesToModify: ['src/auth/login.js'],
    estimatedComplexity: 'medium' as const,
    requiredContext: ['authentication', 'SQL queries', 'security best practices'],
    suggestedApproach: 'Replace string concatenation with parameterized queries',
    canBeFixed: true
  };

  const fileContents = {
    'src/auth/login.js': `const mysql = require('mysql');
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

module.exports = { authenticateUser, getUserOrders };`
  };

  // Build prompt
  const prompt = buildSolutionPrompt(issue, analysisData, fileContents);
  
  console.log('Prompt length:', prompt.length);
  console.log('\n=== FULL PROMPT ===\n');
  console.log(prompt);
  console.log('\n=== END PROMPT ===\n');
  
  try {
    const response = await aiClient.complete(prompt, {
      temperature: 0.2,
      maxTokens: 4000
    });
    
    console.log('\n=== AI RESPONSE ===\n');
    console.log(response);
    console.log('\n=== END RESPONSE ===\n');
    
  } catch (error) {
    console.error('Error:', error);
  }
}

testAI().catch(console.error);