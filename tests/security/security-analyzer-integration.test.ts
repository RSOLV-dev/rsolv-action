import { describe, test, expect } from 'bun:test';
import { SecurityAwareAnalyzer } from '../../src/ai/security-analyzer.js';
import { IssueContext, ActionConfig } from '../../src/types/index.js';

describe('SecurityAwareAnalyzer Integration', () => {
  const analyzer = new SecurityAwareAnalyzer();
  
  const mockIssue: IssueContext = {
    id: '123',
    number: 8,
    title: 'Security audit needed',
    body: 'SQL injection vulnerabilities detected',
    labels: ['security', 'bug'],
    assignees: [],
    repository: {
      owner: 'test',
      name: 'repo',
      fullName: 'test/repo',
      defaultBranch: 'main',
      language: 'JavaScript'
    },
    source: 'github',
    url: 'https://github.com/test/repo/issues/8',
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString()
  };
  
  const mockConfig: ActionConfig = {
    apiKey: 'test-key',
    configPath: '.github/rsolv.yml',
    issueLabel: 'rsolv:automate',
    enableSecurityAnalysis: true,
    aiProvider: {
      provider: 'anthropic',
      apiKey: 'test-key',
      model: 'claude-3-sonnet',
      temperature: 0.2,
      maxTokens: 4000
    },
    containerConfig: {
      enabled: false
    },
    securitySettings: {}
  };
  
  const vulnerableCode = `
const mysql = require('mysql');
const connection = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: 'password',
  database: 'ecommerce'
});

function authenticateUser(username, password) {
  const query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'";
  
  return new Promise((resolve, reject) => {
    connection.query(query, (error, results) => {
      if (error) {
        reject(error);
        return;
      }
      resolve(results.length > 0 ? results[0] : null);
    });
  });
}

function getUserOrders(userId) {
  const query = "SELECT * FROM orders WHERE user_id = " + userId;
  
  return new Promise((resolve, reject) => {
    connection.query(query, (error, results) => {
      if (error) {
        reject(error);
        return;
      }
      resolve(results);
    });
  });
}

module.exports = { authenticateUser, getUserOrders };
`;

  test('should return analysis with security vulnerabilities', async () => {
    const codebaseFiles = new Map([['src/auth/login.js', vulnerableCode]]);
    
    const result = await analyzer.analyzeWithSecurity(mockIssue, mockConfig, codebaseFiles);
    
    // Check standard analysis fields
    expect(result.issueType).toBe('security');
    expect(result.filesToModify).toBeArray();
    expect(result.estimatedComplexity).toBeOneOf(['simple', 'medium', 'complex']);
    expect(result.suggestedApproach).toBeString();
    
    // Check security analysis
    expect(result.securityAnalysis).toBeDefined();
    expect(result.securityAnalysis!.hasSecurityIssues).toBe(true);
    expect(result.securityAnalysis!.vulnerabilities).toBeArray();
    expect(result.securityAnalysis!.vulnerabilities.length).toBeGreaterThan(0);
    
    // Check vulnerability structure
    const firstVuln = result.securityAnalysis!.vulnerabilities[0];
    expect(firstVuln).toHaveProperty('type');
    expect(firstVuln).toHaveProperty('severity');
    expect(firstVuln).toHaveProperty('line');
    expect(firstVuln).toHaveProperty('file', 'src/auth/login.js');
    expect(firstVuln).toHaveProperty('message');
    expect(firstVuln).toHaveProperty('description');
    
    // Check summary
    expect(result.securityAnalysis!.summary).toBeDefined();
    expect(result.securityAnalysis!.summary.total).toBe(result.securityAnalysis!.vulnerabilities.length);
    expect(result.securityAnalysis!.summary.byType).toBeDefined();
    expect(result.securityAnalysis!.summary.bySeverity).toBeDefined();
    
    // Check specific vulnerabilities we expect
    const sqlInjectionVulns = result.securityAnalysis!.vulnerabilities.filter(
      v => v.type === 'sql_injection'
    );
    expect(sqlInjectionVulns.length).toBeGreaterThanOrEqual(2);
  });
  
  test('should handle case with no security issues', async () => {
    const safeCode = `
function greetUser(name) {
  return \`Hello, \${name}!\`;
}

module.exports = { greetUser };
`;
    
    const codebaseFiles = new Map([['src/utils/greeting.js', safeCode]]);
    
    const result = await analyzer.analyzeWithSecurity(mockIssue, mockConfig, codebaseFiles);
    
    expect(result.securityAnalysis).toBeDefined();
    expect(result.securityAnalysis!.hasSecurityIssues).toBe(false);
    expect(result.securityAnalysis!.vulnerabilities).toEqual([]);
    expect(result.securityAnalysis!.summary.total).toBe(0);
  });
  
  test('should work without codebase files', async () => {
    const result = await analyzer.analyzeWithSecurity(mockIssue, mockConfig);
    
    expect(result.issueType).toBeString();
    expect(result.securityAnalysis).toBeUndefined();
  });
});