import { describe, it, expect, mock } from 'vitest';
import { SecurityAwareAnalyzer } from '../security-analyzer.js';
import { IssueContext, ActionConfig } from '../../types/index.js';

// Mock the AI client using require.resolve to avoid mock pollution
const clientPath = require.resolve('../client');
vi.mock(clientPath, () => ({
  getAiClient: () => ({
    complete: async (prompt: string) => {
      // Return different responses based on prompt content
      if (prompt.includes('crash') || prompt.includes('null pointer')) {
        return `This is a bug in the application that causes crashes.

Files to modify:
- src/app.js
- src/utils.js

This is a simple null pointer exception that needs to be fixed.

Suggested Approach:
Add proper null checks before accessing object properties.`;
      }
      
      // Default to security response
      return `This is a security vulnerability in the authentication system.

Files to modify:
- src/database.js
- src/auth.js

This is a high-severity SQL injection vulnerability that needs immediate attention.

Suggested Approach:
Use parameterized queries to prevent SQL injection attacks.`;
    }
  })
}));

describe('SecurityAwareAnalyzer', () => {
  const analyzer = new SecurityAwareAnalyzer();

  const mockIssue: IssueContext = {
    id: 'issue-123',
    number: 123,
    title: 'Fix SQL injection vulnerability',
    body: 'The user input is not properly sanitized before database queries',
    labels: ['security', 'bug'],
    assignees: ['test-user'],
    repository: {
      owner: 'test',
      name: 'repo',
      fullName: 'test/repo',
      defaultBranch: 'main',
      language: 'JavaScript'
    },
    source: 'github',
    createdAt: '2023-01-01T00:00:00Z',
    updatedAt: '2023-01-01T00:00:00Z'
  };

  const mockConfig: ActionConfig = {
    repoToken: 'fake-token',
    apiKey: 'fake-api-key',
    configPath: '.github/rsolv.yml',
    issueLabel: 'rsolv',
    aiProvider: {
      provider: 'anthropic',
      apiKey: 'fake-key',
      model: 'claude-3-sonnet',
      temperature: 0.2,
      maxTokens: 2000
    },
    containerConfig: {
      enabled: false
    },
    securitySettings: {
      disableNetworkAccess: true
    }
  };

  describe('Security Analysis', () => {
    it('should detect SQL injection vulnerabilities in code', async () => {
      const codebaseFiles = new Map<string, string>([
        ['src/database.js', `
          const query = "SELECT * FROM users WHERE id = " + userId;
          db.query(query);
        `],
        ['src/safe-database.js', `
          const query = "SELECT * FROM users WHERE id = ?";
          db.query(query, [userId]);
        `]
      ]);

      const result = await analyzer.analyzeWithSecurity(mockIssue, mockConfig, codebaseFiles);

      expect(result.securityAnalysis).toBeDefined();
      expect(result.securityAnalysis!.hasSecurityIssues).toBe(true);
      expect(result.securityAnalysis!.vulnerabilities).toHaveLength(1);
      expect(result.securityAnalysis!.vulnerabilities[0].type).toBe('sql_injection');
      expect(result.securityAnalysis!.affectedFiles).toContain('src/database.js');
      expect(result.securityAnalysis!.affectedFiles).not.toContain('src/safe-database.js');
    });

    it('should detect XSS vulnerabilities in code', async () => {
      const codebaseFiles = new Map<string, string>([
        ['src/frontend.js', `
          element.innerHTML = userInput;
          document.write(userContent);
        `]
      ]);

      const result = await analyzer.analyzeWithSecurity(mockIssue, mockConfig, codebaseFiles);

      expect(result.securityAnalysis).toBeDefined();
      expect(result.securityAnalysis!.hasSecurityIssues).toBe(true);
      expect(result.securityAnalysis!.vulnerabilities).toHaveLength(2);
      expect(result.securityAnalysis!.vulnerabilities.some(v => v.type === 'xss')).toBe(true);
    });

    it('should calculate appropriate risk levels', async () => {
      const highRiskCode = new Map<string, string>([
        ['src/app.js', `
          const query = "SELECT * FROM users WHERE id = " + userId;
          element.innerHTML = userInput;
          document.write(userContent);
        `]
      ]);

      const result = await analyzer.analyzeWithSecurity(mockIssue, mockConfig, highRiskCode);

      expect(result.securityAnalysis!.riskLevel).toBe('critical'); // 3 high-severity vulns = critical
      expect(result.securityAnalysis!.recommendations).toContain('Implement parameterized queries throughout the codebase');
      expect(result.securityAnalysis!.recommendations).toContain('Use secure DOM manipulation methods (textContent, not innerHTML)');
    });

    it('should adjust complexity based on security risk', async () => {
      const criticalRiskCode = new Map<string, string>([
        ['src/app1.js', 'const query = "SELECT * FROM users WHERE id = " + userId;'],
        ['src/app2.js', 'const query = "SELECT * FROM posts WHERE id = " + postId;'],
        ['src/app3.js', 'const query = "SELECT * FROM comments WHERE id = " + commentId;']
      ]);

      const result = await analyzer.analyzeWithSecurity(mockIssue, mockConfig, criticalRiskCode);

      expect(result.estimatedComplexity).toBe('complex');
      expect(result.issueType).toBe('security');
    });

    it('should handle files with no vulnerabilities', async () => {
      const safeCode = new Map<string, string>([
        ['src/safe.js', `
          const query = "SELECT * FROM users WHERE id = ?";
          db.query(query, [userId]);
          element.textContent = userInput;
        `]
      ]);

      const result = await analyzer.analyzeWithSecurity(mockIssue, mockConfig, safeCode);

      expect(result.securityAnalysis!.hasSecurityIssues).toBe(false);
      expect(result.securityAnalysis!.vulnerabilities).toHaveLength(0);
      expect(result.securityAnalysis!.riskLevel).toBe('low');
    });

    it('should handle mixed languages', async () => {
      const mixedCode = new Map<string, string>([
        ['src/app.js', 'const query = "SELECT * FROM users WHERE id = " + userId;'],
        ['src/app.ts', 'const query: string = "SELECT * FROM posts WHERE id = " + postId;'],
        ['config.json', '{"database": "test"}'], // Should be ignored
        ['README.md', '# Project'] // Should be ignored
      ]);

      const result = await analyzer.analyzeWithSecurity(mockIssue, mockConfig, mixedCode);

      expect(result.securityAnalysis!.hasSecurityIssues).toBe(true);
      expect(result.securityAnalysis!.vulnerabilities).toHaveLength(2);
      expect(result.securityAnalysis!.affectedFiles).toHaveLength(2);
    });
  });

  describe('Issue Type Detection', () => {
    it('should detect security issues from title and body', async () => {
      const securityIssue: IssueContext = {
        ...mockIssue,
        title: 'XSS vulnerability in user input',
        body: 'Cross-site scripting attack possible'
      };

      const result = await analyzer.analyzeWithSecurity(securityIssue, mockConfig);

      expect(result.issueType).toBe('security');
    });

    it('should detect bug issues', async () => {
      const bugIssue: IssueContext = {
        id: 'issue-456',
        number: 456,
        title: 'Fix crash when loading page',
        body: 'Application crashes with null pointer exception',
        labels: ['bug'],
        assignees: ['test-user'],
        repository: {
          owner: 'test',
          name: 'repo',
          fullName: 'test/repo',
          defaultBranch: 'main',
          language: 'JavaScript'
        },
        source: 'github',
        createdAt: '2023-01-01T00:00:00Z',
        updatedAt: '2023-01-01T00:00:00Z'
      };

      const result = await analyzer.analyzeWithSecurity(bugIssue, mockConfig);

      expect(result.issueType).toBe('bug');
    });
  });
});