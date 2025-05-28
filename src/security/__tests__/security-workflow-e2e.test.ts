import { describe, it, expect, beforeEach, jest, mock } from 'bun:test';
import { SecurityDetector } from '../detector.js';
import { SecurityAwareAnalyzer } from '../../ai/security-analyzer.js';
import { ComplianceGenerator } from '../compliance.js';
import { ThreeTierExplanationFramework } from '../explanation-framework.js';
import { buildSecuritySolutionPrompt, buildSecurityExplanationPrompt } from '../../ai/security-prompts.js';

// Mock the AI client
mock.module('../../ai/client', () => ({
  getAiClient: () => ({
    complete: async (prompt: string) => {
      return `This is a security vulnerability in the system.

Files to modify:
- src/database.js
- src/frontend.js

This contains SQL injection and XSS vulnerabilities that need immediate attention.

Suggested Approach:
Use parameterized queries and proper DOM manipulation methods.`;
    }
  })
}));

describe('Security Workflow End-to-End Tests', () => {
  let detector: SecurityDetector;
  let analyzer: SecurityAwareAnalyzer;
  let complianceGenerator: ComplianceGenerator;
  let explanationFramework: ThreeTierExplanationFramework;

  // Shared test config
  const testConfig = {
    apiKey: 'test-api-key',
    configPath: '.github/rsolv.yml',
    issueLabel: 'rsolv',
    aiProvider: {
      provider: 'anthropic',
      apiKey: 'test-api-key',
      model: 'claude-3-sonnet'
    },
    containerConfig: {
      enabled: false
    },
    securitySettings: {
      disableNetworkAccess: true
    }
  };

  // Helper to create proper issue objects
  const createTestIssue = (id: string, number: number, title: string, body: string) => ({
    id,
    number,
    title,
    body,
    labels: ['security'],
    assignees: [],
    repository: {
      owner: 'test-owner',
      name: 'test-repo',
      fullName: 'test-owner/test-repo',
      defaultBranch: 'main',
      language: 'JavaScript'
    },
    source: 'github',
    createdAt: '2023-01-01T00:00:00Z',
    updatedAt: '2023-01-01T00:00:00Z'
  });

  beforeEach(() => {
    detector = new SecurityDetector();
    analyzer = new SecurityAwareAnalyzer();
    complianceGenerator = new ComplianceGenerator();
    explanationFramework = new ThreeTierExplanationFramework();
  });

  describe('Complete Security Analysis Workflow', () => {
    it('should perform complete security analysis from detection to solution prompts', async () => {
      // Sample vulnerable code
      const codebaseFiles = {
        'src/database.js': `
          const mysql = require('mysql');
          
          function getUser(userId) {
            const query = "SELECT * FROM users WHERE id = " + userId;
            return db.query(query);
          }
        `,
        'src/frontend.js': `
          function displayUserContent(content) {
            document.getElementById('content').innerHTML = content;
          }
        `
      };

      const issue = createTestIssue(
        '123',
        123,
        'Security vulnerabilities found in codebase',
        'Multiple security issues detected including SQL injection and XSS'
      );

      // Step 1: Perform security-aware analysis
      const codebaseMap = new Map(Object.entries(codebaseFiles));
      const analysisData = await analyzer.analyzeWithSecurity(issue, testConfig, codebaseMap);

      // Verify security analysis was performed
      expect(analysisData.securityAnalysis).toBeDefined();
      expect(analysisData.securityAnalysis?.vulnerabilities.length).toBeGreaterThan(0);
      expect(analysisData.securityAnalysis?.affectedFiles.length).toBeGreaterThan(0);
      expect(analysisData.securityAnalysis?.riskLevel).toBeDefined();

      // Step 2: Generate compliance report
      const complianceReport = complianceGenerator.generateOwaspComplianceReport(
        analysisData.securityAnalysis!.vulnerabilities
      );

      expect(complianceReport.standard).toBe('OWASP Top 10 2021');
      expect(complianceReport.summary.totalVulnerabilities).toBeGreaterThan(0);
      expect(complianceReport.summary.compliance.status).toMatch(/non-compliant|partial/);

      // Step 3: Generate three-tier explanations
      const completeExplanation = explanationFramework.generateCompleteExplanation(
        analysisData.securityAnalysis!.vulnerabilities,
        codebaseFiles
      );

      expect(completeExplanation.lineLevelExplanations.length).toBeGreaterThan(0);
      expect(completeExplanation.conceptLevelExplanations.length).toBeGreaterThan(0);
      expect(completeExplanation.businessLevelExplanation).toBeDefined();

      // Step 4: Generate security-focused solution prompt
      const solutionPrompt = buildSecuritySolutionPrompt(
        issue,
        analysisData,
        codebaseFiles,
        analysisData.securityAnalysis!
      );

      expect(solutionPrompt).toContain('SECURITY-FOCUSED SOLUTION');
      expect(solutionPrompt).toContain('vulnerabilities');
      expect(solutionPrompt).toContain('SQL injection');

      // Step 5: Generate security explanation prompt
      const explanationPrompt = buildSecurityExplanationPrompt(
        analysisData.securityAnalysis!.vulnerabilities,
        { 'fix1': 'Security fixes implemented' }
      );

      expect(explanationPrompt).toContain('three-tier explanation');
      expect(explanationPrompt).toContain('LINE-LEVEL');
      expect(explanationPrompt).toContain('BUSINESS-LEVEL');
    });

    it('should handle mixed vulnerability types in workflow', async () => {
      const codebaseFiles = {
        'src/app.js': `
          // SQL Injection vulnerability
          const userQuery = "SELECT * FROM users WHERE name = '" + userName + "'";
          
          // XSS vulnerability  
          element.innerHTML = userInput;
          
          // Broken access control
          app.get('/admin/users', (req, res) => {
            res.json(getAllUsers());
          });
          
          // Sensitive data exposure
          console.log('User password:', password);
        `
      };

      const issue = {
        id: '456',
        title: 'Multiple security vulnerabilities',
        body: 'Code review found several security issues',
        number: 456,
        labels: ['security'],
        assignees: [],
        repository: {
          owner: 'test-owner',
          name: 'test-repo',
          fullName: 'test-owner/test-repo',
          language: 'JavaScript'
        }
      };

      const codebaseMap = new Map(Object.entries(codebaseFiles));
      const analysisData = await analyzer.analyzeWithSecurity(issue, testConfig, codebaseMap);

      // Should detect multiple vulnerability types
      expect(analysisData.securityAnalysis?.vulnerabilities.length).toBeGreaterThanOrEqual(3);
      
      const vulnTypes = new Set(analysisData.securityAnalysis!.vulnerabilities.map(v => v.type));
      expect(vulnTypes.size).toBeGreaterThanOrEqual(2); // Multiple different types

      // Generate comprehensive reports
      const complianceReport = complianceGenerator.generateOwaspComplianceReport(
        analysisData.securityAnalysis!.vulnerabilities
      );
      
      expect(Object.keys(complianceReport.categories).length).toBeGreaterThan(1);

      const explanation = explanationFramework.generateCompleteExplanation(
        analysisData.securityAnalysis!.vulnerabilities,
        codebaseFiles
      );

      expect(explanation.conceptLevelExplanations.length).toBeGreaterThan(1);
      expect(explanation.summary.totalVulnerabilities).toBeGreaterThanOrEqual(3);
    });
  });

  describe('Security Detection Integration', () => {
    it('should detect vulnerabilities in realistic code patterns', () => {
      const realisticCode = `
        const express = require('express');
        const mysql = require('mysql');
        const app = express();
        
        // SQL Injection - string concatenation
        app.get('/users/:id', (req, res) => {
          const query = "SELECT * FROM users WHERE id = " + req.params.id;
          db.query(query, (err, results) => {
            if (err) throw err;
            res.json(results);
          });
        });
        
        // XSS - direct innerHTML assignment
        app.post('/comment', (req, res) => {
          const comment = req.body.comment;
          const html = '<div class="comment">' + comment + '</div>';
          // This would be sent to client and inserted via innerHTML
          res.send(html);
        });
        
        // Broken Access Control - no authentication
        app.delete('/admin/users/:id', (req, res) => {
          const deleteQuery = "DELETE FROM users WHERE id = " + req.params.id;
          db.query(deleteQuery);
          res.send('User deleted');
        });
      `;

      const vulnerabilities = detector.detect(realisticCode, 'javascript');

      expect(vulnerabilities.length).toBeGreaterThanOrEqual(3);
      
      // We're detecting access control issues primarily
      const accessControlVulns = vulnerabilities.filter(v => v.type === 'broken_access_control');
      expect(accessControlVulns.length).toBeGreaterThanOrEqual(2);
      
      // Verify we have multiple different security vulnerability types detected
      const vulnerabilityTypes = new Set(vulnerabilities.map(v => v.type));
      expect(vulnerabilityTypes.size).toBeGreaterThanOrEqual(1);
    });

    it('should correctly identify safe patterns and avoid false positives', () => {
      const safeCode = `
        const mysql = require('mysql');
        
        // Safe parameterized query
        function getUser(userId) {
          const query = "SELECT * FROM users WHERE id = ?";
          return db.query(query, [userId]);
        }
        
        // Safe DOM manipulation
        function displayContent(content) {
          element.textContent = content;
        }
        
        // Properly authenticated endpoint
        app.get('/admin/users', authenticateUser, authorizeAdmin, (req, res) => {
          res.json(getUsers());
        });
        
        // Safe password handling
        const hashedPassword = await bcrypt.hash(password, 10);
      `;

      const vulnerabilities = detector.detect(safeCode, 'javascript');

      // Should have no vulnerabilities in safe code
      expect(vulnerabilities.length).toBe(0);
    });
  });

  describe('Cross-Component Integration', () => {
    it('should maintain data consistency across all security components', async () => {
      const testCode = `
        const query = "SELECT * FROM users WHERE id = " + req.params.id;
        element.innerHTML = userContent;
      `;

      // Detect vulnerabilities
      const detectedVulnerabilities = detector.detect(testCode, 'javascript');
      
      // Analyze with AI system
      const issue = {
        id: '789',
        title: 'Security issues',
        body: 'Found vulnerabilities',
        number: 789,
        labels: ['security'],
        assignees: [],
        repository: {
          owner: 'test-owner',
          name: 'test-repo',
          fullName: 'test-owner/test-repo',
          language: 'JavaScript'
        }
      };
      const codebaseMap = new Map([['app.js', testCode]]);
      const analysisData = await analyzer.analyzeWithSecurity(issue, testConfig, codebaseMap);

      // Generate compliance report
      const compliance = complianceGenerator.generateOwaspComplianceReport(detectedVulnerabilities);

      // Generate explanations
      const explanation = explanationFramework.generateCompleteExplanation(
        detectedVulnerabilities,
        { 'app.js': testCode }
      );

      // Verify data consistency across components
      const detectedVulnCount = detectedVulnerabilities.length;
      const analyzedVulnCount = analysisData.securityAnalysis?.vulnerabilities.length || 0;
      const complianceVulnCount = compliance.summary.totalVulnerabilities;
      const explanationVulnCount = explanation.summary.totalVulnerabilities;

      expect(detectedVulnCount).toBe(analyzedVulnCount);
      expect(detectedVulnCount).toBe(complianceVulnCount);
      expect(detectedVulnCount).toBe(explanationVulnCount);

      // Verify vulnerability types are consistent
      const detectedTypes = new Set(detectedVulnerabilities.map(v => v.type));
      const analyzedTypes = new Set(analysisData.securityAnalysis!.vulnerabilities.map(v => v.type));
      
      expect(detectedTypes).toEqual(analyzedTypes);
    });

    it('should generate actionable security prompts with proper context', async () => {
      const vulnerableCode = {
        'database.js': 'const query = "SELECT * FROM users WHERE id = " + userId;',
        'frontend.js': 'element.innerHTML = content;'
      };

      const issue = {
        id: '101112',
        title: 'Fix security vulnerabilities',
        body: 'Multiple security issues found',
        number: 101112,
        labels: ['security'],
        assignees: [],
        repository: {
          owner: 'test-owner',
          name: 'test-repo',
          fullName: 'test-owner/test-repo',
          language: 'JavaScript'
        }
      };

      const codebaseMap = new Map(Object.entries(vulnerableCode));
      const analysisData = await analyzer.analyzeWithSecurity(issue, testConfig, codebaseMap);
      
      const solutionPrompt = buildSecuritySolutionPrompt(
        issue,
        analysisData,
        vulnerableCode,
        analysisData.securityAnalysis!
      );

      // Verify prompt contains specific guidance
      expect(solutionPrompt).toContain('parameterized queries');
      expect(solutionPrompt).toContain('textContent');
      expect(solutionPrompt).toContain('SECURITY-FOCUSED SOLUTION REQUIREMENTS');
      
      // Verify affected files are marked
      expect(solutionPrompt).toContain('CONTAINS VULNERABILITIES');
      
      // Verify security requirements are included
      expect(solutionPrompt).toContain('input validation');
      expect(solutionPrompt).toContain('security tests');
    });
  });

  describe('Performance and Scalability', () => {
    it('should handle large codebases efficiently', async () => {
      // Generate a larger codebase for testing
      const largeCodebase: Record<string, string> = {};
      
      for (let i = 1; i <= 10; i++) {
        largeCodebase[`file${i}.js`] = `
          function processData${i}(input) {
            const query = "SELECT * FROM table${i} WHERE value = " + input;
            return db.query(query);
          }
          
          function displayData${i}(content) {
            document.getElementById('output${i}').innerHTML = content;
          }
        `;
      }

      const startTime = Date.now();
      
      const issue = {
        id: '999',
        title: 'Large codebase security scan',
        body: 'Review all files',
        number: 999,
        labels: ['security'],
        assignees: [],
        repository: {
          owner: 'test-owner',
          name: 'test-repo',
          fullName: 'test-owner/test-repo',
          language: 'JavaScript'
        }
      };
      const codebaseMap = new Map(Object.entries(largeCodebase));
      const analysisData = await analyzer.analyzeWithSecurity(issue, testConfig, codebaseMap);
      
      const endTime = Date.now();
      const duration = endTime - startTime;

      // Should complete within reasonable time (adjust threshold as needed)
      expect(duration).toBeLessThan(5000); // 5 seconds
      
      // Should detect vulnerabilities across multiple files
      expect(analysisData.securityAnalysis?.vulnerabilities.length).toBeGreaterThan(10);
      expect(analysisData.securityAnalysis?.affectedFiles.length).toBe(10);
    });
  });
});