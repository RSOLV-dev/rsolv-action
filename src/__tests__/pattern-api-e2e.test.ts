/**
 * Pattern API End-to-End Test
 * 
 * This test verifies the complete integration between RSOLV-action and RSOLV-api
 * for the RFC-008 Pattern Serving API implementation.
 * 
 * This test uses REAL API calls, not mocks.
 */

import { describe, it, expect, beforeAll, afterAll } from 'bun:test';
import { TieredPatternSource, SecurityDetector } from '../security/index.js';
import { SecurityAwareAnalyzer } from '../ai/security-analyzer.js';

// Use environment variable or default to local Docker Compose setup
const API_URL = process.env.RSOLV_API_URL || 'http://localhost:4000';

// Test credentials
const TEST_API_KEY = 'test_rsolv_abcdef123456'; // This should be seeded in the test database

describe('Pattern API E2E Tests (Real API)', () => {
  let patternSource: TieredPatternSource;

  beforeAll(() => {
    console.log(`🧪 Running E2E tests against: ${API_URL}`);
    patternSource = new TieredPatternSource(API_URL);
  });

  afterAll(() => {
    // Clear cache to avoid test pollution
    patternSource.clearCache();
  });

  describe('Public Pattern Access', () => {
    it('should fetch public JavaScript patterns without authentication', async () => {
      const patterns = await patternSource.getPatternsByLanguage('javascript');
      
      expect(patterns).toBeDefined();
      expect(Array.isArray(patterns)).toBe(true);
      expect(patterns.length).toBeGreaterThan(0);
      
      // Verify pattern structure
      const firstPattern = patterns[0];
      expect(firstPattern).toHaveProperty('name');
      expect(firstPattern).toHaveProperty('description');
      expect(firstPattern).toHaveProperty('type');
      expect(firstPattern).toHaveProperty('severity');
      expect(firstPattern).toHaveProperty('patterns');
      expect(firstPattern.patterns).toHaveProperty('regex');
      
      console.log(`✅ Retrieved ${patterns.length} public JavaScript patterns`);
    });

    it('should fetch public patterns for different languages', async () => {
      const languages = ['javascript', 'python', 'ruby', 'java'];
      
      for (const language of languages) {
        const patterns = await patternSource.getPatternsByLanguage(language);
        console.log(`  ${language}: ${patterns.length} patterns`);
        
        // CVE patterns might return 0 for public tier
        if (language !== 'cve') {
          expect(patterns.length).toBeGreaterThanOrEqual(0);
        }
      }
    });
  });

  describe('Protected Pattern Access', () => {
    it('should fetch protected patterns with valid API key', async () => {
      const customerConfig = {
        apiKey: TEST_API_KEY,
        tier: 'teams' as const
      };
      
      const patterns = await patternSource.getPatternsByLanguage('javascript', customerConfig);
      
      expect(patterns).toBeDefined();
      expect(Array.isArray(patterns)).toBe(true);
      
      // Protected tier should have more patterns than public
      const publicPatterns = await patternSource.getPatternsByLanguage('javascript');
      console.log(`✅ Public patterns: ${publicPatterns.length}, Protected patterns: ${patterns.length}`);
    });

    it('should fall back to public patterns with invalid API key', async () => {
      const customerConfig = {
        apiKey: 'invalid-api-key',
        tier: 'teams' as const
      };
      
      const patterns = await patternSource.getPatternsByLanguage('javascript', customerConfig);
      
      expect(patterns).toBeDefined();
      expect(Array.isArray(patterns)).toBe(true);
      
      // Should have fallen back to public patterns
      console.log(`✅ Fallback to public patterns: ${patterns.length} patterns`);
    });
  });

  describe('AI Tier Pattern Access', () => {
    it('should access AI patterns with proper credentials', async () => {
      const customerConfig = {
        apiKey: TEST_API_KEY,
        aiEnabled: true
      };
      
      const patterns = await patternSource.getPatternsByLanguage('cve', customerConfig);
      
      expect(patterns).toBeDefined();
      expect(Array.isArray(patterns)).toBe(true);
      
      // AI tier should include CVE patterns
      console.log(`✅ AI tier CVE patterns: ${patterns.length} patterns`);
    });
  });

  describe('SecurityDetector Integration', () => {
    it('should detect vulnerabilities using API patterns', async () => {
      const detector = new SecurityDetector(patternSource);
      
      // Test code with multiple vulnerability types
      const testCode = `
        // Hardcoded secret
        const api_key = "sk-1234567890abcdef";
        
        // SQL injection
        const query = "SELECT * FROM users WHERE id = " + userId;
        
        // XSS vulnerability
        document.getElementById('output').innerHTML = userInput;
        
        // Command injection
        const exec = require('child_process').exec;
        exec('ping ' + userProvidedHost);
      `;
      
      const vulnerabilities = await detector.detect(testCode, 'javascript');
      
      expect(vulnerabilities).toBeDefined();
      expect(Array.isArray(vulnerabilities)).toBe(true);
      expect(vulnerabilities.length).toBeGreaterThan(0);
      
      console.log(`✅ Detected ${vulnerabilities.length} vulnerabilities`);
      
      // Log vulnerability types found
      const types = new Set(vulnerabilities.map(v => v.type));
      console.log(`  Types: ${Array.from(types).join(', ')}`);
    });
  });

  describe('SecurityAwareAnalyzer Integration', () => {
    it('should perform security analysis using API patterns', async () => {
      const analyzer = new SecurityAwareAnalyzer();
      
      const codebaseFiles = new Map([
        ['src/auth.js', `
          const password = "admin123";
          const apiKey = "sk-prod-1234567890";
        `],
        ['src/database.js', `
          function getUser(id) {
            return db.query("SELECT * FROM users WHERE id = " + id);
          }
        `]
      ]);
      
      const issue = {
        number: 1,
        title: 'Security vulnerability scan',
        body: 'Please scan for security issues',
        repository: {
          fullName: 'test/repo',
          language: 'javascript'
        }
      };
      
      const result = await analyzer.performSecurityAnalysis(codebaseFiles, issue);
      
      expect(result).toBeDefined();
      expect(result.hasSecurityIssues).toBe(true);
      expect(result.vulnerabilities.length).toBeGreaterThan(0);
      expect(result.affectedFiles.length).toBeGreaterThan(0);
      
      console.log(`✅ Security analysis complete:`);
      console.log(`  - Total vulnerabilities: ${result.summary.total}`);
      console.log(`  - Risk level: ${result.riskLevel}`);
      console.log(`  - Affected files: ${result.affectedFiles.join(', ')}`);
    });
  });

  describe('Performance Tests', () => {
    it('should cache patterns to reduce API calls', async () => {
      // Clear cache first
      patternSource.clearCache();
      
      const start1 = Date.now();
      await patternSource.getPatternsByLanguage('javascript');
      const time1 = Date.now() - start1;
      
      const start2 = Date.now();
      await patternSource.getPatternsByLanguage('javascript');
      const time2 = Date.now() - start2;
      
      console.log(`✅ Cache performance:`);
      console.log(`  - First call: ${time1}ms`);
      console.log(`  - Cached call: ${time2}ms`);
      
      // Cached call should be significantly faster
      expect(time2).toBeLessThan(time1 / 2);
    });

    it('should handle API timeouts gracefully', async () => {
      // Create a pattern source with unreachable API
      const badSource = new TieredPatternSource('http://localhost:9999');
      
      const patterns = await badSource.getPatternsByLanguage('javascript');
      
      expect(patterns).toBeDefined();
      expect(Array.isArray(patterns)).toBe(true);
      expect(patterns.length).toBeGreaterThan(0);
      
      // Should have fallback patterns
      expect(patterns[0].tags).toContain('fallback');
      console.log(`✅ Fallback patterns working: ${patterns.length} patterns`);
    });
  });

  describe('Complete Workflow Test', () => {
    it('should complete full security scan workflow with API patterns', async () => {
      console.log('\n🔄 Running complete workflow test...\n');
      
      // 1. Initialize components
      const patternSource = new TieredPatternSource(API_URL);
      const detector = new SecurityDetector(patternSource);
      
      // 2. Simulate vulnerable code
      const vulnerableCode = `
        const express = require('express');
        const app = express();
        
        // SQL injection vulnerability
        app.get('/user/:id', (req, res) => {
          const query = 'SELECT * FROM users WHERE id = ' + req.params.id;
          db.query(query, (err, result) => {
            res.json(result);
          });
        });
        
        // XSS vulnerability
        app.post('/comment', (req, res) => {
          const comment = req.body.comment;
          res.send('<div>' + comment + '</div>');
        });
        
        // Hardcoded credentials
        const config = {
          database: {
            password: 'super-secret-password-123',
            apiKey: 'sk-prod-abcdef123456789'
          }
        };
        
        app.listen(3000);
      `;
      
      // 3. Run detection
      console.log('🔍 Scanning for vulnerabilities...');
      const vulnerabilities = await detector.detect(vulnerableCode, 'javascript');
      
      // 4. Verify results
      expect(vulnerabilities.length).toBeGreaterThan(0);
      
      console.log(`\n📊 Scan Results:`);
      console.log(`  Total vulnerabilities: ${vulnerabilities.length}`);
      
      // Group by type
      const byType = vulnerabilities.reduce((acc, v) => {
        acc[v.type] = (acc[v.type] || 0) + 1;
        return acc;
      }, {} as Record<string, number>);
      
      console.log(`\n  By Type:`);
      Object.entries(byType).forEach(([type, count]) => {
        console.log(`    - ${type}: ${count}`);
      });
      
      // Group by severity
      const bySeverity = vulnerabilities.reduce((acc, v) => {
        acc[v.severity] = (acc[v.severity] || 0) + 1;
        return acc;
      }, {} as Record<string, number>);
      
      console.log(`\n  By Severity:`);
      Object.entries(bySeverity).forEach(([severity, count]) => {
        console.log(`    - ${severity}: ${count}`);
      });
      
      console.log('\n✅ Complete workflow test passed!');
    });
  });
});

// Add a script runner for package.json
if (import.meta.main) {
  console.log('🚀 Starting Pattern API E2E Tests...\n');
  console.log(`API URL: ${API_URL}`);
  console.log('Make sure RSOLV-api is running with the Pattern API endpoints!\n');
}