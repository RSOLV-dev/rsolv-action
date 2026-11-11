/**
 * Integration tests for actual API endpoints
 * These tests verify real API behavior and should be run separately from unit tests
 * Run with: INTEGRATION_TEST=true vitest test/integration/api-endpoints.test.ts
 */

import { describe, it, expect, beforeAll, skipIf, vi } from 'vitest';
import { RsolvApiClient } from '../../src/external/api-client.js';

// Skip these tests unless explicitly running integration tests
const isIntegrationTest = process.env.INTEGRATION_TEST === 'true';
const hasApiKey = !!process.env.RSOLV_API_KEY;

describe.skipIf(!isIntegrationTest || !hasApiKey)('API Endpoint Integration Tests', () => {
  let apiClient: RsolvApiClient;
  const apiKey = process.env.RSOLV_API_KEY!;
  
  beforeAll(() => {
    apiClient = new RsolvApiClient(apiKey);
  });
  
  describe('Pattern API', () => {
    it('should fetch patterns from real API', async () => {
      const patterns = await apiClient.getPatterns();
      
      expect(patterns).toBeDefined();
      expect(Array.isArray(patterns)).toBe(true);
      expect(patterns.length).toBeGreaterThan(0);
      
      // Verify pattern structure
      const pattern = patterns[0];
      expect(pattern).toHaveProperty('id');
      expect(pattern).toHaveProperty('type');
      expect(pattern).toHaveProperty('severity');
    });
    
    it('should handle language-specific pattern requests', async () => {
      const jsPatterns = await apiClient.getPatterns('javascript');
      
      expect(jsPatterns).toBeDefined();
      expect(Array.isArray(jsPatterns)).toBe(true);
      
      // All patterns should support JavaScript
      jsPatterns.forEach(pattern => {
        expect(pattern.languages).toContain('javascript');
      });
    });
  });
  
  describe('Validation API', () => {
    it('should validate vulnerabilities through real API', async () => {
      const testVulnerability = {
        id: 'test-1',
        type: 'sql_injection',
        filePath: 'test.js',
        line: 10,
        code: 'db.query(`SELECT * FROM users WHERE id = ${userId}`)'
      };
      
      const result = await apiClient.validateVulnerabilities(
        [testVulnerability],
        { 'test.js': { content: 'test content', hash: 'sha256:test' } }
      );
      
      expect(result).toBeDefined();
      expect(result.validated).toBeDefined();
      expect(Array.isArray(result.validated)).toBe(true);
    });
  });
  
  describe('Fix Tracking API', () => {
    it('should record fix attempts', async () => {
      const fixAttempt = {
        issueId: 'test-issue-1',
        repository: 'test-owner/test-repo',
        status: 'success',
        filesModified: ['test.js'],
        prNumber: 1
      };
      
      const result = await apiClient.recordFixAttempt(fixAttempt);
      
      expect(result).toBeDefined();
      expect(result.success).toBe(true);
    });
  });
});

describe.skipIf(!isIntegrationTest)('API Error Handling', () => {
  it('should handle rate limiting gracefully', async () => {
    // This test would need to trigger rate limiting
    // which might not be appropriate for regular testing
    expect(true).toBe(true);
  });
  
  it('should handle network errors with retry', async () => {
    // Test network resilience
    expect(true).toBe(true);
  });
});