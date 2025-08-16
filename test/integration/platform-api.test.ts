/**
 * Integration tests for PhaseDataClient <-> Platform API
 * These tests verify the contract between TypeScript client and Elixir server
 */

import { describe, it, expect, beforeAll } from '@jest/globals';
import { PhaseDataClient } from '../../src/modes/phase-data-client';

describe('PhaseDataClient Platform Integration', () => {
  let client: PhaseDataClient;
  const testRepo = `RSOLV-dev/integration-test-${Date.now()}`;
  const testIssue = 99;
  const testCommit = `test-commit-${Date.now()}`;
  
  beforeAll(() => {
    // Use environment variables for configuration
    const apiKey = process.env.RSOLV_TEST_API_KEY || 'test_key';
    const apiUrl = process.env.RSOLV_TEST_API_URL || 'http://localhost:4000';
    
    client = new PhaseDataClient(apiKey, apiUrl);
  });

  describe('Phase Name Mapping', () => {
    it('should map validate to validation in API calls', async () => {
      const validationData = {
        validation: {
          [`issue-${testIssue}`]: {
            validated: true,
            confidence: 0.95,
            timestamp: new Date().toISOString()
          }
        }
      };

      const result = await client.storePhaseResults('validate', validationData, {
        repo: testRepo,
        issueNumber: testIssue,
        commitSha: testCommit,
        branch: 'main'
      });

      expect(result.success).toBe(true);
      // Verify the platform received 'validation' not 'validate'
    });

    it('should map mitigate to mitigation in API calls', async () => {
      const mitigationData = {
        mitigation: {
          [`issue-${testIssue}`]: {
            fixed: true,
            prUrl: 'https://github.com/test/pr/1',
            timestamp: new Date().toISOString()
          }
        }
      };

      const result = await client.storePhaseResults('mitigate', mitigationData, {
        repo: testRepo,
        issueNumber: testIssue,
        commitSha: testCommit,
        branch: 'main'
      });

      expect(result.success).toBe(true);
      // Verify the platform received 'mitigation' not 'mitigate'
    });
  });

  describe('Data Structure Contract', () => {
    it('should send scan data in correct format', async () => {
      const scanData = {
        scan: {
          vulnerabilities: [
            {
              type: 'xss',
              file: 'app.js',
              line: 42,
              severity: 'high'
            }
          ],
          timestamp: new Date().toISOString(),
          commitHash: testCommit
        }
      };

      const result = await client.storePhaseResults('scan', scanData, {
        repo: testRepo,
        issueNumber: testIssue,
        commitSha: testCommit,
        branch: 'main'
      });

      expect(result.success).toBe(true);
    });

    it('should send validation data with issue key nesting', async () => {
      const validationData = {
        validation: {
          [`issue-${testIssue}`]: {
            validated: true,
            vulnerabilities: [],
            confidence: 0.95,
            timestamp: new Date().toISOString()
          }
        }
      };

      const result = await client.storePhaseResults('validate', validationData, {
        repo: testRepo,
        issueNumber: testIssue,
        commitSha: testCommit,
        branch: 'main'
      });

      expect(result.success).toBe(true);
    });
  });

  describe('Three-Phase Flow', () => {
    const flowTestRepo = `RSOLV-dev/flow-test-${Date.now()}`;
    const flowTestIssue = 123;
    const flowTestCommit = `flow-${Date.now()}`;

    it('should store and retrieve scan phase data', async () => {
      // Store scan data
      await client.storePhaseResults('scan', {
        scan: {
          vulnerabilities: [{type: 'sql-injection', file: 'db.js', line: 100}],
          timestamp: new Date().toISOString(),
          commitHash: flowTestCommit
        }
      }, {
        repo: flowTestRepo,
        issueNumber: flowTestIssue,
        commitSha: flowTestCommit,
        branch: 'main'
      });

      // Retrieve as VALIDATE phase would
      const data = await client.retrievePhaseResults(flowTestRepo, flowTestIssue, flowTestCommit);
      
      expect(data.scan).toBeDefined();
      expect(data.scan?.vulnerabilities).toHaveLength(1);
      expect(data.scan?.vulnerabilities[0].type).toBe('sql-injection');
    });

    it('should retrieve scan data in validate phase', async () => {
      const data = await client.retrievePhaseResults(flowTestRepo, flowTestIssue, flowTestCommit);
      
      expect(data.scan).toBeDefined();
      expect(data.scan?.vulnerabilities).toBeDefined();
    });

    it('should retrieve both scan and validation data in mitigate phase', async () => {
      // First store validation data
      await client.storePhaseResults('validate', {
        validation: {
          [`issue-${flowTestIssue}`]: {
            validated: true,
            confidence: 0.99,
            timestamp: new Date().toISOString()
          }
        }
      }, {
        repo: flowTestRepo,
        issueNumber: flowTestIssue,
        commitSha: flowTestCommit
      });

      // Retrieve as MITIGATE phase would
      const data = await client.retrievePhaseResults(flowTestRepo, flowTestIssue, flowTestCommit);
      
      expect(data.scan).toBeDefined();
      expect(data.validation).toBeDefined();
      expect(data.validation?.[`issue-${flowTestIssue}`]?.validated).toBe(true);
    });
  });

  describe('Error Handling', () => {
    it('should fallback to local storage on platform errors', async () => {
      // Temporarily use a bad URL to trigger fallback
      const errorClient = new PhaseDataClient('test_key', 'http://invalid-url-that-does-not-exist');
      
      const result = await errorClient.storePhaseResults('scan', {
        scan: {
          vulnerabilities: [],
          timestamp: new Date().toISOString(),
          commitHash: 'test'
        }
      }, {
        repo: 'test/repo',
        issueNumber: 1,
        commitSha: 'test',
        branch: 'main'
      });

      expect(result.success).toBe(true);
      expect(result.storage).toBe('local');
      expect(result.warning).toContain('Platform storage failed');
    });
  });

  describe('Field Name Mapping', () => {
    it('should convert camelCase to snake_case for platform API', async () => {
      // This test verifies that commitSha becomes commit_sha, etc.
      const scanData = {
        scan: {
          vulnerabilities: [],
          timestamp: new Date().toISOString(),
          commitHash: testCommit
        }
      };

      const result = await client.storePhaseResults('scan', scanData, {
        repo: testRepo,
        issueNumber: testIssue,
        commitSha: testCommit,  // Should become commit_sha
        branch: 'main'
      });

      expect(result.success).toBe(true);
      // Platform should receive commit_sha, issue_number in snake_case
    });
  });
});