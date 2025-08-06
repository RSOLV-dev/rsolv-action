/**
 * TDD tests for PhaseDataClient
 * Following RFC-041 specification for phase data storage
 */

import { describe, test, expect, beforeEach, mock } from 'bun:test';
import { PhaseDataClient, StoreResult, PhaseData } from '../index.js';

describe('PhaseDataClient', () => {
  let client: PhaseDataClient;
  const mockApiKey = 'test-api-key';
  const mockBaseUrl = 'https://test.api.rsolv.dev';

  beforeEach(() => {
    // Reset fetch mock
    global.fetch = mock(async () => new Response());
  });

  describe('storePhaseResults', () => {
    test('should store phase results successfully', async () => {
      // RED: This test will fail because PhaseDataClient doesn't exist yet
      
      // Arrange
      client = new PhaseDataClient(mockApiKey, mockBaseUrl);
      
      const mockResponse = {
        success: true,
        id: 'phase-123',
        message: 'Phase data stored successfully'
      };
      
      global.fetch = mock(async () => 
        new Response(JSON.stringify(mockResponse), {
          status: 200,
          headers: { 'Content-Type': 'application/json' }
        })
      );

      const phaseData: PhaseData = {
        scan: {
          vulnerabilities: [
            { type: 'sql-injection', file: 'user.js', line: 42 }
          ],
          timestamp: '2025-08-06T10:00:00Z',
          commitHash: 'abc123'
        }
      };

      // Act
      const result = await client.storePhaseResults(
        'scan',
        phaseData,
        {
          repo: 'test-owner/test-repo',
          issueNumber: 123,
          commitSha: 'abc123'
        }
      );

      // Assert
      expect(result.success).toBe(true);
      expect(result.id).toBe('phase-123');
      expect(global.fetch).toHaveBeenCalledWith(
        'https://test.api.rsolv.dev/api/v1/phases/store',
        expect.objectContaining({
          method: 'POST',
          headers: expect.any(Headers),
          body: expect.stringContaining('scan')
        })
      );
    });

    test('should include API key in headers', async () => {
      // Arrange
      client = new PhaseDataClient(mockApiKey);
      
      global.fetch = mock(async (url: string, options?: RequestInit) => {
        // Capture the headers for verification
        const headers = options?.headers as Headers;
        expect(headers.get('X-API-Key')).toBe(mockApiKey);
        expect(headers.get('Content-Type')).toBe('application/json');
        
        return new Response(JSON.stringify({ success: true }), { status: 200 });
      });

      // Act
      await client.storePhaseResults('scan', {}, {
        repo: 'test/repo',
        commitSha: 'abc123'
      });

      // Assert
      expect(global.fetch).toHaveBeenCalled();
    });

    test('should fall back to local storage on API failure', async () => {
      // Arrange
      client = new PhaseDataClient(mockApiKey);
      
      // Mock fetch to fail
      global.fetch = mock(async () => {
        throw new Error('Network error');
      });

      // Mock file system for local storage
      const mockWriteFile = mock(async () => {});
      const mockMkdir = mock(async () => {});
      
      mock.module('fs/promises', () => ({
        writeFile: mockWriteFile,
        mkdir: mockMkdir
      }));

      // Act
      const result = await client.storePhaseResults('scan', {}, {
        repo: 'test/repo',
        commitSha: 'abc123'
      });

      // Assert
      expect(result.success).toBe(true);
      expect(result.storage).toBe('local');
      expect(result.warning).toContain('Platform unavailable');
    });
  });

  describe('retrievePhaseResults', () => {
    test('should retrieve phase results successfully', async () => {
      // Arrange
      client = new PhaseDataClient(mockApiKey, mockBaseUrl);
      
      const mockData: PhaseData = {
        scan: {
          vulnerabilities: [{ type: 'xss', file: 'view.js', line: 10 }],
          timestamp: '2025-08-06T11:00:00Z',
          commitHash: 'def456'
        }
      };
      
      global.fetch = mock(async () => 
        new Response(JSON.stringify(mockData), {
          status: 200,
          headers: { 'Content-Type': 'application/json' }
        })
      );

      // Act
      const result = await client.retrievePhaseResults(
        'test/repo',
        123,
        'def456'
      );

      // Assert
      expect(result).toEqual(mockData);
      expect(global.fetch).toHaveBeenCalledWith(
        expect.stringContaining('/api/v1/phases/retrieve'),
        expect.objectContaining({
          headers: expect.any(Headers)
        })
      );
    });

    test('should return null for 404 responses', async () => {
      // Arrange
      client = new PhaseDataClient(mockApiKey);
      
      global.fetch = mock(async () => 
        new Response('Not found', { status: 404 })
      );

      // Act
      const result = await client.retrievePhaseResults('test/repo', 123, 'abc');

      // Assert
      expect(result).toBe(null);
    });

    test('should fall back to local storage on API error', async () => {
      // Arrange
      client = new PhaseDataClient(mockApiKey);
      
      // Mock fetch to fail with non-404 error
      global.fetch = mock(async () => 
        new Response('Server error', { status: 500 })
      );

      // Mock file system for local retrieval
      const mockReaddir = mock(async () => ['test-repo-123-scan.json']);
      const mockReadFile = mock(async () => JSON.stringify({
        phase: 'scan',
        data: { scan: { vulnerabilities: [] } },
        metadata: { commitSha: 'abc123' }
      }));
      
      mock.module('fs/promises', () => ({
        readdir: mockReaddir,
        readFile: mockReadFile
      }));

      // Act
      const result = await client.retrievePhaseResults('test-repo', 123, 'abc123');

      // Assert
      expect(result).toBeDefined();
      expect(result?.scan).toBeDefined();
    });
  });

  describe('validatePhaseTransition', () => {
    test('should validate allowed phase transitions', async () => {
      // Arrange
      client = new PhaseDataClient(mockApiKey);
      
      // Mock git command to return current commit
      mock.module('child_process', () => ({
        execSync: () => 'abc123\n'
      }));

      // Act & Assert
      expect(await client.validatePhaseTransition('scan', 'validate', 'abc123')).toBe(true);
      expect(await client.validatePhaseTransition('validate', 'mitigate', 'abc123')).toBe(true);
      expect(await client.validatePhaseTransition('mitigate', 'scan', 'abc123')).toBe(false);
    });

    test('should reject transition if commit has changed', async () => {
      // Arrange
      client = new PhaseDataClient(mockApiKey);
      
      // Mock git to return different commit
      mock.module('child_process', () => ({
        execSync: () => 'different-commit\n'
      }));

      // Act
      const result = await client.validatePhaseTransition('scan', 'validate', 'abc123');

      // Assert
      expect(result).toBe(false);
    });
  });
});