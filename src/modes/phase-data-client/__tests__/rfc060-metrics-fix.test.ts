/**
 * RFC-060 Metrics Collection Fix - Regression Tests
 *
 * Ensures PhaseDataClient correctly extracts and sends phase data
 * to the platform API for metrics collection.
 *
 * Bug: PhaseDataClient was sending wrapped PhaseData structure instead
 * of extracting specific phase data for each issue.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { PhaseDataClient } from '../index.js';
import type { PhaseData } from '../index.js';

describe('RFC-060 Metrics Fix - Phase Data Extraction', () => {
  let client: PhaseDataClient;
  let fetchMock: any;

  beforeEach(() => {
    fetchMock = vi.fn();
    global.fetch = fetchMock;
    client = new PhaseDataClient('test-api-key', 'https://test.rsolv.dev');
  });

  describe('SCAN phase data extraction', () => {
    it('should send scan data directly to platform', async () => {
      fetchMock.mockResolvedValue({
        ok: true,
        json: async () => ({ success: true, id: 'scan-123', phase: 'scan' })
      });

      const scanData: PhaseData = {
        scan: {
          vulnerabilities: [
            { type: 'xss', file: 'index.js', line: 42 }
          ],
          timestamp: '2025-10-12T14:00:00Z',
          commitHash: 'abc123'
        }
      };

      await client.storePhaseResults('scan', scanData, {
        repo: 'owner/repo',
        commitSha: 'abc123'
      });

      expect(fetchMock).toHaveBeenCalledWith(
        'https://test.rsolv.dev/api/v1/phases/store',
        expect.objectContaining({
          method: 'POST',
          body: JSON.stringify({
            phase: 'scan',
            data: scanData.scan, // Direct scan data, not wrapped
            repo: 'owner/repo',
            commitSha: 'abc123'
          })
        })
      );
    });
  });

  describe('VALIDATE phase data extraction', () => {
    it('should extract issue-specific validation data for platform', async () => {
      fetchMock.mockResolvedValue({
        ok: true,
        json: async () => ({ success: true, id: 'val-123', phase: 'validation' })
      });

      const validateData: PhaseData = {
        validate: {
          '42': {
            validated: true,
            branchName: 'rsolv/validate/42',
            testPath: '__tests__/security/rsolv-42.test.js',
            timestamp: '2025-10-12T14:01:00Z'
          }
        }
      };

      await client.storePhaseResults('validate', validateData, {
        repo: 'owner/repo',
        issueNumber: 42,
        commitSha: 'def456'
      });

      expect(fetchMock).toHaveBeenCalledWith(
        'https://test.rsolv.dev/api/v1/phases/store',
        expect.objectContaining({
          method: 'POST',
          body: JSON.stringify({
            phase: 'validation',
            data: {  // Extracted issue-specific data, not wrapped
              validated: true,
              branchName: 'rsolv/validate/42',
              testPath: '__tests__/security/rsolv-42.test.js',
              timestamp: '2025-10-12T14:01:00Z'
            },
            repo: 'owner/repo',
            issueNumber: 42,
            commitSha: 'def456'
          })
        })
      );
    });

    it('should map validate to validation phase name', async () => {
      fetchMock.mockResolvedValue({
        ok: true,
        json: async () => ({ success: true })
      });

      const validateData: PhaseData = {
        validate: {
          '99': {
            validated: false,
            falsePositiveReason: 'vendor file',
            timestamp: '2025-10-12T14:02:00Z'
          }
        }
      };

      await client.storePhaseResults('validate', validateData, {
        repo: 'owner/repo',
        issueNumber: 99,
        commitSha: 'ghi789'
      });

      const callBody = JSON.parse(fetchMock.mock.calls[0][1].body);
      expect(callBody.phase).toBe('validation');  // Not 'validate'
    });
  });

  describe('MITIGATE phase data extraction', () => {
    it('should extract issue-specific mitigation data for platform', async () => {
      fetchMock.mockResolvedValue({
        ok: true,
        json: async () => ({ success: true, id: 'mit-123', phase: 'mitigation' })
      });

      const mitigateData: PhaseData = {
        mitigate: {
          '42': {
            fixed: true,
            prUrl: 'https://github.com/owner/repo/pull/100',
            fixCommit: 'jkl012',
            timestamp: '2025-10-12T14:03:00Z'
          }
        }
      };

      await client.storePhaseResults('mitigate', mitigateData, {
        repo: 'owner/repo',
        issueNumber: 42,
        commitSha: 'jkl012'
      });

      expect(fetchMock).toHaveBeenCalledWith(
        'https://test.rsolv.dev/api/v1/phases/store',
        expect.objectContaining({
          method: 'POST',
          body: JSON.stringify({
            phase: 'mitigation',
            data: {  // Extracted issue-specific data, not wrapped
              fixed: true,
              prUrl: 'https://github.com/owner/repo/pull/100',
              fixCommit: 'jkl012',
              timestamp: '2025-10-12T14:03:00Z'
            },
            repo: 'owner/repo',
            issueNumber: 42,
            commitSha: 'jkl012'
          })
        })
      );
    });

    it('should map mitigate to mitigation phase name', async () => {
      fetchMock.mockResolvedValue({
        ok: true,
        json: async () => ({ success: true })
      });

      const mitigateData: PhaseData = {
        mitigate: {
          '77': {
            fixed: false,
            timestamp: '2025-10-12T14:04:00Z'
          }
        }
      };

      await client.storePhaseResults('mitigate', mitigateData, {
        repo: 'owner/repo',
        issueNumber: 77,
        commitSha: 'mno345'
      });

      const callBody = JSON.parse(fetchMock.mock.calls[0][1].body);
      expect(callBody.phase).toBe('mitigation');  // Not 'mitigate'
    });
  });

  describe('Error handling', () => {
    it('should throw error when validation data missing for issue', async () => {
      const validateData: PhaseData = {
        validate: {
          '99': {  // Different issue number
            validated: true,
            timestamp: '2025-10-12T14:05:00Z'
          }
        }
      };

      await expect(
        client.storePhaseResults('validate', validateData, {
          repo: 'owner/repo',
          issueNumber: 42,  // Request issue 42, but data only has 99
          commitSha: 'xyz'
        })
      ).rejects.toThrow('No validate data found for issue 42');
    });

    it('should fallback to local storage on platform error', async () => {
      fetchMock.mockRejectedValue(new Error('Network error'));

      const validateData: PhaseData = {
        validate: {
          '42': {
            validated: true,
            timestamp: '2025-10-12T14:06:00Z'
          }
        }
      };

      const result = await client.storePhaseResults('validate', validateData, {
        repo: 'owner/repo',
        issueNumber: 42,
        commitSha: 'abc'
      });

      expect(result.storage).toBe('local');
      expect(result.warning).toContain('Platform unavailable');
    });
  });
});
