/**
 * Tests for PipelineRunClient (RFC-126)
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { PipelineRunClient } from '../pipeline-run-client.js';

describe('PipelineRunClient', () => {
  let client: PipelineRunClient;

  beforeEach(() => {
    client = new PipelineRunClient({
      apiUrl: 'https://api.rsolv.dev',
      apiKey: 'test-key-123',
    });
    vi.restoreAllMocks();
  });

  describe('createRun', () => {
    it('calls POST /api/v1/pipeline-runs with scan results', async () => {
      const mockResponse = {
        pipeline_run_id: 'run-uuid-123',
        issues: [
          { issue_number: 1, cwe_id: 'CWE-89', phase: 'scan_detected' },
          { issue_number: 2, cwe_id: 'CWE-79', phase: 'scan_detected' },
        ],
      };

      vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce({
        ok: true,
        json: async () => mockResponse,
      } as Response);

      const result = await client.createRun({
        commitSha: 'abc123',
        branch: 'main',
        mode: 'scan',
        namespace: 'arubis/railsgoat-vulnerability-demo',
        createdIssues: [
          { issue_number: 1, cwe_id: 'CWE-89' },
          { issue_number: 2, cwe_id: 'CWE-79' },
        ],
      });

      expect(result.pipeline_run_id).toBe('run-uuid-123');
      expect(result.issues).toHaveLength(2);

      expect(fetch).toHaveBeenCalledWith(
        'https://api.rsolv.dev/api/v1/pipeline-runs',
        expect.objectContaining({
          method: 'POST',
          headers: expect.objectContaining({
            'x-api-key': 'test-key-123',
          }),
        })
      );
    });

    it('sets pipeline_run_id as output after scanning', async () => {
      const mockResponse = {
        pipeline_run_id: 'run-uuid-456',
        issues: [],
      };

      vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce({
        ok: true,
        json: async () => mockResponse,
      } as Response);

      const result = await client.createRun({
        commitSha: 'abc123',
        mode: 'scan',
        namespace: 'test/repo',
        createdIssues: [],
      });

      expect(result.pipeline_run_id).toBe('run-uuid-456');
    });

    it('throws on failed request', async () => {
      vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce({
        ok: false,
        status: 400,
        text: async () => '{"error":"commit_sha is required"}',
      } as Response);

      await expect(
        client.createRun({
          commitSha: '',
          mode: 'scan',
          namespace: 'test/repo',
          createdIssues: [],
        })
      ).rejects.toThrow('Failed to create pipeline run');
    });
  });

  describe('getPendingIssues', () => {
    it('calls GET /pending-issues for work discovery', async () => {
      const mockResponse = {
        pending_issues: [
          { issue_number: 1, cwe_id: 'CWE-89', phase: 'scan_detected', pending_action: 'validate' },
          { issue_number: 2, cwe_id: 'CWE-79', phase: 'validated', pending_action: 'mitigate' },
        ],
      };

      vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce({
        ok: true,
        json: async () => mockResponse,
      } as Response);

      const pending = await client.getPendingIssues('run-uuid-123');

      expect(pending).toHaveLength(2);
      expect(pending[0].pending_action).toBe('validate');
      expect(pending[1].pending_action).toBe('mitigate');

      expect(fetch).toHaveBeenCalledWith(
        'https://api.rsolv.dev/api/v1/pipeline-runs/run-uuid-123/pending-issues',
        expect.objectContaining({
          method: 'GET',
          headers: expect.objectContaining({
            'x-api-key': 'test-key-123',
          }),
        })
      );
    });

    it('returns empty for no pending issues', async () => {
      vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce({
        ok: true,
        json: async () => ({ pending_issues: [] }),
      } as Response);

      const pending = await client.getPendingIssues('run-uuid-123');
      expect(pending).toEqual([]);
    });
  });

  describe('reportPR', () => {
    it('reports pr_url via PATCH after PR creation', async () => {
      vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce({
        ok: true,
        json: async () => ({ success: true }),
      } as Response);

      await client.reportPR(
        'run-uuid-123',
        1,
        'https://github.com/arubis/test-repo/pull/42',
        42
      );

      expect(fetch).toHaveBeenCalledWith(
        'https://api.rsolv.dev/api/v1/pipeline-runs/run-uuid-123/issues/1',
        expect.objectContaining({
          method: 'PATCH',
          body: JSON.stringify({
            pr_url: 'https://github.com/arubis/test-repo/pull/42',
            pr_number: 42,
          }),
        })
      );
    });
  });
});
