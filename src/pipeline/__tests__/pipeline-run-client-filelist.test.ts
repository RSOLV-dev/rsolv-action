/**
 * Tests for PipelineRunClient file list passthrough (test discovery wiring)
 *
 * The platform's PhaseContext reads `files_scanned` from ScanExecution.data
 * to derive test directory/file hints and recommended test files. This test
 * verifies the Action sends the scanned file list in the createRun payload.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { PipelineRunClient } from '../pipeline-run-client.js';

describe('PipelineRunClient — fileList passthrough', () => {
  let client: PipelineRunClient;

  beforeEach(() => {
    client = new PipelineRunClient({
      apiUrl: 'https://api.rsolv.dev',
      apiKey: 'test-key-123',
    });
    vi.restoreAllMocks();
  });

  it('sends files_scanned in the request body when fileList is provided', async () => {
    const mockResponse = {
      pipeline_run_id: 'run-uuid-filelist',
      issues: [{ issue_number: 1, cwe_id: 'CWE-89', phase: 'scan_detected' }],
    };

    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce({
      ok: true,
      json: async () => mockResponse,
    } as Response);

    await client.createRun({
      commitSha: 'abc123',
      branch: 'main',
      mode: 'scan',
      namespace: 'arubis/nodegoat-vulnerability-demo',
      createdIssues: [{ issue_number: 1, cwe_id: 'CWE-89' }],
      fileList: [
        'src/app.js',
        'src/routes/index.js',
        'test/security.test.js',
        'test/unit/auth.test.js',
      ],
    });

    // Verify the fetch body includes files_scanned
    const fetchCall = vi.mocked(fetch).mock.calls[0];
    const body = JSON.parse(fetchCall[1]!.body as string);

    expect(body.files_scanned).toEqual([
      'src/app.js',
      'src/routes/index.js',
      'test/security.test.js',
      'test/unit/auth.test.js',
    ]);
  });

  it('sends empty array for files_scanned when fileList is undefined', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce({
      ok: true,
      json: async () => ({ pipeline_run_id: 'run-uuid', issues: [] }),
    } as Response);

    await client.createRun({
      commitSha: 'abc123',
      mode: 'scan',
      namespace: 'test/repo',
      createdIssues: [],
    });

    const fetchCall = vi.mocked(fetch).mock.calls[0];
    const body = JSON.parse(fetchCall[1]!.body as string);

    expect(body.files_scanned).toEqual([]);
  });
});
