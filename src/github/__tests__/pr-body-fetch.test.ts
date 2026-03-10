import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { PipelineRunClient } from '../../pipeline/pipeline-run-client.js';

describe('PipelineRunClient.fetchPrBody', () => {
  let client: PipelineRunClient;
  const originalFetch = global.fetch;

  beforeEach(() => {
    client = new PipelineRunClient({
      apiUrl: 'https://api.example.com',
      apiKey: 'test-key',
    });
  });

  afterEach(() => {
    global.fetch = originalFetch;
  });

  it('returns pr_body on success', async () => {
    const mockBody = '## Security Fix Summary\nTest body';
    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ pr_body: mockBody }),
    });

    const result = await client.fetchPrBody('run-123', 42);
    expect(result).toBe(mockBody);

    expect(global.fetch).toHaveBeenCalledWith(
      'https://api.example.com/api/v1/pipeline-runs/run-123/issues/42/pr-body',
      expect.objectContaining({
        method: 'GET',
        headers: { 'x-api-key': 'test-key' },
      })
    );
  });

  it('returns null on HTTP error', async () => {
    global.fetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 404,
    });

    const result = await client.fetchPrBody('run-123', 42);
    expect(result).toBeNull();
  });

  it('returns null on network error', async () => {
    global.fetch = vi.fn().mockRejectedValue(new Error('Network error'));

    const result = await client.fetchPrBody('run-123', 42);
    expect(result).toBeNull();
  });

  it('returns null when pr_body is empty string', async () => {
    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ pr_body: '' }),
    });

    const result = await client.fetchPrBody('run-123', 42);
    expect(result).toBeNull();
  });

  it('returns null when response has no pr_body field', async () => {
    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ other_field: 'value' }),
    });

    const result = await client.fetchPrBody('run-123', 42);
    expect(result).toBeNull();
  });
});
