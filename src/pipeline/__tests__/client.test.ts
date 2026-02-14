/**
 * RED TESTS — PipelineClient (RFC-096 Phase A)
 *
 * Tests the thin SSE consumer that connects the GitHub Action
 * to the backend-orchestrated pipeline.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { PipelineClient } from '../client.js';
import type { SessionStartParams, SessionStartResponse, ToolRequest } from '../types.js';

// Mock fetch globally
const mockFetch = vi.fn();
vi.stubGlobal('fetch', mockFetch);

describe('PipelineClient', () => {
  let client: PipelineClient;

  beforeEach(() => {
    vi.clearAllMocks();
    client = new PipelineClient({
      baseUrl: 'https://api.rsolv.dev',
      apiKey: 'rsolv_test_key_123',
    });
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('startSession', () => {
    it('POSTs to /api/v1/{phase}/start with params', async () => {
      const mockResponse: SessionStartResponse = {
        session_id: 'sess_v_abc123',
        stream_url: '/api/v1/validation/stream/sess_v_abc123',
      };

      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => mockResponse,
      });

      const params: SessionStartParams = {
        phase: 'validation',
        namespace: 'RSOLV-dev',
        context: { repo: 'RSOLV-dev/nodegoat', issue_number: 42 },
      };

      const result = await client.startSession(params);

      expect(mockFetch).toHaveBeenCalledWith(
        'https://api.rsolv.dev/api/v1/validation/start',
        expect.objectContaining({
          method: 'POST',
          headers: expect.objectContaining({
            'Content-Type': 'application/json',
            'x-api-key': 'rsolv_test_key_123',
          }),
        })
      );

      expect(result.session_id).toBe('sess_v_abc123');
      expect(result.stream_url).toContain('stream');
    });

    it('returns session_id and stream_url', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({
          session_id: 'sess_m_def456',
          stream_url: '/api/v1/mitigation/stream/sess_m_def456',
        }),
      });

      const result = await client.startSession({
        phase: 'mitigation',
        namespace: 'RSOLV-dev',
        context: {},
      });

      expect(result.session_id).toMatch(/^sess_m_/);
      expect(result.stream_url).toBeDefined();
    });

    it('throws on non-200 response', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 401,
        json: async () => ({ error: 'unauthorized' }),
        statusText: 'Unauthorized',
      });

      await expect(
        client.startSession({
          phase: 'validation',
          namespace: 'RSOLV-dev',
          context: {},
        })
      ).rejects.toThrow();
    });

    it('includes API key in x-api-key header', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({
          session_id: 'sess_v_test',
          stream_url: '/api/v1/validation/stream/sess_v_test',
        }),
      });

      await client.startSession({
        phase: 'validation',
        namespace: 'RSOLV-dev',
        context: {},
      });

      const [, options] = mockFetch.mock.calls[0];
      expect(options.headers['x-api-key']).toBe('rsolv_test_key_123');
    });
  });

  describe('submitToolResponse', () => {
    it('POSTs tool result to /api/v1/{phase}/tool_response/{id}', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({ success: true }),
      });

      await client.submitToolResponse(
        'validation',
        'sess_v_abc123',
        'req_001',
        { content: 'file contents' }
      );

      expect(mockFetch).toHaveBeenCalledWith(
        'https://api.rsolv.dev/api/v1/validation/tool_response/sess_v_abc123',
        expect.objectContaining({
          method: 'POST',
          headers: expect.objectContaining({
            'Content-Type': 'application/json',
            'x-api-key': 'rsolv_test_key_123',
          }),
        })
      );

      const [, options] = mockFetch.mock.calls[0];
      const body = JSON.parse(options.body);
      expect(body.request_id).toBe('req_001');
      expect(body.result.content).toBe('file contents');
    });

    it('throws on non-200 response', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 404,
        statusText: 'Not Found',
        json: async () => ({ error: 'session not found' }),
      });

      await expect(
        client.submitToolResponse('validation', 'sess_v_unknown', 'req_001', {})
      ).rejects.toThrow();
    });
  });

  describe('getSessionStatus', () => {
    it('GETs session status', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({
          session_id: 'sess_v_abc123',
          status: 'streaming',
          phase: 'validation',
        }),
      });

      const status = await client.getSessionStatus('validation', 'sess_v_abc123');

      expect(status.status).toBe('streaming');
      expect(mockFetch).toHaveBeenCalledWith(
        'https://api.rsolv.dev/api/v1/validation/status/sess_v_abc123',
        expect.objectContaining({
          method: 'GET',
          headers: expect.objectContaining({
            'x-api-key': 'rsolv_test_key_123',
          }),
        })
      );
    });
  });

  describe('cancelSession', () => {
    it('DELETEs the session', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({ success: true }),
      });

      await client.cancelSession('validation', 'sess_v_abc123');

      expect(mockFetch).toHaveBeenCalledWith(
        'https://api.rsolv.dev/api/v1/validation/sess_v_abc123',
        expect.objectContaining({
          method: 'DELETE',
          headers: expect.objectContaining({
            'x-api-key': 'rsolv_test_key_123',
          }),
        })
      );
    });
  });
});
