/**
 * RED TESTS — MitigationClient (RFC-096 Phase B)
 *
 * Tests the thin MITIGATE client that uses PipelineClient and ToolExecutors
 * to run mitigation via the backend-orchestrated pipeline.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import type { PipelineClientConfig, SSEEvent, ToolRequest } from '../types.js';

// Mock child_process for git operations
vi.mock('child_process', () => ({
  execSync: vi.fn().mockReturnValue(''),
}));

// Mock fs for tool executors
vi.mock('fs', () => ({
  readFileSync: vi.fn().mockReturnValue('file content'),
  writeFileSync: vi.fn(),
  mkdirSync: vi.fn(),
  existsSync: vi.fn().mockReturnValue(true),
}));

// Mock fetch globally for PipelineClient
const mockFetch = vi.fn();
vi.stubGlobal('fetch', mockFetch);

// Import after mocks are set up
import { MitigationClient, MitigationContext, MitigationResult } from '../mitigation-client.js';
import { execSync } from 'child_process';

describe('MitigationClient', () => {
  let client: MitigationClient;
  const config: PipelineClientConfig = {
    baseUrl: 'https://api.rsolv.dev',
    apiKey: 'rsolv_test_key_123',
  };

  const context: MitigationContext = {
    issue: {
      title: 'CWE-89: SQL Injection',
      body: 'Login endpoint is vulnerable to SQLi',
      number: 42,
    },
    analysis: {
      summary: 'Unsanitized input',
      complexity: 'low',
    },
    repoPath: '/tmp/test-repo',
    namespace: 'test-org',
  };

  beforeEach(() => {
    vi.clearAllMocks();
    // Use very short reconnection delays and fewer retries for tests
    client = new MitigationClient(config, { reconnectBaseDelayMs: 10, maxReconnects: 1 });
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('constructor', () => {
    it('creates a MitigationClient with config', () => {
      expect(client).toBeInstanceOf(MitigationClient);
    });
  });

  describe('runMitigation', () => {
    it('starts a session with phase=mitigation', async () => {
      // Mock start session
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({
          session_id: 'sess_m_abc123',
          stream_url: '/api/v1/mitigation/stream/sess_m_abc123',
        }),
      });

      // Mock SSE stream that completes immediately
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        headers: new Map([['content-type', 'text/event-stream']]),
        body: createSSEStream([
          { type: 'complete', id: 1, data: { success: true, title: 'Fixed', description: 'Done', files_mentioned: [] } },
        ]),
      });

      const result = await client.runMitigation(context);

      // Verify start session was called with correct params
      expect(mockFetch).toHaveBeenCalledWith(
        'https://api.rsolv.dev/api/v1/mitigation/start',
        expect.objectContaining({
          method: 'POST',
          headers: expect.objectContaining({
            'x-api-key': 'rsolv_test_key_123',
          }),
        })
      );
    });

    it('dispatches tool_request events to correct executors', async () => {
      // Mock start session
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({
          session_id: 'sess_m_abc123',
          stream_url: '/api/v1/mitigation/stream/sess_m_abc123',
        }),
      });

      // Mock SSE stream with a read_file tool request, then complete
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        headers: new Map([['content-type', 'text/event-stream']]),
        body: createSSEStream([
          {
            type: 'tool_request',
            id: 1,
            data: { id: 'req_1', tool: 'read_file', input: { path: '/app/server.js' } },
          },
          { type: 'complete', id: 2, data: { success: true, title: 'Fixed', description: 'Done', files_mentioned: [] } },
        ]),
      });

      // Mock tool_response submission
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({ success: true }),
      });

      const result = await client.runMitigation(context);

      // Verify tool_response was submitted
      expect(mockFetch).toHaveBeenCalledWith(
        'https://api.rsolv.dev/api/v1/mitigation/tool_response/sess_m_abc123',
        expect.objectContaining({
          method: 'POST',
          body: expect.stringContaining('req_1'),
        })
      );
    });

    it('creates git commit and returns result on complete', async () => {
      // Mock: no modified files
      vi.mocked(execSync)
        .mockReturnValueOnce('') // git config user.name check
        .mockReturnValueOnce('') // git diff --name-only (no files)
      ;

      // Mock start session
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({
          session_id: 'sess_m_abc123',
          stream_url: '/api/v1/mitigation/stream/sess_m_abc123',
        }),
      });

      // Mock SSE stream with immediate complete
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        headers: new Map([['content-type', 'text/event-stream']]),
        body: createSSEStream([
          { type: 'complete', id: 1, data: { success: true, title: 'Fixed SQLi', description: 'Done', files_mentioned: ['/app/server.js'] } },
        ]),
      });

      const result = await client.runMitigation(context);

      expect(result).toBeDefined();
      expect(result.success).toBe(true);
      expect(result.title).toBe('Fixed SQLi');
    });

    it('returns failure result on error event', async () => {
      // Mock start session
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({
          session_id: 'sess_m_abc123',
          stream_url: '/api/v1/mitigation/stream/sess_m_abc123',
        }),
      });

      // Mock SSE stream with error
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        headers: new Map([['content-type', 'text/event-stream']]),
        body: createSSEStream([
          { type: 'error', id: 1, data: { error: 'api_error: timeout' } },
        ]),
      });

      const result = await client.runMitigation(context);

      expect(result.success).toBe(false);
      expect(result.error).toContain('api_error');
    });

    it('handles no-files-modified scenario', async () => {
      // Mock start session
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({
          session_id: 'sess_m_abc123',
          stream_url: '/api/v1/mitigation/stream/sess_m_abc123',
        }),
      });

      // Mock SSE stream with complete (success but no files)
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        headers: new Map([['content-type', 'text/event-stream']]),
        body: createSSEStream([
          { type: 'complete', id: 1, data: { success: true, title: 'Fixed', description: 'Done', files_mentioned: [] } },
        ]),
      });

      const result = await client.runMitigation(context);

      // Should still succeed (the backend orchestrator decided it was done)
      expect(result.success).toBe(true);
    });

    it('includes validation_data in start params when present', async () => {
      const contextWithTests: MitigationContext = {
        ...context,
        validationData: {
          red_test: {
            test_path: 'test/test_auth.py',
            test_code: 'def test_sqli(): assert ...',
            framework: 'pytest',
            test_command: 'python -m pytest test/test_auth.py',
          },
        },
      };

      // Mock start session
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({
          session_id: 'sess_m_abc123',
          stream_url: '/api/v1/mitigation/stream/sess_m_abc123',
        }),
      });

      // Mock SSE stream with immediate complete
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        headers: new Map([['content-type', 'text/event-stream']]),
        body: createSSEStream([
          { type: 'complete', id: 1, data: { success: true, title: 'Fixed', description: 'Done', files_mentioned: [] } },
        ]),
      });

      await client.runMitigation(contextWithTests);

      // Verify start session included validation_data
      const startCall = mockFetch.mock.calls[0];
      const body = JSON.parse(startCall[1].body);
      expect(body.context.validation_data).toBeDefined();
      expect(body.context.validation_data.red_test.framework).toBe('pytest');
    });

    it('handles SSE stream disconnect gracefully with reconnection', async () => {
      // Mock start session
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({
          session_id: 'sess_m_abc123',
          stream_url: '/api/v1/mitigation/stream/sess_m_abc123',
        }),
      });

      // attempt 0: SSE stream closes abruptly (empty stream)
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        headers: new Map([['content-type', 'text/event-stream']]),
        body: createSSEStream([]),
      });

      // attempt 1: status check → still streaming
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({
          session_id: 'sess_m_abc123',
          status: 'streaming',
          phase: 'mitigation',
          event_counter: 0,
          pending_tools: 0,
        }),
      });

      // attempt 1: SSE reconnect also closes (exhaust maxReconnects=1)
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        headers: new Map([['content-type', 'text/event-stream']]),
        body: createSSEStream([]),
      });

      const result = await client.runMitigation(context);

      // Should return failure after exhausting reconnection attempts
      expect(result.success).toBe(false);
      expect(result.error).toContain('reconnect');
    });

    it('handles start session failure', async () => {
      // Mock start session failure
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 500,
        statusText: 'Internal Server Error',
        json: async () => ({ error: 'session creation failed' }),
      });

      const result = await client.runMitigation(context);

      expect(result.success).toBe(false);
      expect(result.error).toContain('session');
    });

    it('dispatches bash tool_request to executeBash', async () => {
      // Mock start session
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({
          session_id: 'sess_m_abc123',
          stream_url: '/api/v1/mitigation/stream/sess_m_abc123',
        }),
      });

      // Mock SSE stream with bash tool request
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        headers: new Map([['content-type', 'text/event-stream']]),
        body: createSSEStream([
          {
            type: 'tool_request',
            id: 1,
            data: { id: 'req_bash', tool: 'bash', input: { command: 'python -m pytest' } },
          },
          { type: 'complete', id: 2, data: { success: true, title: 'Fixed', description: 'Done', files_mentioned: [] } },
        ]),
      });

      // Mock tool_response submission
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({ success: true }),
      });

      // Mock execSync for bash tool execution (called by executeBash)
      vi.mocked(execSync).mockReturnValueOnce(Buffer.from('PASSED'));

      const result = await client.runMitigation(context);

      // Verify tool_response was submitted for the bash request
      const toolResponseCall = mockFetch.mock.calls.find(
        (call) => typeof call[0] === 'string' && call[0].includes('tool_response')
      );
      expect(toolResponseCall).toBeDefined();
    });

    it('handles multiple sequential tool requests', async () => {
      // Mock start session
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({
          session_id: 'sess_m_abc123',
          stream_url: '/api/v1/mitigation/stream/sess_m_abc123',
        }),
      });

      // Mock SSE stream with multiple tool requests
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        headers: new Map([['content-type', 'text/event-stream']]),
        body: createSSEStream([
          {
            type: 'tool_request',
            id: 1,
            data: { id: 'req_1', tool: 'read_file', input: { path: '/app/a.js' } },
          },
          {
            type: 'tool_request',
            id: 2,
            data: { id: 'req_2', tool: 'edit_file', input: { path: '/app/a.js', old_string: 'old', new_string: 'new' } },
          },
          { type: 'complete', id: 3, data: { success: true, title: 'Fixed', description: 'Done', files_mentioned: [] } },
        ]),
      });

      // Mock tool_response submissions (one per tool request)
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({ success: true }),
      });
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({ success: true }),
      });

      const result = await client.runMitigation(context);

      // Verify both tool responses were submitted
      const toolResponseCalls = mockFetch.mock.calls.filter(
        (call) => typeof call[0] === 'string' && call[0].includes('tool_response')
      );
      expect(toolResponseCalls.length).toBe(2);
    });
  });
});

// Helper: Create a ReadableStream that emits SSE events in real platform format.
// The platform sends: event: <type>\nid: <N>\ndata: <json_payload>\n\n
// where the data line is the raw payload (NOT wrapped with type/id).
function createSSEStream(events: SSEEvent[]): ReadableStream<Uint8Array> {
  const encoder = new TextEncoder();
  let index = 0;

  return new ReadableStream({
    pull(controller) {
      if (index < events.length) {
        const event = events[index++];
        const dataJson = event.data != null ? JSON.stringify(event.data) : '';
        let sseChunk = `event: ${event.type}\nid: ${event.id}\n`;
        if (dataJson) {
          sseChunk += `data: ${dataJson}\n`;
        }
        sseChunk += '\n';
        controller.enqueue(encoder.encode(sseChunk));
      } else {
        controller.close();
      }
    },
  });
}
