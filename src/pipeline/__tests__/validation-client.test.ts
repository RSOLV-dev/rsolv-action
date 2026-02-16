/**
 * RED TESTS — ValidationClient (RFC-096 Phase C)
 *
 * Tests the thin VALIDATE client that uses PipelineClient and ToolExecutors
 * to run validation via the backend-orchestrated pipeline.
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
import { ValidationClient, ValidationContext, ValidationResult } from '../validation-client.js';

describe('ValidationClient', () => {
  let client: ValidationClient;
  const config: PipelineClientConfig = {
    baseUrl: 'https://api.rsolv.dev',
    apiKey: 'rsolv_test_key_123',
  };

  const context: ValidationContext = {
    vulnerability: {
      type: 'CWE-89',
      description: 'SQL injection in login endpoint',
      location: 'app/controllers/auth_controller.rb:42',
      attack_vector: 'User-supplied username parameter',
      source: 'app/controllers/auth_controller.rb',
    },
    framework: {
      name: 'rspec',
      test_command: 'bundle exec rspec',
    },
    cwe_id: 'CWE-89',
    namespace: 'test-org',
    repo: 'test-org/test-repo',
    repoPath: '/tmp/test-repo',
  };

  beforeEach(() => {
    vi.clearAllMocks();
    client = new ValidationClient(config);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('constructor', () => {
    it('creates a ValidationClient with config', () => {
      expect(client).toBeInstanceOf(ValidationClient);
    });
  });

  describe('runValidation', () => {
    it('starts a session with phase=validation', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({
          session_id: 'sess_v_abc123',
          stream_url: '/api/v1/validation/stream/sess_v_abc123',
        }),
      });

      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        headers: new Map([['content-type', 'text/event-stream']]),
        body: createSSEStream([
          { type: 'complete', id: 1, data: { validated: true, test_path: 'spec/auth_spec.rb', test_code: 'test code', framework: 'rspec', cwe_id: 'CWE-89' } },
        ]),
      });

      await client.runValidation(context);

      expect(mockFetch).toHaveBeenCalledWith(
        'https://api.rsolv.dev/api/v1/validation/start',
        expect.objectContaining({
          method: 'POST',
          headers: expect.objectContaining({
            'x-api-key': 'rsolv_test_key_123',
          }),
        })
      );
    });

    it('dispatches tool_request events to correct executors', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({
          session_id: 'sess_v_abc123',
          stream_url: '/api/v1/validation/stream/sess_v_abc123',
        }),
      });

      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        headers: new Map([['content-type', 'text/event-stream']]),
        body: createSSEStream([
          {
            type: 'tool_request',
            id: 1,
            data: { id: 'req_1', tool: 'glob', input: { pattern: 'spec/**/*_spec.rb' } },
          },
          { type: 'complete', id: 2, data: { validated: true, test_path: 'spec/auth_spec.rb', test_code: 'test', framework: 'rspec', cwe_id: 'CWE-89' } },
        ]),
      });

      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({ success: true }),
      });

      await client.runValidation(context);

      expect(mockFetch).toHaveBeenCalledWith(
        'https://api.rsolv.dev/api/v1/validation/tool_response/sess_v_abc123',
        expect.objectContaining({
          method: 'POST',
          body: expect.stringContaining('req_1'),
        })
      );
    });

    it('returns validated=true with test metadata on complete', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({
          session_id: 'sess_v_abc123',
          stream_url: '/api/v1/validation/stream/sess_v_abc123',
        }),
      });

      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        headers: new Map([['content-type', 'text/event-stream']]),
        body: createSSEStream([
          {
            type: 'complete',
            id: 1,
            data: {
              validated: true,
              test_path: 'spec/controllers/auth_sqli_spec.rb',
              test_code: 'describe AuthController do ... end',
              framework: 'rspec',
              cwe_id: 'CWE-89',
            },
          },
        ]),
      });

      const result = await client.runValidation(context);

      expect(result.validated).toBe(true);
      expect(result.test_path).toBe('spec/controllers/auth_sqli_spec.rb');
      expect(result.test_code).toBe('describe AuthController do ... end');
      expect(result.framework).toBe('rspec');
      expect(result.cwe_id).toBe('CWE-89');
    });

    it('returns validated=false on error event', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({
          session_id: 'sess_v_abc123',
          stream_url: '/api/v1/validation/stream/sess_v_abc123',
        }),
      });

      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        headers: new Map([['content-type', 'text/event-stream']]),
        body: createSSEStream([
          { type: 'error', id: 1, data: { error: 'api_error: timeout' } },
        ]),
      });

      const result = await client.runValidation(context);

      expect(result.validated).toBe(false);
      expect(result.error).toContain('api_error');
    });

    it('handles start session failure', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 500,
        statusText: 'Internal Server Error',
        json: async () => ({ error: 'session creation failed' }),
      });

      const result = await client.runValidation(context);

      expect(result.validated).toBe(false);
      expect(result.error).toContain('session');
    });

    it('handles SSE stream disconnect gracefully', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({
          session_id: 'sess_v_abc123',
          stream_url: '/api/v1/validation/stream/sess_v_abc123',
        }),
      });

      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        headers: new Map([['content-type', 'text/event-stream']]),
        body: createSSEStream([]),
      });

      const result = await client.runValidation(context);

      expect(result.validated).toBe(false);
      expect(result.error).toBeDefined();
    });

    it('sends repo in session context for platform enrichment', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({
          session_id: 'sess_v_abc123',
          stream_url: '/api/v1/validation/stream/sess_v_abc123',
        }),
      });

      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        headers: new Map([['content-type', 'text/event-stream']]),
        body: createSSEStream([
          { type: 'complete', id: 1, data: { validated: false } },
        ]),
      });

      await client.runValidation(context);

      const startCall = mockFetch.mock.calls[0];
      const body = JSON.parse(startCall[1].body);
      expect(body.context.repo).toBe('test-org/test-repo');
    });

    it('omits framework from session context when not provided', async () => {
      const minimalContext: ValidationContext = {
        vulnerability: { type: 'CWE-89', description: 'SQL injection' },
        cwe_id: 'CWE-89',
        namespace: 'test-org',
        repo: 'test-org/test-repo',
        repoPath: '/tmp/test-repo',
      };

      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({
          session_id: 'sess_v_abc123',
          stream_url: '/api/v1/validation/stream/sess_v_abc123',
        }),
      });

      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        headers: new Map([['content-type', 'text/event-stream']]),
        body: createSSEStream([
          { type: 'complete', id: 1, data: { validated: false } },
        ]),
      });

      await client.runValidation(minimalContext);

      const startCall = mockFetch.mock.calls[0];
      const body = JSON.parse(startCall[1].body);
      expect(body.context.framework).toBeUndefined();
      expect(body.context.repo).toBe('test-org/test-repo');
    });

    it('includes project_shape in start context when provided', async () => {
      const contextWithShape: ValidationContext = {
        ...context,
        project_shape: {
          ecosystem: 'ruby',
          runtime_version: '3.2.0',
          framework_versions: { rails: '7.1.0' },
        },
      };

      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({
          session_id: 'sess_v_abc123',
          stream_url: '/api/v1/validation/stream/sess_v_abc123',
        }),
      });

      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        headers: new Map([['content-type', 'text/event-stream']]),
        body: createSSEStream([
          { type: 'complete', id: 1, data: { validated: false } },
        ]),
      });

      await client.runValidation(contextWithShape);

      const startCall = mockFetch.mock.calls[0];
      const body = JSON.parse(startCall[1].body);
      expect(body.context.project_shape).toBeDefined();
      expect(body.context.project_shape.ecosystem).toBe('ruby');
    });

    it('dispatches bash tool_request for test execution', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({
          session_id: 'sess_v_abc123',
          stream_url: '/api/v1/validation/stream/sess_v_abc123',
        }),
      });

      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        headers: new Map([['content-type', 'text/event-stream']]),
        body: createSSEStream([
          {
            type: 'tool_request',
            id: 1,
            data: { id: 'req_bash', tool: 'bash', input: { command: 'bundle exec rspec spec/auth_spec.rb' } },
          },
          { type: 'complete', id: 2, data: { validated: true, test_path: 'spec/auth_spec.rb', test_code: 'test', framework: 'rspec', cwe_id: 'CWE-89' } },
        ]),
      });

      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({ success: true }),
      });

      await client.runValidation(context);

      const toolResponseCall = mockFetch.mock.calls.find(
        (call) => typeof call[0] === 'string' && call[0].includes('tool_response')
      );
      expect(toolResponseCall).toBeDefined();
    });

    it('dispatches write_file for test creation', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({
          session_id: 'sess_v_abc123',
          stream_url: '/api/v1/validation/stream/sess_v_abc123',
        }),
      });

      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        headers: new Map([['content-type', 'text/event-stream']]),
        body: createSSEStream([
          {
            type: 'tool_request',
            id: 1,
            data: { id: 'req_write', tool: 'write_file', input: { path: 'spec/auth_spec.rb', content: 'test code' } },
          },
          { type: 'complete', id: 2, data: { validated: true, test_path: 'spec/auth_spec.rb', test_code: 'test code', framework: 'rspec', cwe_id: 'CWE-89' } },
        ]),
      });

      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({ success: true }),
      });

      await client.runValidation(context);

      const toolResponseCall = mockFetch.mock.calls.find(
        (call) => typeof call[0] === 'string' && call[0].includes('tool_response')
      );
      expect(toolResponseCall).toBeDefined();
      if (toolResponseCall) {
        const body = JSON.parse(toolResponseCall[1].body);
        expect(body.request_id).toBe('req_write');
      }
    });

    it('extracts classification fields from complete event', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({
          session_id: 'sess_v_abc123',
          stream_url: '/api/v1/validation/stream/sess_v_abc123',
        }),
      });

      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        headers: new Map([['content-type', 'text/event-stream']]),
        body: createSSEStream([
          {
            type: 'complete',
            id: 1,
            data: {
              validated: true,
              test_path: 'spec/auth_spec.rb',
              test_code: 'test code',
              framework: 'rspec',
              cwe_id: 'CWE-89',
              classification: 'validated',
              test_type: 'behavioral',
              retry_count: 3,
            },
          },
        ]),
      });

      const result = await client.runValidation(context);

      expect(result.validated).toBe(true);
      expect(result.classification).toBe('validated');
      expect(result.test_type).toBe('behavioral');
      expect(result.retry_count).toBe(3);
    });

    it('handles classification fields for false positive', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({
          session_id: 'sess_v_abc123',
          stream_url: '/api/v1/validation/stream/sess_v_abc123',
        }),
      });

      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        headers: new Map([['content-type', 'text/event-stream']]),
        body: createSSEStream([
          {
            type: 'complete',
            id: 1,
            data: {
              validated: false,
              classification: 'false_positive',
              test_type: 'behavioral',
              retry_count: 2,
            },
          },
        ]),
      });

      const result = await client.runValidation(context);

      expect(result.validated).toBe(false);
      expect(result.classification).toBe('false_positive');
      expect(result.test_type).toBe('behavioral');
      expect(result.retry_count).toBe(2);
    });

    it('defaults classification fields to undefined when not present', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({
          session_id: 'sess_v_abc123',
          stream_url: '/api/v1/validation/stream/sess_v_abc123',
        }),
      });

      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        headers: new Map([['content-type', 'text/event-stream']]),
        body: createSSEStream([
          {
            type: 'complete',
            id: 1,
            data: {
              validated: true,
              test_path: 'spec/auth_spec.rb',
            },
          },
        ]),
      });

      const result = await client.runValidation(context);

      expect(result.validated).toBe(true);
      expect(result.classification).toBeUndefined();
      expect(result.test_type).toBeUndefined();
      expect(result.retry_count).toBeUndefined();
    });

    it('handles multiple sequential tool requests', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({
          session_id: 'sess_v_abc123',
          stream_url: '/api/v1/validation/stream/sess_v_abc123',
        }),
      });

      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        headers: new Map([['content-type', 'text/event-stream']]),
        body: createSSEStream([
          {
            type: 'tool_request',
            id: 1,
            data: { id: 'req_1', tool: 'glob', input: { pattern: 'spec/**/*_spec.rb' } },
          },
          {
            type: 'tool_request',
            id: 2,
            data: { id: 'req_2', tool: 'read_file', input: { path: 'spec/users_spec.rb' } },
          },
          {
            type: 'tool_request',
            id: 3,
            data: { id: 'req_3', tool: 'write_file', input: { path: 'spec/auth_spec.rb', content: 'test' } },
          },
          { type: 'complete', id: 4, data: { validated: true, test_path: 'spec/auth_spec.rb', test_code: 'test', framework: 'rspec', cwe_id: 'CWE-89' } },
        ]),
      });

      // Mock tool_response submissions
      mockFetch.mockResolvedValueOnce({ ok: true, status: 200, json: async () => ({ success: true }) });
      mockFetch.mockResolvedValueOnce({ ok: true, status: 200, json: async () => ({ success: true }) });
      mockFetch.mockResolvedValueOnce({ ok: true, status: 200, json: async () => ({ success: true }) });

      const result = await client.runValidation(context);

      const toolResponseCalls = mockFetch.mock.calls.filter(
        (call) => typeof call[0] === 'string' && call[0].includes('tool_response')
      );
      expect(toolResponseCalls.length).toBe(3);
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
