import { describe, it, expect, vi, beforeEach } from 'vitest';
import {
  PipelineRunChannel,
  type PipelineRunChannelConfig,
  type DetectedIssue,
} from '../pipeline-run-channel.js';

// Mock WebSocket
class MockWebSocket {
  static OPEN = 1;
  static instances: MockWebSocket[] = [];

  url: string;
  readyState = MockWebSocket.OPEN;
  onopen: (() => void) | null = null;
  onerror: ((event: unknown) => void) | null = null;
  onmessage: ((event: { data: string }) => void) | null = null;
  onclose: (() => void) | null = null;
  sentMessages: unknown[] = [];

  constructor(url: string) {
    this.url = url;
    MockWebSocket.instances.push(this);
    // Simulate connection success
    setTimeout(() => this.onopen?.(), 0);
  }

  send(data: string): void {
    this.sentMessages.push(JSON.parse(data));
  }

  close(): void {
    this.readyState = 3;
    this.onclose?.();
  }

  // Test helper: simulate server sending a message
  simulateMessage(message: unknown[]): void {
    this.onmessage?.({ data: JSON.stringify(message) });
  }

  // Test helper: simulate phx_reply
  simulateReply(ref: string, status: string, response: unknown): void {
    this.simulateMessage([null, ref, 'pipeline_run:test', 'phx_reply', { status, response }]);
  }
}

// Replace global WebSocket
vi.stubGlobal('WebSocket', MockWebSocket);

describe('PipelineRunChannel', () => {
  let config: PipelineRunChannelConfig;
  let channel: PipelineRunChannel;

  beforeEach(() => {
    MockWebSocket.instances = [];
    config = {
      wsUrl: 'wss://api.rsolv.dev/action/websocket',
      apiKey: 'rsolv_test_key_123',
      onValidate: vi.fn(),
      onMitigate: vi.fn(),
      onComplete: vi.fn(),
      onStatusChange: vi.fn(),
    };
    channel = new PipelineRunChannel(config);
  });

  describe('connect', () => {
    it('connects to WebSocket with API key', async () => {
      await channel.connect();

      expect(MockWebSocket.instances).toHaveLength(1);
      expect(MockWebSocket.instances[0].url).toContain('api_key=rsolv_test_key_123');
      expect(channel.isConnected()).toBe(true);
    });
  });

  describe('createRun', () => {
    it('joins channel and receives run ID', async () => {
      await channel.connect();
      const ws = MockWebSocket.instances[0];

      // Start createRun (it sends a phx_join message)
      const promise = channel.createRun({
        commitSha: 'abc123',
        mode: 'full',
        maxIssues: 3,
      });

      // Wait for the join message to be sent
      await vi.waitFor(() => {
        expect(ws.sentMessages.length).toBeGreaterThan(0);
      });

      // The join message should be [joinRef, ref, topic, "phx_join", payload]
      const joinMsg = ws.sentMessages[0] as unknown[];
      expect(joinMsg[3]).toBe('phx_join');
      expect((joinMsg[4] as Record<string, unknown>).action).toBe('create');
      expect((joinMsg[4] as Record<string, unknown>).commit_sha).toBe('abc123');

      // Simulate server reply
      const ref = joinMsg[1] as string;
      ws.simulateReply(ref, 'ok', { run_id: 'test-run-id', status: 'pending' });

      const result = await promise;
      expect(result.runId).toBe('test-run-id');
    });
  });

  describe('registerIssues', () => {
    it('sends issues to channel', async () => {
      await channel.connect();
      const ws = MockWebSocket.instances[0];

      // Join first
      const createPromise = channel.createRun({ commitSha: 'abc123', mode: 'full' });
      await vi.waitFor(() => expect(ws.sentMessages.length).toBeGreaterThan(0));
      const joinRef = (ws.sentMessages[0] as unknown[])[1] as string;
      ws.simulateReply(joinRef, 'ok', { run_id: 'test-run', status: 'pending' });
      await createPromise;

      // Register issues
      const issues: DetectedIssue[] = [
        { issue_number: 1, cwe_id: 'CWE-79' },
        { issue_number: 2, cwe_id: 'CWE-89' },
      ];

      const registerPromise = channel.registerIssues(issues);
      await vi.waitFor(() => expect(ws.sentMessages.length).toBeGreaterThan(1));

      const registerMsg = ws.sentMessages[1] as unknown[];
      expect(registerMsg[3]).toBe('register_issues');
      expect((registerMsg[4] as Record<string, unknown>).issues).toEqual(issues);

      const ref = registerMsg[1] as string;
      ws.simulateReply(ref, 'ok', {});
      await registerPromise;
    });
  });

  describe('server pushes', () => {
    it('onValidate receives validate push events', async () => {
      await channel.connect();
      const ws = MockWebSocket.instances[0];

      // Join
      const createPromise = channel.createRun({ commitSha: 'abc123', mode: 'full' });
      await vi.waitFor(() => expect(ws.sentMessages.length).toBeGreaterThan(0));
      ws.simulateReply((ws.sentMessages[0] as unknown[])[1] as string, 'ok', { run_id: 'r1' });
      await createPromise;

      // Simulate server push: validate
      ws.simulateMessage([null, null, 'pipeline_run:r1', 'validate', {
        issues: [{ issue_number: 1, cwe_id: 'CWE-79' }],
      }]);

      expect(config.onValidate).toHaveBeenCalledWith([{ issue_number: 1, cwe_id: 'CWE-79' }]);
    });

    it('onMitigate receives mitigate push events', async () => {
      await channel.connect();
      const ws = MockWebSocket.instances[0];

      const createPromise = channel.createRun({ commitSha: 'abc123', mode: 'full' });
      await vi.waitFor(() => expect(ws.sentMessages.length).toBeGreaterThan(0));
      ws.simulateReply((ws.sentMessages[0] as unknown[])[1] as string, 'ok', { run_id: 'r1' });
      await createPromise;

      ws.simulateMessage([null, null, 'pipeline_run:r1', 'mitigate', {
        issues: [{ issue_number: 1 }],
      }]);

      expect(config.onMitigate).toHaveBeenCalledWith([{ issue_number: 1 }]);
    });

    it('onComplete receives complete event', async () => {
      await channel.connect();
      const ws = MockWebSocket.instances[0];

      const createPromise = channel.createRun({ commitSha: 'abc123', mode: 'full' });
      await vi.waitFor(() => expect(ws.sentMessages.length).toBeGreaterThan(0));
      ws.simulateReply((ws.sentMessages[0] as unknown[])[1] as string, 'ok', { run_id: 'r1' });
      await createPromise;

      ws.simulateMessage([null, null, 'pipeline_run:r1', 'complete', {
        run_id: 'r1',
        status: 'completed',
      }]);

      expect(config.onComplete).toHaveBeenCalledWith({ run_id: 'r1', status: 'completed' });
    });

    it('onStatusChange receives status updates', async () => {
      await channel.connect();
      const ws = MockWebSocket.instances[0];

      const createPromise = channel.createRun({ commitSha: 'abc123', mode: 'full' });
      await vi.waitFor(() => expect(ws.sentMessages.length).toBeGreaterThan(0));
      ws.simulateReply((ws.sentMessages[0] as unknown[])[1] as string, 'ok', { run_id: 'r1' });
      await createPromise;

      ws.simulateMessage([null, null, 'pipeline_run:r1', 'status_change', {
        status: 'validating',
      }]);

      expect(config.onStatusChange).toHaveBeenCalledWith('validating');
    });
  });

  describe('disconnect', () => {
    it('closes WebSocket connection', async () => {
      await channel.connect();
      expect(channel.isConnected()).toBe(true);

      channel.disconnect();
      expect(channel.isConnected()).toBe(false);
    });
  });

  describe('reconnect', () => {
    it('reconnects to existing run', async () => {
      await channel.connect();
      const ws = MockWebSocket.instances[0];

      const reconnectPromise = channel.reconnect('existing-run-id');
      await vi.waitFor(() => expect(ws.sentMessages.length).toBeGreaterThan(0));

      const joinMsg = ws.sentMessages[0] as unknown[];
      expect(joinMsg[2]).toBe('pipeline_run:existing-run-id');
      expect(joinMsg[3]).toBe('phx_join');

      ws.simulateReply(joinMsg[1] as string, 'ok', { status: 'validating' });
      const result = await reconnectPromise;
      expect(result.status).toBe('validating');
    });
  });
});
