/**
 * MitigationClient — Thin MITIGATE client for RFC-096 Phase B.
 *
 * Uses PipelineClient to start a backend-orchestrated mitigation session,
 * consumes SSE events, dispatches tool_request events to local ToolExecutors,
 * and submits results back to the backend.
 *
 * The backend Orchestrator drives the agentic loop (API calls, tool selection,
 * fix generation). This client just executes tools and reports back.
 */

import { PipelineClient } from './client.js';
import {
  executeReadFile,
  executeWriteFile,
  executeEditFile,
  executeGlob,
  executeGrep,
  executeBash,
} from './tool-executors.js';
import type {
  PipelineClientConfig,
  ToolRequest,
  ToolName,
  SSEEvent,
} from './types.js';

export interface MitigationContext {
  issue: {
    title: string;
    body: string;
    number: number;
  };
  analysis: {
    summary: string;
    complexity: string;
    recommended_approach?: string;
    related_files?: string[];
  };
  repoPath: string;
  namespace: string;
  validationData?: {
    red_test?: {
      test_path: string;
      test_code: string;
      framework: string;
      test_command: string;
    };
  };
}

export interface MitigationResult {
  success: boolean;
  title?: string;
  description?: string;
  files_mentioned?: string[];
  error?: string;
}

type ToolExecutor = (input: Record<string, unknown>) => Promise<Record<string, unknown>>;

async function wrapExecutor<T>(fn: () => Promise<T>): Promise<Record<string, unknown>> {
  const result = await fn();
  return result as unknown as Record<string, unknown>;
}

const TOOL_DISPATCH: Record<ToolName, ToolExecutor> = {
  read_file: (input) => wrapExecutor(() => executeReadFile(input as { path: string })),
  write_file: (input) => wrapExecutor(() => executeWriteFile(input as { path: string; content: string })),
  edit_file: (input) =>
    wrapExecutor(() => executeEditFile(input as { path: string; old_string: string; new_string: string })),
  glob: (input) => wrapExecutor(() => executeGlob(input as { pattern: string; path?: string })),
  grep: (input) => wrapExecutor(() => executeGrep(input as { pattern: string; path?: string })),
  bash: (input) =>
    wrapExecutor(() => executeBash(input as { command: string; timeout_ms?: number; cwd?: string })),
};

export class MitigationClient {
  private client: PipelineClient;
  private config: PipelineClientConfig;
  private maxReconnects: number;
  private reconnectBaseDelayMs: number;

  constructor(config: PipelineClientConfig, options?: { maxReconnects?: number; reconnectBaseDelayMs?: number }) {
    this.config = config;
    this.client = new PipelineClient(config);
    this.maxReconnects = options?.maxReconnects ?? 5;
    this.reconnectBaseDelayMs = options?.reconnectBaseDelayMs ?? 2000;
  }

  /**
   * Runs a backend-orchestrated mitigation session.
   *
   * 1. POST /mitigation/start with issue context
   * 2. Connect SSE stream with automatic reconnection
   * 3. On tool_request: dispatch to local executor, POST tool_response
   * 4. On complete: return success result
   * 5. On error: return failure result
   * 6. On disconnect: check session status, reconnect if still active
   */
  async runMitigation(context: MitigationContext): Promise<MitigationResult> {
    let sessionId: string;

    // 1. Start session
    try {
      const startResponse = await this.client.startSession({
        phase: 'mitigation',
        namespace: context.namespace,
        context: this.buildSessionContext(context),
      });
      sessionId = startResponse.session_id;
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      return {
        success: false,
        error: `Failed to start mitigation session: ${message}`,
      };
    }

    // 2. Connect SSE stream with reconnection
    for (let attempt = 0; attempt <= this.maxReconnects; attempt++) {
      if (attempt > 0) {
        const statusResult = await this.checkSessionBeforeReconnect(sessionId);
        if (statusResult !== null) return statusResult;

        const delay = this.reconnectBaseDelayMs * Math.pow(2, attempt - 1);
        await new Promise(resolve => setTimeout(resolve, delay));
        console.log(`[MitigationClient] SSE reconnecting (attempt ${attempt}/${this.maxReconnects})...`);
      }

      try {
        const result = await this.connectSSEStream(sessionId);
        return result;
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        console.log(`[MitigationClient] SSE stream error (attempt ${attempt}/${this.maxReconnects}): ${message}`);
        if (attempt === this.maxReconnects) {
          return {
            success: false,
            error: `SSE stream failed after ${this.maxReconnects} reconnect attempts: ${message}`,
          };
        }
        continue;
      }
    }

    return { success: false, error: 'SSE reconnection exhausted' };
  }

  private async checkSessionBeforeReconnect(sessionId: string): Promise<MitigationResult | null> {
    try {
      const status = await this.client.getSessionStatus('mitigation', sessionId);
      if (status.status === 'completed') {
        return { success: false, error: `Session completed during SSE disconnect (status: ${status.status})` };
      }
      if (status.status === 'failed') {
        return { success: false, error: 'Session failed during SSE disconnect' };
      }
      return null;
    } catch {
      return null;
    }
  }

  private async connectSSEStream(sessionId: string): Promise<MitigationResult> {
    const streamUrl = `${this.config.baseUrl}/api/v1/mitigation/stream/${sessionId}`;
    const response = await fetch(streamUrl, {
      method: 'GET',
      headers: {
        'x-api-key': this.config.apiKey,
        Accept: 'text/event-stream',
      },
    });

    if (!response.ok || !response.body) {
      throw new Error(`Failed to connect SSE stream: ${response.status} ${response.statusText}`);
    }

    return this.processSSEStream(response.body, sessionId);
  }

  private buildSessionContext(
    context: MitigationContext
  ): Record<string, unknown> {
    const sessionContext: Record<string, unknown> = {
      issue: context.issue,
      analysis: context.analysis,
    };

    if (context.validationData) {
      sessionContext.validation_data = context.validationData;
    }

    return sessionContext;
  }

  private async processSSEStream(
    body: ReadableStream<Uint8Array>,
    sessionId: string
  ): Promise<MitigationResult> {
    const reader = body.getReader();
    const decoder = new TextDecoder();
    let buffer = '';

    try {
      while (true) {
        const { done, value } = await reader.read();

        if (done) {
          // Stream ended without complete event — throw to trigger reconnection
          throw new Error('SSE stream disconnected without terminal event');
        }

        buffer += decoder.decode(value, { stream: true });

        // Parse SSE events from buffer
        const events = this.parseSSEBuffer(buffer);
        buffer = events.remaining;

        for (const event of events.parsed) {
          const result = await this.handleSSEEvent(event, sessionId);
          if (result !== null) {
            return result;
          }
        }
      }
    } finally {
      reader.releaseLock();
    }
  }

  private parseSSEBuffer(buffer: string): {
    parsed: SSEEvent[];
    remaining: string;
  } {
    const parsed: SSEEvent[] = [];
    const blocks = buffer.split('\n\n');

    // Last block may be incomplete
    const remaining = blocks.pop() || '';

    for (const block of blocks) {
      if (!block.trim()) continue;

      const lines = block.split('\n');
      let eventType = '';
      let eventId = '';
      let dataLine = '';

      for (const line of lines) {
        if (line.startsWith('event: ')) {
          eventType = line.slice(7);
        } else if (line.startsWith('id: ')) {
          eventId = line.slice(4);
        } else if (line.startsWith('data: ')) {
          dataLine = line.slice(6);
        }
        // Lines starting with ':' are SSE comments (keepalive) — skip
      }

      if (eventType) {
        try {
          const data = dataLine ? JSON.parse(dataLine) : null;
          const event: SSEEvent = {
            type: eventType as SSEEvent['type'],
            id: eventId ? parseInt(eventId, 10) : 0,
            data,
          };
          parsed.push(event);
        } catch {
          // Skip malformed events
        }
      }
    }

    return { parsed, remaining };
  }

  private async handleSSEEvent(
    event: SSEEvent,
    sessionId: string
  ): Promise<MitigationResult | null> {
    switch (event.type) {
    case 'tool_request': {
      const toolRequest = event.data as ToolRequest;
      await this.executeAndSubmitTool(toolRequest, sessionId);
      return null; // Continue processing
    }

    case 'complete': {
      const data = event.data as Record<string, unknown>;
      return {
        success: (data.success as boolean) ?? true,
        title: data.title as string | undefined,
        description: data.description as string | undefined,
        files_mentioned: data.files_mentioned as string[] | undefined,
      };
    }

    case 'error': {
      const data = event.data as Record<string, unknown>;
      return {
        success: false,
        error: (data.error as string) || 'Unknown error from backend',
      };
    }

    case 'heartbeat':
    case 'progress':
      return null; // Continue processing

    default:
      return null; // Ignore unknown event types
    }
  }

  private async executeAndSubmitTool(
    toolRequest: ToolRequest,
    sessionId: string
  ): Promise<void> {
    const executor = TOOL_DISPATCH[toolRequest.tool];

    let result: Record<string, unknown>;

    if (!executor) {
      result = { error: `Unknown tool: ${toolRequest.tool}` };
    } else {
      try {
        result = await executor(toolRequest.input);
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        result = { error: `Tool execution failed: ${message}` };
      }
    }

    // Submit tool response back to backend
    await this.client.submitToolResponse(
      'mitigation',
      sessionId,
      toolRequest.id,
      result
    );
  }
}
