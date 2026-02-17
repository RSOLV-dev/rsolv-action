/**
 * ValidationClient — Thin VALIDATE client for RFC-096 Phase C.
 *
 * Uses PipelineClient to start a backend-orchestrated validation session,
 * consumes SSE events, dispatches tool_request events to local ToolExecutors,
 * and submits results back to the backend.
 *
 * The backend Orchestrator drives the agentic loop (API calls, tool selection,
 * test generation, classification gates). This client just executes tools and
 * returns the validation result.
 *
 * Key difference from MitigationClient:
 * - Phase is 'validation' (not 'mitigation')
 * - Result type is ValidationResult (validated, test_path, test_code, framework, cwe_id)
 * - No PR creation — VALIDATE only generates and validates the RED test
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

/** Thrown when the SSE stream closes without a terminal event (complete/error). */
class SSEDisconnectError extends Error {
  constructor() {
    super('SSE stream disconnected without terminal event');
    this.name = 'SSEDisconnectError';
  }
}

export interface ValidationContext {
  vulnerability: {
    type: string;
    description: string;
    location?: string;
    attack_vector?: string;
    source?: string;
  };
  cwe_id: string;
  namespace: string;
  repoPath: string;
  /** Full repo name (owner/repo) — platform uses this to enrich from stored SCAN data */
  repo: string;
  /** Optional — platform auto-resolves from stored project_shape when omitted */
  framework?: {
    name: string;
    test_command?: string;
    assertion_style?: string;
    available_libraries?: string[];
  };
  /** Optional — platform auto-resolves from stored SCAN data when omitted */
  project_shape?: {
    ecosystem?: string;
    runtime_version?: string;
    framework_versions?: Record<string, string>;
  };
}

export interface ValidationResult {
  validated: boolean;
  test_path?: string;
  test_code?: string;
  framework?: string;
  cwe_id?: string;
  error?: string;
  /** Classification from backend: validated, false_positive, infrastructure_failure, inconclusive, no_test_framework */
  classification?: string;
  /** Test type: behavioral (has test execution) or static (file writes only) */
  test_type?: string;
  /** Number of tool calls in the session */
  retry_count?: number;
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

export class ValidationClient {
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
   * Runs a backend-orchestrated validation session.
   *
   * 1. POST /validation/start with vulnerability context
   * 2. Connect SSE stream with automatic reconnection
   * 3. On tool_request: dispatch to local executor, POST tool_response
   * 4. On complete: return validation result with test metadata
   * 5. On error: return failure result
   * 6. On disconnect: check session status, reconnect if still active
   */
  async runValidation(context: ValidationContext): Promise<ValidationResult> {
    let sessionId: string;

    // 1. Start session
    try {
      const startResponse = await this.client.startSession({
        phase: 'validation',
        namespace: context.namespace,
        context: this.buildSessionContext(context),
      });
      sessionId = startResponse.session_id;
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      return {
        validated: false,
        error: `Failed to start validation session: ${message}`,
      };
    }

    // 2. Connect SSE stream with reconnection
    for (let attempt = 0; attempt <= this.maxReconnects; attempt++) {
      // On reconnect (attempt > 0), check session status first
      if (attempt > 0) {
        const statusResult = await this.checkSessionBeforeReconnect(sessionId);
        if (statusResult !== null) return statusResult;

        const delay = this.reconnectBaseDelayMs * Math.pow(2, attempt - 1);
        await new Promise(resolve => setTimeout(resolve, delay));
        console.log(`[ValidationClient] SSE reconnecting (attempt ${attempt}/${this.maxReconnects})...`);
      }

      try {
        const result = await this.connectSSEStream(sessionId);
        return result; // Got terminal result
      } catch (err) {
        // Reconnect on ANY stream error — not just SSEDisconnectError.
        // Undici throws generic Error ("socket connection was closed unexpectedly")
        // at the fetch() level, which isn't an SSEDisconnectError. Both represent
        // recoverable transport failures. See RFC-114 for long-term Channel migration.
        const message = err instanceof Error ? err.message : String(err);
        console.log(`[ValidationClient] SSE stream error (attempt ${attempt}/${this.maxReconnects}): ${message}`);
        if (attempt === this.maxReconnects) {
          return {
            validated: false,
            error: `SSE stream failed after ${this.maxReconnects} reconnect attempts: ${message}`,
          };
        }
        continue; // Try reconnecting
      }
    }

    return { validated: false, error: 'SSE reconnection exhausted' };
  }

  /**
   * Check session status before reconnecting. If the session completed
   * or failed while we were disconnected, return the result immediately
   * instead of reconnecting.
   */
  private async checkSessionBeforeReconnect(sessionId: string): Promise<ValidationResult | null> {
    try {
      const status = await this.client.getSessionStatus('validation', sessionId);
      if (status.status === 'completed') {
        return { validated: false, error: `Session completed during SSE disconnect (status: ${status.status})` };
      }
      if (status.status === 'failed') {
        return { validated: false, error: `Session failed during SSE disconnect` };
      }
      // Session still active — proceed with reconnect
      return null;
    } catch {
      // Can't check status — proceed with reconnect anyway
      return null;
    }
  }

  /**
   * Opens a single SSE connection to the stream endpoint and processes events.
   * Throws SSEDisconnectError if stream closes without a terminal event.
   */
  private async connectSSEStream(sessionId: string): Promise<ValidationResult> {
    const streamUrl = `${this.config.baseUrl}/api/v1/validation/stream/${sessionId}`;
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
    context: ValidationContext
  ): Record<string, unknown> {
    // Send minimal context — platform auto-enriches from stored SCAN data
    // via PhaseContext.enrich_for_validation() using the repo name
    const sessionContext: Record<string, unknown> = {
      vulnerability: context.vulnerability,
      cwe_id: context.cwe_id,
      repo: context.repo,
    };

    // Include framework/project_shape only when explicitly provided;
    // platform resolves these from stored shape when omitted
    if (context.framework) {
      sessionContext.framework = context.framework;
    }

    if (context.project_shape) {
      sessionContext.project_shape = context.project_shape;
    }

    return sessionContext;
  }

  private async processSSEStream(
    body: ReadableStream<Uint8Array>,
    sessionId: string
  ): Promise<ValidationResult> {
    const reader = body.getReader();
    const decoder = new TextDecoder();
    let buffer = '';

    try {
      while (true) {
        const { done, value } = await reader.read();

        if (done) {
          throw new SSEDisconnectError();
        }

        buffer += decoder.decode(value, { stream: true });

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
  ): Promise<ValidationResult | null> {
    switch (event.type) {
      case 'tool_request': {
        const toolRequest = event.data as ToolRequest;
        await this.executeAndSubmitTool(toolRequest, sessionId);
        return null; // Continue processing
      }

      case 'complete': {
        const data = event.data as Record<string, unknown>;
        return {
          validated: (data.validated as boolean) ?? false,
          test_path: data.test_path as string | undefined,
          test_code: data.test_code as string | undefined,
          framework: data.framework as string | undefined,
          cwe_id: data.cwe_id as string | undefined,
          classification: data.classification as string | undefined,
          test_type: data.test_type as string | undefined,
          retry_count: data.retry_count as number | undefined,
        };
      }

      case 'error': {
        const data = event.data as Record<string, unknown>;
        return {
          validated: false,
          error: (data.error as string) || 'Unknown error from backend',
        };
      }

      case 'heartbeat':
      case 'progress':
        return null;

      default:
        return null;
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

    await this.client.submitToolResponse(
      'validation',
      sessionId,
      toolRequest.id,
      result
    );
  }
}
