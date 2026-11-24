/**
 * PipelineClient — SSE consumer for the backend-orchestrated pipeline (RFC-096).
 *
 * Communicates with the Elixir backend to:
 * - Start pipeline sessions
 * - Consume SSE streams of tool requests
 * - Submit tool execution responses
 * - Check session status
 * - Cancel sessions
 */

import type {
  PipelineClientConfig,
  PipelinePhase,
  SessionStartParams,
  SessionStartResponse,
  SessionStatusResponse,
} from './types.js';

const PROVIDER_AUTH_MESSAGE =
  'RSOLV\'s AI provider rejected our credentials. This is a problem on RSOLV\'s side, not your repository; we\'ve been alerted. Re-running won\'t help until it\'s fixed.';

/**
 * The message for a session that failed because the platform's AI provider
 * refused RSOLV's credential, from an `error` event's data or a failed
 * session's status; undefined for any other failure.
 */
export function providerAuthMessage(data: { error?: unknown; reason?: unknown }): string | undefined {
  return data.error === 'service_unavailable' && data.reason === 'provider_auth'
    ? PROVIDER_AUTH_MESSAGE
    : undefined;
}

/** The message for a session `error` event's data. */
export function sessionErrorMessage(data: Record<string, unknown>): string {
  return providerAuthMessage(data) ?? ((data.error as string) || 'Unknown error from backend');
}

export class PipelineClient {
  private readonly baseUrl: string;
  private readonly apiKey: string;
  private readonly timeout: number;

  constructor(config: PipelineClientConfig) {
    this.baseUrl = config.baseUrl.replace(/\/$/, ''); // strip trailing slash
    this.apiKey = config.apiKey;
    this.timeout = config.timeout ?? 30_000;
  }

  /**
   * Starts a new pipeline session.
   *
   * POSTs to /api/v1/{phase}/start with session params.
   * Returns session_id and stream_url for SSE connection.
   */
  async startSession(params: SessionStartParams): Promise<SessionStartResponse> {
    const url = `${this.baseUrl}/api/v1/${params.phase}/start`;

    const response = await fetch(url, {
      method: 'POST',
      headers: this.headers(),
      body: JSON.stringify({
        namespace: params.namespace,
        context: params.context,
      }),
    });

    if (!response.ok) {
      const body = await response.json().catch(() => ({}));
      throw new Error(
        `Failed to start session: ${response.status} ${response.statusText} - ${JSON.stringify(body)}`
      );
    }

    return (await response.json()) as SessionStartResponse;
  }

  /**
   * Submits a tool execution response to the backend.
   *
   * POSTs to /api/v1/{phase}/tool_response/{session_id}.
   */
  async submitToolResponse(
    phase: PipelinePhase | string,
    sessionId: string,
    requestId: string,
    result: Record<string, unknown>
  ): Promise<void> {
    const url = `${this.baseUrl}/api/v1/${phase}/tool_response/${sessionId}`;

    const response = await fetch(url, {
      method: 'POST',
      headers: this.headers(),
      body: JSON.stringify({
        request_id: requestId,
        result,
      }),
    });

    if (!response.ok) {
      const body = await response.json().catch(() => ({}));
      throw new Error(
        `Failed to submit tool response: ${response.status} ${response.statusText} - ${JSON.stringify(body)}`
      );
    }
  }

  /**
   * Gets the current status of a pipeline session.
   *
   * GETs /api/v1/{phase}/status/{session_id}.
   */
  async getSessionStatus(
    phase: PipelinePhase | string,
    sessionId: string
  ): Promise<SessionStatusResponse> {
    const url = `${this.baseUrl}/api/v1/${phase}/status/${sessionId}`;

    const response = await fetch(url, {
      method: 'GET',
      headers: this.headers(),
    });

    if (!response.ok) {
      throw new Error(`Failed to get session status: ${response.status} ${response.statusText}`);
    }

    return (await response.json()) as SessionStatusResponse;
  }

  /**
   * Cancels a running pipeline session.
   *
   * DELETEs /api/v1/{phase}/{session_id}.
   */
  async cancelSession(phase: PipelinePhase | string, sessionId: string): Promise<void> {
    const url = `${this.baseUrl}/api/v1/${phase}/${sessionId}`;

    const response = await fetch(url, {
      method: 'DELETE',
      headers: this.headers(),
    });

    if (!response.ok) {
      throw new Error(`Failed to cancel session: ${response.status} ${response.statusText}`);
    }
  }

  /** Build common headers for all requests */
  private headers(): Record<string, string> {
    return {
      'Content-Type': 'application/json',
      'x-api-key': this.apiKey,
    };
  }
}
