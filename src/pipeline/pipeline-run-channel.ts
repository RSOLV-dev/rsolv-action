/**
 * PipelineRunChannel — TypeScript client for Phoenix Channel communication
 * with the PipelineRun Coordinator.
 *
 * Uses the `phoenix` npm package (official Phoenix Channel JS client).
 *
 * RFC-124: Replaces GitHub label polling with bidirectional WebSocket.
 */

export interface CreateRunParams {
  commitSha: string;
  branch?: string;
  mode: 'full' | 'validate_only' | 'mitigate_only';
  maxIssues?: number;
}

export interface DetectedIssue {
  issue_number: number;
  cwe_id?: string;
}

export interface IssueInstruction {
  issue_number: number;
  cwe_id?: string;
}

export interface RunSummary {
  run_id: string;
  status: string;
  issues: Record<string, unknown>;
}

export interface PipelineRunChannelConfig {
  wsUrl: string;
  apiKey: string;
  onValidate?: (issues: IssueInstruction[]) => void;
  onMitigate?: (issues: IssueInstruction[]) => void;
  onComplete?: (summary: RunSummary) => void;
  onStatusChange?: (status: string) => void;
  onError?: (error: string) => void;
}

/**
 * Client for communicating with the PipelineRun Coordinator via Phoenix Channels.
 *
 * Usage:
 * ```typescript
 * const channel = new PipelineRunChannel({
 *   wsUrl: 'wss://api.rsolv.dev/action/websocket',
 *   apiKey: 'rsolv_...',
 *   onValidate: (issues) => { ... },
 *   onMitigate: (issues) => { ... },
 *   onComplete: (summary) => { ... },
 * });
 *
 * await channel.connect();
 * const { runId } = await channel.createRun({ commitSha: '...', mode: 'full' });
 * await channel.registerIssues(issues);
 * // ... Coordinator pushes instructions via callbacks
 * channel.disconnect();
 * ```
 */
export class PipelineRunChannel {
  private config: PipelineRunChannelConfig;
  private socket: WebSocket | null = null;
  private runId: string | null = null;
  private connected = false;
  private joinRef = 0;
  private ref = 0;
  private pendingReplies: Map<string, { resolve: (value: unknown) => void; reject: (reason: unknown) => void }> = new Map();
  private heartbeatInterval: ReturnType<typeof setInterval> | null = null;

  constructor(config: PipelineRunChannelConfig) {
    this.config = config;
  }

  /**
   * Connect to the ActionSocket WebSocket endpoint.
   */
  async connect(): Promise<void> {
    return new Promise((resolve, reject) => {
      const url = `${this.config.wsUrl}?api_key=${encodeURIComponent(this.config.apiKey)}&vsn=2.0.0`;

      this.socket = new WebSocket(url);

      this.socket.onopen = () => {
        this.connected = true;
        this.startHeartbeat();
        resolve();
      };

      this.socket.onerror = (event) => {
        reject(new Error(`WebSocket connection failed: ${event}`));
      };

      this.socket.onmessage = (event) => {
        this.handleMessage(JSON.parse(event.data as string));
      };

      this.socket.onclose = () => {
        this.connected = false;
        this.stopHeartbeat();
      };
    });
  }

  /**
   * Create a new pipeline run by joining a channel topic.
   */
  async createRun(params: CreateRunParams): Promise<{ runId: string }> {
    const runId = crypto.randomUUID();
    this.runId = runId;

    const reply = await this.joinChannel(`pipeline_run:${runId}`, {
      action: 'create',
      commit_sha: params.commitSha,
      branch: params.branch,
      mode: params.mode,
      max_issues: params.maxIssues || 3,
    });

    return { runId: (reply as { run_id: string }).run_id || runId };
  }

  /**
   * Reconnect to an existing pipeline run.
   */
  async reconnect(runId: string): Promise<{ status: string }> {
    this.runId = runId;
    const reply = await this.joinChannel(`pipeline_run:${runId}`, {});
    return { status: (reply as { status: string }).status };
  }

  /**
   * Register detected issues from SCAN phase.
   */
  async registerIssues(issues: DetectedIssue[]): Promise<void> {
    await this.push('register_issues', { issues });
  }

  /**
   * Report that a session has started for an issue.
   */
  async reportSessionStarted(issueNumber: number, sessionId: string): Promise<void> {
    await this.push('session_started', {
      issue_number: issueNumber,
      session_id: sessionId,
    });
  }

  /**
   * Transition the run status (e.g., to "scanning").
   */
  async transitionStatus(status: string): Promise<void> {
    await this.push('transition_status', { status });
  }

  /**
   * Mark the run as completed.
   */
  async complete(): Promise<void> {
    await this.push('complete', {});
  }

  /**
   * Mark the run as failed.
   */
  async fail(error: string): Promise<void> {
    await this.push('fail', { error });
  }

  /**
   * Disconnect from the WebSocket.
   */
  disconnect(): void {
    if (this.runId) {
      this.leaveChannel(`pipeline_run:${this.runId}`);
    }
    this.stopHeartbeat();
    if (this.socket) {
      this.socket.close();
      this.socket = null;
    }
    this.connected = false;
  }

  /**
   * Check if connected.
   */
  isConnected(): boolean {
    return this.connected;
  }

  // --- Private Methods ---

  private async joinChannel(topic: string, params: Record<string, unknown>): Promise<unknown> {
    return new Promise((resolve, reject) => {
      const joinRef = String(++this.joinRef);
      const ref = String(++this.ref);

      this.pendingReplies.set(ref, { resolve, reject });

      // Phoenix v2 wire format: [joinRef, ref, topic, event, payload]
      this.send([joinRef, ref, topic, 'phx_join', params]);

      // Timeout after 10s
      setTimeout(() => {
        if (this.pendingReplies.has(ref)) {
          this.pendingReplies.delete(ref);
          reject(new Error('Join timeout'));
        }
      }, 10000);
    });
  }

  private leaveChannel(topic: string): void {
    const ref = String(++this.ref);
    this.send([null, ref, topic, 'phx_leave', {}]);
  }

  private async push(event: string, payload: Record<string, unknown>): Promise<unknown> {
    if (!this.runId) throw new Error('No active run');

    return new Promise((resolve, reject) => {
      const ref = String(++this.ref);
      const topic = `pipeline_run:${this.runId}`;

      this.pendingReplies.set(ref, { resolve, reject });
      this.send([this.joinRef.toString(), ref, topic, event, payload]);

      setTimeout(() => {
        if (this.pendingReplies.has(ref)) {
          this.pendingReplies.delete(ref);
          reject(new Error(`Push timeout for ${event}`));
        }
      }, 10000);
    });
  }

  private send(message: unknown[]): void {
    if (this.socket && this.socket.readyState === WebSocket.OPEN) {
      this.socket.send(JSON.stringify(message));
    }
  }

  private handleMessage(message: unknown[]): void {
    // Phoenix v2 wire format: [joinRef, ref, topic, event, payload]
    if (!Array.isArray(message) || message.length < 5) return;

    const [, ref, , event, payload] = message as [string | null, string, string, string, Record<string, unknown>];

    // Handle replies to our pushes
    if (event === 'phx_reply' && ref) {
      const pending = this.pendingReplies.get(ref);
      if (pending) {
        this.pendingReplies.delete(ref);
        const response = payload as { status: string; response: unknown };
        if (response.status === 'ok') {
          pending.resolve(response.response);
        } else {
          pending.reject(new Error(JSON.stringify(response.response)));
        }
      }
      return;
    }

    // Handle server pushes
    switch (event) {
      case 'validate':
        this.config.onValidate?.(payload.issues as IssueInstruction[]);
        break;
      case 'mitigate':
        this.config.onMitigate?.(payload.issues as IssueInstruction[]);
        break;
      case 'complete':
        this.config.onComplete?.(payload as unknown as RunSummary);
        break;
      case 'status_change':
        this.config.onStatusChange?.(payload.status as string);
        break;
      case 'error':
        this.config.onError?.(payload.error as string);
        break;
    }
  }

  private startHeartbeat(): void {
    this.heartbeatInterval = setInterval(() => {
      const ref = String(++this.ref);
      this.send([null, ref, 'phoenix', 'heartbeat', {}]);
    }, 30000);
  }

  private stopHeartbeat(): void {
    if (this.heartbeatInterval) {
      clearInterval(this.heartbeatInterval);
      this.heartbeatInterval = null;
    }
  }
}
