/**
 * Pipeline protocol types (RFC-096 Phase A).
 *
 * Mirrors the Elixir backend types for type-safe communication
 * between the GitHub Action and the backend-orchestrated pipeline.
 */

/** Valid pipeline phases */
export type PipelinePhase = 'scan' | 'validation' | 'mitigation';

/** Tool names that the backend can request */
export type ToolName = 'read_file' | 'write_file' | 'edit_file' | 'glob' | 'grep' | 'bash';

/** Session status values */
export type SessionStatus =
  | 'created'
  | 'streaming'
  | 'waiting_for_tool'
  | 'completed'
  | 'failed';

/** Tool request sent from backend to action via SSE */
export interface ToolRequest {
  id: string;
  tool: ToolName;
  input: Record<string, unknown>;
  timeout_ms?: number;
}

/** Tool response sent from action to backend via HTTP POST */
export interface ToolResponse {
  request_id: string;
  result?: Record<string, unknown>;
  error?: string;
}

/** SSE event received from the backend */
export interface SSEEvent {
  type: 'tool_request' | 'progress' | 'complete' | 'error' | 'heartbeat';
  id: number;
  data?: ToolRequest | Record<string, unknown> | null;
}

/** Parameters for starting a new session */
export interface SessionStartParams {
  phase: PipelinePhase;
  namespace: string;
  context: Record<string, unknown>;
}

/** Response from POST /api/v1/:phase/start */
export interface SessionStartResponse {
  session_id: string;
  stream_url: string;
}

/** Response from GET /api/v1/:phase/status/:session_id */
export interface SessionStatusResponse {
  session_id: string;
  status: SessionStatus;
  phase: string;
  event_counter: number;
  pending_tools: number;
}

/** Configuration for PipelineClient */
export interface PipelineClientConfig {
  baseUrl: string;
  apiKey: string;
  timeout?: number;
}

/** Input types for tool executors */
export interface ReadFileInput {
  path: string;
}

export interface WriteFileInput {
  path: string;
  content: string;
}

export interface EditFileInput {
  path: string;
  old_string: string;
  new_string: string;
}

export interface GlobInput {
  pattern: string;
  path?: string;
}

export interface GrepInput {
  pattern: string;
  path?: string;
}

export interface BashInput {
  command: string;
  timeout_ms?: number;
  cwd?: string;
}

/** Tool execution results */
export interface ReadFileResult {
  content?: string;
  error?: string;
}

export interface WriteFileResult {
  success?: boolean;
  error?: string;
}

export interface EditFileResult {
  success?: boolean;
  error?: string;
}

export interface GlobResult {
  files: string[];
  error?: string;
}

export interface GrepMatch {
  file: string;
  line: string;
  line_number: number;
}

export interface GrepResult {
  matches: GrepMatch[];
  error?: string;
}

export interface BashResult {
  stdout?: string;
  stderr?: string;
  exit_code: number;
  error?: string;
}
