/**
 * Pipeline module — Backend-orchestrated pipeline client (RFC-096).
 *
 * Exports the thin client and tool executors for communication
 * with the Elixir backend's orchestrated pipeline.
 */

export { PipelineClient } from './client.js';
export { MitigationClient } from './mitigation-client.js';
export type { MitigationContext, MitigationResult } from './mitigation-client.js';
export {
  executeReadFile,
  executeWriteFile,
  executeEditFile,
  executeGlob,
  executeGrep,
  executeBash,
} from './tool-executors.js';
export { collectManifestFiles, collectVulnerableFiles } from './context-prefetch.js';
export type {
  PipelinePhase,
  ToolName,
  SessionStatus,
  ToolRequest,
  ToolResponse,
  SSEEvent,
  SessionStartParams,
  SessionStartResponse,
  SessionStatusResponse,
  PipelineClientConfig,
} from './types.js';
