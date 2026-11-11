import { TOOL_DISPATCH } from '../pipeline/tool-executors.js';
import type { ToolName } from '../pipeline/types.js';

/** `rsolv-sandbox tool`: runs one relay tool request, `{tool, input}`. */
export async function runTool(request: unknown): Promise<Record<string, unknown>> {
  const { tool, input } = (request ?? {}) as { tool?: unknown; input?: unknown };
  if (typeof tool !== 'string' || !Object.hasOwn(TOOL_DISPATCH, tool)) return { error: 'unknown tool' };
  if (typeof input !== 'object' || input === null || Array.isArray(input)) return { error: 'malformed tool request' };

  try {
    return await TOOL_DISPATCH[tool as ToolName](input as Record<string, unknown>);
  } catch (err) {
    return { error: `Tool execution failed: ${err instanceof Error ? err.message : String(err)}` };
  }
}
