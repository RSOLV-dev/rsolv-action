/**
 * ToolExecutors — Local tool handlers for the pipeline protocol (RFC-096).
 *
 * These execute file I/O, shell commands, and search operations
 * on the GitHub Action runner in response to backend tool requests.
 */

import * as fs from 'fs';
import * as path from 'path';
import { exec, execFile } from 'child_process';
import { promisify } from 'util';
import { globSync } from 'glob';
import type {
  ReadFileInput,
  ReadFileResult,
  WriteFileInput,
  WriteFileResult,
  EditFileInput,
  EditFileResult,
  GlobInput,
  GlobResult,
  GrepInput,
  GrepResult,
  GrepMatch,
  BashInput,
  BashResult,
  ToolName,
} from './types.js';


export const MAX_BASH_TIMEOUT_MS = 900_000;
export const MAX_STREAM_BYTES = 262_144;

/**
 * Reads a file and returns its contents.
 */
export async function executeReadFile(input: ReadFileInput): Promise<ReadFileResult> {
  try {
    const content = fs.readFileSync(input.path, 'utf-8');
    return { content };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return { error: `Failed to read file: ${message}` };
  }
}

/**
 * Writes content to a file, creating parent directories if needed.
 */
export async function executeWriteFile(input: WriteFileInput): Promise<WriteFileResult> {
  try {
    const dir = path.dirname(input.path);
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(input.path, input.content, 'utf-8');
    return { success: true };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return { error: `Failed to write file: ${message}` };
  }
}

/**
 * Replaces old_string with new_string in a file.
 */
export async function executeEditFile(input: EditFileInput): Promise<EditFileResult> {
  try {
    const content = fs.readFileSync(input.path, 'utf-8');

    if (!content.includes(input.old_string)) {
      return { error: `old_string not found in file: ${input.path}` };
    }

    const updated = content.replace(input.old_string, input.new_string);
    fs.writeFileSync(input.path, updated, 'utf-8');
    return { success: true };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return { error: `Failed to edit file: ${message}` };
  }
}

/**
 * Finds files matching a glob pattern.
 */
export async function executeGlob(input: GlobInput): Promise<GlobResult> {
  try {
    const cwd = input.path || process.cwd();
    const files = globSync(input.pattern, { cwd, absolute: false });
    return { files };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return { files: [], error: `Glob failed: ${message}` };
  }
}

/**
 * Searches file contents with a regex pattern.
 */
export async function executeGrep(input: GrepInput): Promise<GrepResult> {
  try {
    const searchPath = input.path || process.cwd();
    const matches: GrepMatch[] = [];

    // argv, never a shell: the pattern comes from the model (RFC-150 gap 4)
    try {
      const { stdout } = await promisify(execFile)('grep', ['-rn', '-e', input.pattern, '--', searchPath], {
        encoding: 'utf-8',
        timeout: 10_000,
        maxBuffer: 5 * 1024 * 1024,
      });

      for (const line of stdout.split('\n').filter(Boolean)) {
        const match = line.match(/^(.+?):(\d+):(.*)$/);
        if (match) {
          matches.push({
            file: match[1],
            line_number: parseInt(match[2], 10),
            line: match[3],
          });
        }
      }
    } catch (grepErr) {
      // grep returns exit code 1 when no matches found — that's OK
      const execError = grepErr as { code?: number | string };
      if (execError.code !== 1) {
        throw grepErr;
      }
    }

    return { matches };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return { matches: [], error: `Grep failed: ${message}` };
  }
}

/**
 * Executes a shell command and returns stdout/stderr/exit_code.
 *
 * Uses async `exec` (not `execSync`) to avoid blocking the event loop.
 * This is critical for SSE connections: execSync freezes the event loop,
 * preventing undici from processing incoming keepalives, which triggers
 * a ~5min bodyTimeout and drops the SSE connection.
 *
 * Includes mise shims in PATH for runtime access.
 */
export async function executeBash(input: BashInput): Promise<BashResult> {
  // Default 600s (10 min) — must accommodate slow ecosystem setup
  // (bundle install, mix deps.get, composer install) before test execution.
  const timeoutMs = Math.min(input.timeout_ms ?? 600_000, MAX_BASH_TIMEOUT_MS);

  // Build PATH with mise shims
  const miseDataDir = process.env.MISE_DATA_DIR || `${process.env.HOME || '/root'}/.local/share/mise`;
  const miseShimsPath = `${miseDataDir}/shims`;
  const enhancedPath = `${miseShimsPath}:${process.env.PATH || ''}`;

  return new Promise((resolve) => {
    exec(input.command, {
      encoding: 'utf-8',
      timeout: timeoutMs,
      maxBuffer: 10 * 1024 * 1024,
      cwd: input.cwd || process.cwd(),
      env: {
        ...process.env,
        PATH: enhancedPath,
      },
    }, (error, stdout, stderr) => {
      if (error) {
        const execError = error as {
          code?: number | string | null;
          killed?: boolean;
          signal?: string;
        };

        // Check if killed by timeout
        if (execError.killed || execError.signal === 'SIGTERM') {
          resolve({
            stdout: truncate(stdout),
            stderr: truncate(stderr),
            exit_code: 124,
            error: `timeout: command exceeded ${timeoutMs}ms`,
          });
          return;
        }

        resolve({
          stdout: truncate(stdout),
          stderr: truncate(stderr),
          exit_code: typeof execError.code === 'number' ? execError.code : 1,
        });
        return;
      }

      resolve({
        stdout: truncate(stdout),
        stderr: truncate(stderr),
        exit_code: 0,
      });
    });
  });
}

function truncate(output: string | undefined): string {
  const bytes = Buffer.from(output || '', 'utf-8');
  if (bytes.length <= MAX_STREAM_BYTES) return output || '';
  return `${bytes.subarray(0, MAX_STREAM_BYTES).toString('utf-8')}…[truncated ${bytes.length - MAX_STREAM_BYTES} bytes]`;
}

type ToolExecutor = (input: Record<string, unknown>) => Promise<Record<string, unknown>>;

async function wrapExecutor<T>(fn: () => Promise<T>): Promise<Record<string, unknown>> {
  const result = await fn();
  return result as unknown as Record<string, unknown>;
}

/** The relay's tools, shared by the v4 pipeline clients and `rsolv-sandbox tool`. */
export const TOOL_DISPATCH: Record<ToolName, ToolExecutor> = {
  read_file: (input) => wrapExecutor(() => executeReadFile(input as unknown as ReadFileInput)),
  write_file: (input) => wrapExecutor(() => executeWriteFile(input as unknown as WriteFileInput)),
  edit_file: (input) => wrapExecutor(() => executeEditFile(input as unknown as EditFileInput)),
  glob: (input) => wrapExecutor(() => executeGlob(input as unknown as GlobInput)),
  grep: (input) => wrapExecutor(() => executeGrep(input as unknown as GrepInput)),
  bash: (input) => wrapExecutor(() => executeBash(input as unknown as BashInput)),
};
