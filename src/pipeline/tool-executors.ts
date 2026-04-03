/**
 * ToolExecutors — Local tool handlers for the pipeline protocol (RFC-096).
 *
 * These execute file I/O, shell commands, and search operations
 * on the GitHub Action runner in response to backend tool requests.
 */

import * as fs from 'fs';
import * as path from 'path';
import { execSync } from 'child_process';
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
} from './types.js';

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

    // Use grep command for efficiency
    try {
      const output = execSync(
        `grep -rn "${input.pattern.replace(/"/g, '\\"')}" ${searchPath}`,
        {
          encoding: 'utf-8',
          timeout: 10_000,
          maxBuffer: 5 * 1024 * 1024,
        }
      );

      for (const line of output.split('\n').filter(Boolean)) {
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
      const execError = grepErr as { status?: number };
      if (execError.status !== 1) {
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
 * Includes mise shims in PATH for runtime access.
 */
export async function executeBash(input: BashInput): Promise<BashResult> {
  const timeoutMs = input.timeout_ms ?? 120_000;

  // Build PATH with mise shims
  const miseDataDir = process.env.MISE_DATA_DIR || `${process.env.HOME || '/root'}/.local/share/mise`;
  const miseShimsPath = `${miseDataDir}/shims`;
  const enhancedPath = `${miseShimsPath}:${process.env.PATH || ''}`;

  try {
    const stdout = execSync(input.command, {
      encoding: 'utf-8',
      timeout: timeoutMs,
      maxBuffer: 10 * 1024 * 1024,
      cwd: input.cwd || process.cwd(),
      env: {
        ...process.env,
        PATH: enhancedPath,
      },
    });

    return {
      stdout,
      stderr: '',
      exit_code: 0,
    };
  } catch (err) {
    const execError = err as {
      status?: number | null;
      stdout?: string;
      stderr?: string;
      killed?: boolean;
      signal?: string;
    };

    // Check if killed by timeout
    if (execError.killed || execError.signal === 'SIGTERM') {
      return {
        stdout: execError.stdout || '',
        stderr: execError.stderr || '',
        exit_code: 124,
        error: `timeout: command exceeded ${timeoutMs}ms`,
      };
    }

    return {
      stdout: execError.stdout || '',
      stderr: execError.stderr || '',
      exit_code: execError.status ?? 1,
    };
  }
}
