/**
 * `rsolv-sandbox`: the programs the RFC-150 host runs inside the sandbox
 * (3c "Sandbox CLI contract"). Input is one length-prefixed JSON frame on
 * stdin. `tool`, `bootstrap` and `patch` write one JSON line to stdout, last;
 * everything else the process prints goes to stderr, which the host merges
 * and discards.
 */

import * as fs from 'fs';
import { pathToFileURL } from 'url';
import { FrameReader } from './frame.js';

type Emit = (result: Record<string, unknown>) => void;
type Command = (reader: FrameReader, emit: Emit) => Promise<number>;

// Each command loads its modules only once output is redirected (see main),
// so nothing they print at import time reaches stdout.
const COMMANDS: Record<string, Command> = {
  tool: async (reader, emit) => {
    const { runTool } = await import('./tool.js');
    emit(await runTool(await reader.next()));
    return 0;
  },
  bootstrap: async (reader, emit) => {
    await reader.next();
    const { runBootstrap } = await import('./bootstrap.js');
    emit({ ...(await runBootstrap({ cwd: process.cwd() })) });
    return 0;
  },
  patch: async (reader, emit) => {
    const { runPatch } = await import('./patch.js');
    const result = await runPatch(await reader.next());
    emit(result);
    return 'patch' in result ? 0 : 1;
  },
};

export async function main(
  argv: string[],
  stdin: NodeJS.ReadableStream,
  stdout: NodeJS.WritableStream,
  stderr: NodeJS.WritableStream = process.stderr
): Promise<number> {
  const command = argv[0];
  if (command === undefined || !Object.hasOwn(COMMANDS, command)) return 2;

  const write = stdout.write.bind(stdout) as (line: string) => boolean;
  const restore = redirectOutput(stderr);
  try {
    return await COMMANDS[command](new FrameReader(stdin), (result) => write(`${JSON.stringify(result)}\n`));
  } catch (err) {
    write(`${JSON.stringify({ error: err instanceof Error ? err.message : String(err) })}\n`);
    return 1;
  } finally {
    restore();
  }
}

/** Points console output and stray process.stdout writes at `stderr` until restored. */
function redirectOutput(stderr: NodeJS.WritableStream): () => void {
  const saved = { log: console.log, info: console.info, debug: console.debug, warn: console.warn, error: console.error };
  const stdoutWrite = process.stdout.write;
  const toStderr = (...args: unknown[]): void => {
    stderr.write(`${args.map((a) => (typeof a === 'string' ? a : safeStringify(a))).join(' ')}\n`);
  };
  Object.assign(console, { log: toStderr, info: toStderr, debug: toStderr, warn: toStderr, error: toStderr });
  process.stdout.write = ((chunk: string | Uint8Array) => stderr.write(chunk)) as typeof process.stdout.write;
  return () => {
    Object.assign(console, saved);
    process.stdout.write = stdoutWrite;
  };
}

function safeStringify(value: unknown): string {
  if (value instanceof Error) return value.stack ?? value.message;
  try {
    return JSON.stringify(value);
  } catch {
    return String(value);
  }
}

async function run(): Promise<void> {
  const stdoutWrite = process.stdout.write.bind(process.stdout);
  const code = await main(process.argv.slice(2), process.stdin, process.stdout);
  // stdin may still be open; exit once stdout has flushed.
  stdoutWrite('', () => process.exit(code));
}

if (process.argv[1] && import.meta.url === pathToFileURL(fs.realpathSync(process.argv[1])).href) {
  void run();
}
