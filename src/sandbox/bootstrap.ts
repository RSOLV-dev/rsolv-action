import { detectTestFramework } from '../modes/phase-executor/detect-test-framework.js';
import { TestRunner, type TestFramework } from '../ai/test-runner.js';
import type { RuntimeReport } from './runtime-install.js';

const LOG_TAIL_BYTES = 8192;

const ECOSYSTEMS: Record<TestFramework, string> = {
  jest: 'javascript',
  vitest: 'javascript',
  mocha: 'javascript',
  rspec: 'ruby',
  minitest: 'ruby',
  pytest: 'python',
  phpunit: 'php',
  junit: 'java',
  junit5: 'java',
  junit4: 'java',
  testing: 'go',
  exunit: 'elixir',
};

export interface BootstrapResult {
  ok: boolean;
  ecosystems: string[];
  log_tail: string;
  /** Python, PHP and Maven installs, which the host annotates. */
  runtimes: RuntimeReport[];
}

/**
 * `rsolv-sandbox bootstrap` (RFC-150 §8): the runtime and dependency setup the
 * v4 action does before VALIDATE, run inside the sandbox. Failures are logged
 * and bootstrap carries on, as v4 does ("continuing anyway"). With
 * `exactRuntimeVersions`, a Python version with no attestations fails rather
 * than falling back to another patch.
 */
export async function runBootstrap({
  cwd,
  exactRuntimeVersions = false,
}: {
  cwd: string;
  exactRuntimeVersions?: boolean;
}): Promise<BootstrapResult> {
  const framework = detectTestFramework(cwd) as TestFramework | 'unknown';
  if (framework === 'unknown') return { ok: true, ecosystems: [], log_tail: '', runtimes: [] };

  const runner = new TestRunner();
  runner.exactRuntimeVersions = exactRuntimeVersions;
  const log = captureConsole();
  try {
    try {
      await runner.ensureRuntime(framework, cwd);
      try {
        await runner.ensureDependencies(framework, cwd);
      } catch (err) {
        console.warn(`[bootstrap] dependencies for ${framework} failed, continuing: ${message(err)}`);
      }
    } catch (err) {
      console.warn(`[bootstrap] runtime for ${framework} failed, continuing: ${message(err)}`);
    }
  } finally {
    log.restore();
  }
  return { ok: true, ecosystems: [ECOSYSTEMS[framework]], log_tail: log.tail(), runtimes: runner.runtimeReports };
}

function message(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

/** Collects console output, keeping the last LOG_TAIL_BYTES or so, until restored. */
function captureConsole(): { restore: () => void; tail: () => string } {
  const saved = { log: console.log, info: console.info, debug: console.debug, warn: console.warn, error: console.error };
  let buffer = '';
  const append = (...args: unknown[]): void => {
    buffer += `${args.map(String).join(' ')}\n`;
    if (buffer.length > 4 * LOG_TAIL_BYTES) buffer = buffer.slice(-2 * LOG_TAIL_BYTES);
  };
  Object.assign(console, { log: append, info: append, debug: append, warn: append, error: append });

  return {
    restore: () => Object.assign(console, saved),
    tail: () => {
      const bytes = Buffer.from(buffer, 'utf8');
      let start = Math.max(0, bytes.length - LOG_TAIL_BYTES);
      // Don't start inside a multi-byte character.
      while (start < bytes.length && (bytes[start] & 0xc0) === 0x80) start++;
      return bytes.subarray(start).toString('utf8');
    },
  };
}
