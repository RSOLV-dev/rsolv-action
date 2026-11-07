import { describe, it, expect, vi } from 'vitest';

const execCalls = vi.hoisted((): Array<{ timeout?: number }> => []);

vi.mock('child_process', async (importOriginal) => {
  const actual = await importOriginal<typeof import('child_process')>();
  return {
    ...actual,
    exec: (_command: string, options: { timeout?: number }, callback: (e: null, out: string, err: string) => void) => {
      execCalls.push(options);
      callback(null, '', '');
    },
  };
});

import { executeBash } from '../tool-executors.js';

describe('executeBash timeout', () => {
  it('caps timeout_ms at 900,000', async () => {
    await executeBash({ command: 'true', timeout_ms: 5_000_000 });

    expect(execCalls.at(-1)?.timeout).toBe(900_000);
  });

  it('keeps a timeout under the cap', async () => {
    await executeBash({ command: 'true', timeout_ms: 1_000 });

    expect(execCalls.at(-1)?.timeout).toBe(1_000);
  });

  it('defaults to 600,000', async () => {
    await executeBash({ command: 'true' });

    expect(execCalls.at(-1)?.timeout).toBe(600_000);
  });
});
