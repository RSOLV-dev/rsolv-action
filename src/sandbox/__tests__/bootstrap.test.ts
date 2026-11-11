import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

const runner = vi.hoisted(() => ({
  calls: [] as string[],
  exact: [] as boolean[],
  reports: [] as unknown[],
  ensureRuntime: async (framework: string, cwd: string): Promise<void> => {
    runner.calls.push(`runtime:${framework}:${cwd}`);
  },
  ensureDependencies: async (framework: string, cwd: string): Promise<void> => {
    runner.calls.push(`deps:${framework}:${cwd}`);
  },
}));

vi.mock('../../ai/test-runner.js', () => ({
  TestRunner: class {
    runtimeReports = runner.reports;
    exactRuntimeVersions = false;
    ensureRuntime(framework: string, cwd: string) {
      runner.exact.push(this.exactRuntimeVersions);
      return runner.ensureRuntime(framework, cwd);
    }
    ensureDependencies(framework: string, cwd: string) {
      return runner.ensureDependencies(framework, cwd);
    }
  },
}));

import { runBootstrap } from '../bootstrap.js';

describe('runBootstrap', () => {
  let cwd: string;
  const original = { ...runner };

  beforeEach(() => {
    cwd = fs.mkdtempSync(path.join(os.tmpdir(), 'rsolv-bootstrap-'));
    runner.calls.length = 0;
    runner.exact.length = 0;
    runner.reports.length = 0;
  });

  afterEach(() => {
    runner.ensureRuntime = original.ensureRuntime;
    runner.ensureDependencies = original.ensureDependencies;
    fs.rmSync(cwd, { recursive: true, force: true });
  });

  it('installs the runtime, then the dependencies, of a jest project', async () => {
    fs.writeFileSync(path.join(cwd, 'package.json'), JSON.stringify({ devDependencies: { jest: '^29' } }));

    const result = await runBootstrap({ cwd });

    expect(result).toEqual({ ok: true, ecosystems: ['javascript'], log_tail: expect.any(String), runtimes: [] });
    expect(runner.calls).toEqual([`runtime:jest:${cwd}`, `deps:jest:${cwd}`]);
  });

  it('carries on when the dependencies fail, with the failure in log_tail', async () => {
    fs.writeFileSync(path.join(cwd, 'Gemfile'), 'gem \'rspec\'\n');
    runner.ensureDependencies = async () => {
      throw new Error('bundle install exploded');
    };

    const result = await runBootstrap({ cwd });

    expect(result.ok).toBe(true);
    expect(result.ecosystems).toEqual(['ruby']);
    expect(result.log_tail).toContain('bundle install exploded');
  });

  it('skips the dependencies when the runtime fails, with the failure in log_tail', async () => {
    fs.writeFileSync(path.join(cwd, 'requirements.txt'), 'pytest\n');
    runner.ensureRuntime = async () => {
      throw new Error('mise install python failed');
    };

    const result = await runBootstrap({ cwd });

    expect(result.ok).toBe(true);
    expect(result.log_tail).toContain('mise install python failed');
    expect(runner.calls).toEqual([]);
  });

  it('returns the runtime installs\' reports, for the host to annotate', async () => {
    fs.writeFileSync(path.join(cwd, 'requirements.txt'), 'pytest\n');
    const report = { runtime: 'python', requested: '3.11.9', actual: '3.11.11', status: 'fallback' };
    runner.ensureRuntime = async () => {
      runner.reports.push(report);
    };

    const result = await runBootstrap({ cwd });

    expect(result.runtimes).toEqual([report]);
  });

  it('keeps the report of a runtime that failed to install', async () => {
    fs.writeFileSync(path.join(cwd, 'requirements.txt'), 'pytest\n');
    const report = { runtime: 'python', requested: '3.11.9', status: 'failed', reason: 'verification_failed' };
    runner.ensureRuntime = async () => {
      runner.reports.push(report);
      throw new Error('python 3.11.9 was not installed: verification_failed');
    };

    const result = await runBootstrap({ cwd });

    expect(result.runtimes).toEqual([report]);
  });

  it('asks the runner for exact runtime versions when required', async () => {
    fs.writeFileSync(path.join(cwd, 'requirements.txt'), 'pytest\n');

    await runBootstrap({ cwd, exactRuntimeVersions: true });
    await runBootstrap({ cwd });

    expect(runner.exact).toEqual([true, false]);
  });

  it('runs nothing in a directory with no test framework', async () => {
    await expect(runBootstrap({ cwd })).resolves.toEqual({ ok: true, ecosystems: [], log_tail: '', runtimes: [] });
    expect(runner.calls).toEqual([]);
  });

  it('keeps the last 8,192 bytes of what the runner logged', async () => {
    fs.writeFileSync(path.join(cwd, 'pom.xml'), '<project/>');
    runner.ensureRuntime = async () => {
      for (let i = 0; i < 2000; i++) console.log(`line ${i} é`);
      console.warn('the very end');
    };

    const result = await runBootstrap({ cwd });

    expect(Buffer.byteLength(result.log_tail)).toBeLessThanOrEqual(8192);
    expect(result.log_tail).toContain('the very end');
    expect(result.log_tail).not.toContain('line 0 ');
    expect(result.log_tail.startsWith('�')).toBe(false);
  });

  it('restores the console afterwards', async () => {
    const log = console.log;
    fs.writeFileSync(path.join(cwd, 'pom.xml'), '<project/>');

    await runBootstrap({ cwd });

    expect(console.log).toBe(log);
  });
});
