/**
 * Runtime installs as the v5 sandbox's non-root user (RFC-150 3d, owner
 * decisions 2026-11-07): Python, PHP and Maven go through
 * sandbox/runtime-install, whose reports the host annotates. As root (the v4
 * action) nothing changes.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

const state = vi.hoisted(() => ({
  execCommands: [] as string[],
  miseLs: '[]',
}));

vi.mock('child_process', () => ({
  exec: (command: string, _options: unknown, callback: (e: Error | null, r?: { stdout: string; stderr: string }) => void) => {
    state.execCommands.push(command);
    // No runtime on PATH, so ensureRuntime has to install one.
    if (command.startsWith('which ')) callback(new Error('not found'));
    else callback(null, { stdout: '', stderr: '' });
  },
  execFile: (
    _file: string,
    _args: string[],
    _options: unknown,
    callback: (e: Error | null, r?: { stdout: string; stderr: string }) => void
  ) => callback(null, { stdout: state.miseLs, stderr: '' }),
}));

const installs = vi.hoisted(() => ({
  installPython: vi.fn(),
  installPhp: vi.fn(),
  installMaven: vi.fn(),
}));

vi.mock('../../sandbox/runtime-install.js', () => ({
  ...installs,
  run: vi.fn(),
  clock: {},
}));

import { TestRunner } from '../test-runner.js';

describe('TestRunner runtime installs in the v5 sandbox', () => {
  let cwd: string;
  let runner: TestRunner;

  const declare = (tool: string, version: string): void => {
    state.miseLs = JSON.stringify([
      { version, requested_version: version, source: { type: 'mise.toml', path: path.join(cwd, 'mise.toml') } },
    ]);
  };

  beforeEach(() => {
    cwd = fs.mkdtempSync(path.join(os.tmpdir(), 'rsolv-runtimes-'));
    state.execCommands.length = 0;
    state.miseLs = '[]';
    Object.values(installs).forEach((fn) => fn.mockReset());
    vi.spyOn(process, 'getuid').mockReturnValue(1001);
    runner = new TestRunner();
  });

  afterEach(() => {
    vi.restoreAllMocks();
    fs.rmSync(cwd, { recursive: true, force: true });
  });

  describe('a repository pinning python 3.11.9', () => {
    beforeEach(() => declare('python', '3.11.9'));

    it('installs it through the attestation-checked installer and keeps its report', async () => {
      const report = { runtime: 'python', requested: '3.11.9', actual: '3.11.11', status: 'fallback' };
      installs.installPython.mockResolvedValue(report);

      await runner.ensureRuntime('pytest', cwd);

      expect(installs.installPython).toHaveBeenCalledWith('3.11.9', expect.objectContaining({ exact: false }));
      expect(runner.runtimeReports).toEqual([report]);
      expect(state.execCommands.some((c) => c.includes('mise install python'))).toBe(false);
    });

    it('passes on a requirement for the exact version', async () => {
      installs.installPython.mockResolvedValue({ runtime: 'python', requested: '3.11.9', status: 'failed', reason: 'no_attestations' });
      runner.exactRuntimeVersions = true;

      await expect(runner.ensureRuntime('pytest', cwd)).rejects.toThrow();

      expect(installs.installPython).toHaveBeenCalledWith('3.11.9', expect.objectContaining({ exact: true }));
    });

    it('fails clearly, with no apt-get substitute, when the install fails', async () => {
      installs.installPython.mockResolvedValue({
        runtime: 'python',
        requested: '3.11.9',
        status: 'failed',
        reason: 'verification_failed',
      });

      await expect(runner.ensureRuntime('pytest', cwd)).rejects.toThrow('python 3.11.9 was not installed: verification_failed');

      expect(runner.runtimeReports).toHaveLength(1);
      expect(state.execCommands.some((c) => c.includes('apt-get'))).toBe(false);
    });
  });

  describe('a repository pinning php 8.3.21', () => {
    beforeEach(() => declare('php', '8.3.21'));

    it('builds it with bounded resources', async () => {
      installs.installPhp.mockResolvedValue({ runtime: 'php', requested: '8.3.21', actual: '8.3.21', status: 'installed' });

      await runner.ensureRuntime('phpunit', cwd);

      expect(installs.installPhp).toHaveBeenCalledWith(
        '8.3.21',
        expect.objectContaining({ jobs: expect.any(Number), timeoutS: 720 })
      );
      const [, { jobs }] = installs.installPhp.mock.calls[0] as [string, { jobs: number }];
      expect(jobs).toBeGreaterThanOrEqual(1);
      expect(jobs).toBeLessThanOrEqual(4);
    });

    it('fails clearly, with no apt-get substitute, when the build fails', async () => {
      installs.installPhp.mockResolvedValue({ runtime: 'php', requested: '8.3.21', status: 'failed', reason: 'build_failed' });

      await expect(runner.ensureRuntime('phpunit', cwd)).rejects.toThrow('php 8.3.21 was not installed: build_failed');

      expect(state.execCommands.some((c) => c.includes('apt-get'))).toBe(false);
      expect(state.execCommands.some((c) => c.includes('mise install php'))).toBe(false);
    });
  });

  it('installs Maven with retries and keeps its report', async () => {
    const report = { runtime: 'maven', requested: '3.9.11', actual: '3.9.11', status: 'installed' };
    installs.installMaven.mockResolvedValue(report);

    await runner['ensureMaven'](cwd);

    expect(installs.installMaven).toHaveBeenCalled();
    expect(runner.runtimeReports).toEqual([report]);
    expect(state.execCommands.some((c) => c.includes('mise install maven') || c.includes('apt-get'))).toBe(false);
  });

  describe('as root (the v4 action)', () => {
    beforeEach(() => {
      vi.spyOn(process, 'getuid').mockReturnValue(0);
      declare('python', '3.11.9');
    });

    it('installs Python as before', async () => {
      await runner.ensureRuntime('pytest', cwd);

      expect(installs.installPython).not.toHaveBeenCalled();
      expect(state.execCommands).toContain('mise install python@3.11.9 && mise use --global python@3.11.9');
    });

    it('installs Maven with apt-get as before', async () => {
      await runner['ensureMaven'](cwd);

      expect(installs.installMaven).not.toHaveBeenCalled();
      expect(state.execCommands).toContain('apt-get update && apt-get install -y maven');
    });
  });
});
