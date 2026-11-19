/**
 * Runtime versions a repository declares through mise config (RFC-150 3d,
 * owner decision 4): mise.toml, .mise.toml, .config/mise.toml or .tool-versions.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import * as path from 'path';
import * as os from 'os';
import { promises as fs } from 'fs';

type MiseAnswer = { error?: Error; stdout?: string };

const state = vi.hoisted(() => ({
  execCommands: [] as string[],
  execFileCalls: [] as Array<{ file: string; args: string[]; cwd?: string }>,
  mise: (_cwd: string | undefined, _args: string[]): { error?: Error; stdout?: string } => ({ stdout: '[]' }),
}));

vi.mock('child_process', () => ({
  exec: (command: string, _options: unknown, callback: (e: Error | null, r: { stdout: string; stderr: string }) => void) => {
    state.execCommands.push(command);
    callback(null, { stdout: '', stderr: '' });
  },
  execFile: (
    file: string,
    args: string[],
    options: { cwd?: string },
    callback: (e: Error | null, r?: { stdout: string; stderr: string }) => void
  ) => {
    state.execFileCalls.push({ file, args, cwd: options?.cwd });
    const answer: MiseAnswer = file === 'mise' ? state.mise(options?.cwd, args) : { stdout: '' };
    if (answer.error) callback(answer.error);
    else callback(null, { stdout: answer.stdout ?? '', stderr: '' });
  },
}));

import { TestRunner } from '../test-runner.js';

const FIXTURES = path.resolve(__dirname, '../../sandbox/__tests__/fixtures/mise');

// mise's real `ls --current --json <tool>` output for one declared version
function miseLs(version: string, sourcePath: string): string {
  return JSON.stringify([
    {
      version,
      requested_version: version,
      install_path: `/opt/mise/installs/node/${version}`,
      source: { type: path.basename(sourcePath) === '.tool-versions' ? '.tool-versions' : 'mise.toml', path: sourcePath },
      installed: false,
      active: false,
    },
  ]);
}

describe('TestRunner runtime versions from mise config', () => {
  let runner: TestRunner;

  beforeEach(() => {
    state.execCommands.length = 0;
    state.execFileCalls.length = 0;
    runner = new TestRunner();
  });

  describe.each([
    ['mise-toml', 'mise.toml'],
    ['dot-mise-toml', '.mise.toml'],
    ['config-mise-toml', '.config/mise.toml'],
    ['tool-versions', '.tool-versions'],
  ])('a repository declaring node 20.18.0 in %s', (fixture, configFile) => {
    const dir = path.join(FIXTURES, fixture);

    beforeEach(() => {
      state.mise = (cwd) => (cwd === dir ? { stdout: miseLs('20.18.0', path.join(dir, configFile)) } : { stdout: '[]' });
    });

    it('reports the declared version', async () => {
      await expect(runner.detectRuntimeVersion('node', dir)).resolves.toBe('20.18.0');
      expect(state.execFileCalls).toContainEqual({ file: 'mise', args: ['ls', '--current', '--json', 'node'], cwd: dir });
    });

    it('installs it with mise', async () => {
      await runner.ensureRuntime('jest', dir);

      expect(state.execCommands.some((c) => c.includes('mise install node@20.18.0'))).toBe(true);
    });
  });

  it('accepts the keyed object form of mise ls --json', async () => {
    const dir = path.join(FIXTURES, 'mise-toml');
    state.mise = () => ({ stdout: JSON.stringify({ node: JSON.parse(miseLs('20.18.0', path.join(dir, 'mise.toml'))) }) });

    await expect(runner.detectRuntimeVersion('node', dir)).resolves.toBe('20.18.0');
  });

  it('ignores a version from config outside the repository and uses its version files', async () => {
    const dir = path.join(FIXTURES, 'global-only');
    state.mise = () => ({ stdout: miseLs('22.13.0', '/opt/home/.config/mise/config.toml') });

    await expect(runner.detectRuntimeVersion('node', dir)).resolves.toBe('18.20.4');
  });

  it('does not treat a sibling directory sharing the prefix as inside the repository', async () => {
    const dir = path.join(FIXTURES, 'global-only');
    state.mise = () => ({ stdout: miseLs('22.13.0', `${dir}-evil/mise.toml`) });

    await expect(runner.detectRuntimeVersion('node', dir)).resolves.toBe('18.20.4');
  });

  it('falls back to version files and logs the failure when mise ls fails', async () => {
    const dir = path.join(FIXTURES, 'global-only');
    state.mise = () => ({ error: new Error('mise ERROR error parsing config file') });
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => undefined);

    await expect(runner.detectRuntimeVersion('node', dir)).resolves.toBe('18.20.4');
    expect(warn.mock.calls.flat().join(' ')).toContain('mise ls');
    warn.mockRestore();
  });

  it('keeps today\'s behaviour for a node project that declares nothing: no install', async () => {
    const dir = path.join(FIXTURES, 'none');
    state.mise = () => ({ stdout: '[]' });

    await runner.ensureRuntime('jest', dir);

    expect(state.execCommands.some((c) => c.includes('mise install'))).toBe(false);
  });

  it('installs the Erlang version the repository declares before its Elixir', async () => {
    const dir = path.join(FIXTURES, 'elixir-erlang');
    const versions: Record<string, string> = { elixir: '1.15.7', erlang: '26.1' };
    state.mise = (_cwd, args) => ({ stdout: miseLs(versions[args[3]], path.join(dir, '.tool-versions')) });

    await runner.ensureRuntime('exunit', dir);

    const erlang = state.execCommands.findIndex((c) => c.includes('mise install erlang@26.1'));
    const elixir = state.execCommands.findIndex((c) => c.includes('mise install elixir@1.15.7'));
    expect(erlang).toBeGreaterThanOrEqual(0);
    expect(erlang).toBeLessThan(elixir);
    expect(state.execCommands.some((c) => c.includes('erlang@latest'))).toBe(false);
  });

  describe('version files mise does not read itself', () => {
    let dir: string;

    beforeEach(async () => {
      dir = await fs.mkdtemp(path.join(os.tmpdir(), 'rsolv-version-file-'));
      state.mise = () => ({ stdout: '[]' });
    });

    afterEach(async () => {
      await fs.rm(dir, { recursive: true, force: true });
    });

    it.each([
      ['ruby', '.ruby-version', 'ruby-3.4.1', '3.4.1'],
      ['ruby', '.ruby-version', 'ruby-3.3.0\n', '3.3.0'],
      ['ruby', '.ruby-version', 'ruby-3.4.1\r\n', '3.4.1'],
      ['ruby', '.ruby-version', '3.2.2@myapp', '3.2.2'],
      ['ruby', '.ruby-version', 'ruby-3.1.4@myapp\n', '3.1.4'],
      ['ruby', '.ruby-version', '# rvm\n  3.2.2  \n', '3.2.2'],
      ['ruby', '.ruby-version', '3.3.6', '3.3.6'],
      ['ruby', '.ruby-version', 'jruby-9.4.5.0', 'jruby-9.4.5.0'],
      ['ruby', '.ruby-version', 'system', undefined],
      ['ruby', '.ruby-version', '3.3.0; touch /tmp/pwned', undefined],
      ['python', '.python-version', '3.12.7', '3.12.7'],
      ['python', '.python-version', '3.12.7\n3.11.9\n', '3.12.7'],
      ['python', '.python-version', 'system', undefined],
      ['python', '.python-version', 'my-project-venv', undefined],
      ['node', '.nvmrc', 'v20.11.0', '20.11.0'],
      ['node', '.nvmrc', 'lts/iron', 'lts/iron'],
      ['node', '.nvmrc', 'lts/*', 'lts'],
      ['node', '.nvmrc', 'node', undefined],
      ['node', '.node-version', '20.11.0\n', '20.11.0'],
      ['ruby', '.tool-versions', 'ruby 3.3.0 # pinned\n', '3.3.0'],
      ['python', '.tool-versions', 'python 3.12.7 3.11.9\n', '3.12.7'],
    ])('reads %s from %s %j as mise version %j', async (runtime, file, content, expected) => {
      await fs.writeFile(path.join(dir, file), content);

      await expect(runner.detectRuntimeVersion(runtime, dir)).resolves.toBe(expected);
    });

    it('installs ruby 3.4.1 for the .ruby-version a stock `rails new` writes', async () => {
      await fs.writeFile(path.join(dir, '.ruby-version'), 'ruby-3.4.1\n');

      await runner.ensureRuntime('rspec', dir);

      expect(state.execCommands.some((c) => c.includes('mise install ruby@3.4.1 '))).toBe(true);
      expect(state.execCommands.some((c) => c.includes('ruby@ruby-'))).toBe(false);
    });
  });
});
