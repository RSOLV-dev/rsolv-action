import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { execFileSync } from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { runPatch } from '../patch.js';

const git = (cwd: string, ...args: string[]): string =>
  execFileSync('git', ['-c', 'user.email=t@example.com', '-c', 'user.name=t', ...args], { cwd, encoding: 'utf-8' });

describe('runPatch', () => {
  let root: string;
  let repo: string;
  let previousCwd: string;
  let baseSha: string;

  beforeEach(() => {
    previousCwd = process.cwd();
    root = fs.mkdtempSync(path.join(os.tmpdir(), 'rsolv-sandbox-patch-'));
    repo = path.join(root, 'work');
    fs.mkdirSync(repo);
    git(repo, 'init', '-q');
    fs.writeFileSync(path.join(repo, 'app.js'), 'const a = 1;\n');
    fs.writeFileSync(path.join(repo, 'logo.bin'), Buffer.from([0, 1, 2, 3]));
    git(repo, 'add', '-A');
    git(repo, 'commit', '-q', '-m', 'base');
    baseSha = git(repo, 'rev-parse', 'HEAD').trim();
    process.chdir(repo);
  });

  afterEach(() => {
    vi.unstubAllEnvs();
    process.chdir(previousCwd);
    fs.rmSync(root, { recursive: true, force: true });
  });

  it('returns a patch that applies to a fresh checkout of base_sha, untracked and CRLF files included', async () => {
    // A user-level core.autocrlf=true would rewrite CRLF in the diff; the patch must not depend on it.
    fs.writeFileSync(path.join(root, 'gitconfig'), '[core]\n\tautocrlf = true\n');
    vi.stubEnv('GIT_CONFIG_GLOBAL', path.join(root, 'gitconfig'));
    fs.writeFileSync('app.js', 'const a = 2;\n');
    fs.writeFileSync('untracked.js', 'new file\n');
    fs.writeFileSync('crlf.txt', 'one\r\ntwo\r\n');
    fs.writeFileSync('logo.bin', Buffer.from([0, 9, 9, 3]));

    const result = await runPatch({ base_sha: baseSha });

    const patch = Buffer.from(result.patch as string, 'base64');
    const text = patch.toString('utf-8');
    expect(text).toContain('untracked.js');
    expect(text).toContain('+one\r\n+two\r\n');
    expect(text).toContain('GIT binary patch');
    expect(text).not.toContain('warning:');

    const fresh = path.join(root, 'fresh');
    git(root, 'clone', '-q', repo, fresh);
    git(fresh, 'checkout', '-q', baseSha);
    fs.writeFileSync(path.join(root, 'fix.patch'), patch);
    git(fresh, 'apply', '--check', path.join(root, 'fix.patch'));
    git(fresh, 'apply', path.join(root, 'fix.patch'));
    expect(fs.readFileSync(path.join(fresh, 'crlf.txt'), 'utf-8')).toBe('one\r\ntwo\r\n');
  });

  it('returns an empty patch when nothing changed', async () => {
    await expect(runPatch({ base_sha: baseSha })).resolves.toEqual({ patch: '' });
  });

  it.each([
    ['short', 'abc123'],
    ['an option', '--output=/tmp/x'],
    ['uppercase', 'A'.repeat(40)],
    ['missing', undefined],
  ])('refuses a base_sha that is %s', async (_label, base_sha) => {
    await expect(runPatch({ base_sha })).resolves.toEqual({ error: 'invalid base_sha' });
  });
});
