import { execFile } from 'child_process';
import { promisify } from 'util';

const execFileAsync = promisify(execFile);

const MAX_DIFF_BYTES = 6 * 1024 * 1024;

/**
 * `rsolv-sandbox patch` (RFC-150 §4.1): the working tree's diff against
 * `base_sha`, untracked files included, read from git's stdout only so no
 * warning text reaches the patch bytes.
 */
export async function runPatch(request: unknown): Promise<Record<string, unknown>> {
  const { base_sha: baseSha } = (request ?? {}) as { base_sha?: unknown };
  if (typeof baseSha !== 'string' || !/^[0-9a-f]{40}$/.test(baseSha)) return { error: 'invalid base_sha' };

  await execFileAsync('git', ['add', '-A', '--intent-to-add']);
  const { stdout } = await execFileAsync(
    'git',
    ['-c', 'core.autocrlf=false', 'diff', '--binary', '--full-index', '--no-renames', '--no-textconv', '--no-ext-diff', baseSha],
    { encoding: 'buffer', maxBuffer: MAX_DIFF_BYTES }
  );
  return { patch: stdout.toString('base64') };
}
