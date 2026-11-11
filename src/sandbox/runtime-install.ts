/**
 * Runtime installs in the v5 sandbox (non-root, behind the egress proxy), per
 * the owner's 2026-11-07 decisions (RFC-150 3d):
 *
 * - Python keeps mise's GitHub attestation check. Only when mise reports that
 *   the version asked for has no attestations at all does it fall back, to the
 *   newest attested patch of the same minor. A failed verification, or a
 *   transient error that outlasts its retries, fails; the minor never changes.
 * - PHP is built from source with bounded CPU and time; a version mise doesn't
 *   know, or a build that fails, fails, with nothing substituted.
 * - Maven's distribution download is retried with exponential backoff and
 *   jitter, for the same exact version, under attempt and time caps.
 *
 * Each install returns a RuntimeReport, which the host turns into annotations.
 */

import { execFile } from 'child_process';

export interface RunResult {
  code: number;
  stdout: string;
  stderr: string;
}

export type Run = (
  file: string,
  args: string[],
  opts?: { timeoutMs?: number; env?: NodeJS.ProcessEnv }
) => Promise<RunResult>;

export interface Clock {
  now(): number;
  sleep(ms: number): Promise<void>;
  /** In [0, 1). */
  random(): number;
}

export interface RuntimeReport {
  runtime: 'python' | 'php' | 'maven';
  requested: string;
  actual?: string;
  status: 'installed' | 'fallback' | 'failed';
  reason?: string;
  /** The downloaded build and its digest, when mise names them. */
  artifact?: string;
}

interface Deps {
  run: Run;
  clock: Clock;
}

export type FailureKind = 'no_attestations' | 'verification_failed' | 'transient' | 'failed';

const TRANSIENT =
  /error sending request|timed out|connection (?:reset|refused|closed)|HTTP status server error|\b(?:502|503|504) |GitHub API returned (?:429|5\d\d)|HTTP error:|Trust root error:/i;

/**
 * Classifies a failed `mise install <spec>` from its output. Missing
 * attestations count only in mise's exact message for `spec`; anything else in
 * the attestation step (a failed signature, workflow, repository or subject
 * check, or a lockfile provenance downgrade) is a verification failure, unless
 * it's a network or server error, which is transient.
 */
export function classifyMiseFailure(output: string, spec: string): FailureKind {
  const verification = output.match(/GitHub artifact attestations verification failed for \S+?(?::\s*(.*))?$/m);
  if (verification) return TRANSIENT.test(verification[1] ?? '') ? 'transient' : 'verification_failed';
  if (/^Lockfile requires .* provenance/m.test(output)) return 'verification_failed';
  if (TRANSIENT.test(output)) return 'transient';
  if (output.includes(`No GitHub artifact attestations found for ${spec}\n`)) return 'no_attestations';
  return 'failed';
}

export interface RetryPolicy {
  attempts: number;
  maxTotalMs: number;
  baseMs: number;
}

/**
 * Runs `op` until it returns `{ retry: false }`, at most `attempts` times,
 * waiting `baseMs * 2^n`, scaled by a jitter of 50–100%, between attempts. It
 * never starts a wait that would end past `maxTotalMs`, and passes each attempt
 * the time left, which the attempt must use as its timeout.
 */
export async function withRetry<T>(
  op: (remainingMs: number) => Promise<{ retry: true } | { retry: false; value: T }>,
  policy: RetryPolicy,
  clock: Clock
): Promise<{ value: T | undefined; attempts: number; exhausted?: true }> {
  const deadline = clock.now() + policy.maxTotalMs;
  for (let attempt = 1; ; attempt++) {
    const outcome = await op(deadline - clock.now());
    if (!outcome.retry) return { value: outcome.value, attempts: attempt };

    const delay = policy.baseMs * 2 ** (attempt - 1) * (0.5 + clock.random() / 2);
    if (attempt >= policy.attempts || clock.now() + delay >= deadline) {
      return { value: undefined, attempts: attempt, exhausted: true };
    }
    await clock.sleep(delay);
  }
}

const RETRY: RetryPolicy = { attempts: 3, maxTotalMs: 300_000, baseMs: 2_000 };
const MAVEN_RETRY: RetryPolicy = { attempts: 4, maxTotalMs: 300_000, baseMs: 2_000 };
const PYTHON_FALLBACK_CANDIDATES = 3;

type Attempt = { ok: true; output: string } | { ok: false; kind: FailureKind };

/** `mise install -v <spec>`, retrying only transient failures. */
async function miseInstall(spec: string, deps: Deps, policy: RetryPolicy = RETRY): Promise<Attempt> {
  const result = await withRetry<Attempt>(
    async (remainingMs) => {
      const { code, stdout, stderr } = await deps.run('mise', ['install', '-v', spec], { timeoutMs: remainingMs });
      const output = `${stdout}\n${stderr}`;
      if (code === 0) return { retry: false, value: { ok: true, output } };
      const kind = classifyMiseFailure(output, spec);
      console.warn(`[runtime] mise install ${spec} failed (${kind}): ${output.trim().slice(-500)}`);
      return kind === 'transient' ? { retry: true } : { retry: false, value: { ok: false, kind } };
    },
    policy,
    deps.clock
  );
  return result.value ?? { ok: false, kind: 'transient' };
}

function pythonArtifact(output: string): string | undefined {
  const file = output.match(/\bdownload (cpython-\S+\.tar\.(?:gz|zst))/)?.[1];
  const digest = output.match(/attestations\/(sha256:[0-9a-f]{64})/)?.[1];
  return file && [file, digest].filter(Boolean).join(' ');
}

const FAILURE_REASON: Record<Exclude<FailureKind, 'no_attestations'>, string> = {
  verification_failed: 'verification_failed',
  transient: 'transient',
  failed: 'install_failed',
};

/**
 * Installs Python `requested`. With `exact`, a version with no attestations
 * fails instead of falling back. A fallback is linked under the requested
 * version (`mise link`), so the repository's pin resolves to it unchanged.
 */
export async function installPython(
  requested: string,
  deps: Deps & { exact?: boolean }
): Promise<RuntimeReport> {
  const failed = (reason: string): RuntimeReport => ({ runtime: 'python', requested, status: 'failed', reason });
  const first = await miseInstall(`python@${requested}`, deps);
  if (first.ok) {
    return { runtime: 'python', requested, actual: requested, status: 'installed', ...artifact(first.output) };
  }
  if (first.kind !== 'no_attestations') return failed(FAILURE_REASON[first.kind]);

  const minor = requested.match(/^(\d+\.\d+)\.\d+$/)?.[1];
  if (deps.exact || !minor) return failed('no_attestations');

  const remote = await deps.run('mise', ['ls-remote', 'python', minor], { timeoutMs: 60_000 });
  const patch = (v: string): number => Number(v.split('.')[2]);
  const candidates = remote.stdout
    .split('\n')
    .map((v) => v.trim())
    .filter((v) => v.startsWith(`${minor}.`) && /^\d+\.\d+\.\d+$/.test(v) && v !== requested)
    .sort((a, b) => patch(b) - patch(a))
    .slice(0, PYTHON_FALLBACK_CANDIDATES);

  for (const candidate of candidates) {
    const attempt = await miseInstall(`python@${candidate}`, deps);
    if (!attempt.ok) {
      if (attempt.kind === 'no_attestations') continue;
      return failed(FAILURE_REASON[attempt.kind]);
    }

    const where = await deps.run('mise', ['where', `python@${candidate}`]);
    const link = await deps.run('mise', ['link', '--force', `python@${requested}`, where.stdout.trim()]);
    if (where.code !== 0 || link.code !== 0) return failed('install_failed');
    console.warn(`[runtime] python ${requested} has no attestations; using ${candidate}, the newest attested ${minor} patch`);
    return { runtime: 'python', requested, actual: candidate, status: 'fallback', ...artifact(attempt.output) };
  }
  return failed('no_attested_patch');
}

function artifact(output: string): { artifact?: string } {
  const found = pythonArtifact(output);
  return found ? { artifact: found } : {};
}

/**
 * Builds PHP `requested` (or the latest) from source as the sandbox user,
 * niced, with at most `jobs` make jobs (vfox-php runs `make -j$(nproc)`, and
 * nproc honours OMP_NUM_THREADS) and killed after `timeoutS`.
 */
export async function installPhp(
  requested: string | undefined,
  deps: Deps & { jobs: number; timeoutS: number }
): Promise<RuntimeReport> {
  const spec = requested ?? 'latest';
  const failed = (reason: string): RuntimeReport => ({ runtime: 'php', requested: spec, status: 'failed', reason });

  if (requested) {
    const remote = await deps.run('mise', ['ls-remote', 'php'], { timeoutMs: 60_000 });
    const known = remote.stdout.split('\n').some((v) => v.trim() === requested || v.trim().startsWith(`${requested}.`));
    if (!known) return failed('unsupported');
  }

  const { code, stderr } = await deps.run(
    'timeout',
    ['-k', '30', String(deps.timeoutS), 'nice', '-n', '10', 'mise', 'install', `php@${spec}`],
    {
      // PEAR's installer fetches go-pear.phar from pear.php.net, which the proxy
      // doesn't allow; Composer replaces it. Appended options win in configure.
      env: { ...process.env, OMP_NUM_THREADS: String(deps.jobs), PHP_EXTRA_CONFIGURE_OPTIONS: '--without-pear' },
      timeoutMs: (deps.timeoutS + 60) * 1000,
    }
  );
  if (code === 124 || code === 137) return failed('timeout');
  if (code !== 0) {
    console.warn(`[runtime] php ${spec} build failed: ${stderr.trim().slice(-1000)}`);
    return failed('build_failed');
  }
  return { runtime: 'php', requested: spec, actual: spec, status: 'installed' };
}

/** Installs the latest Maven, resolved once to an exact version, retrying a failed download of it. */
export async function installMaven(deps: Deps): Promise<RuntimeReport> {
  const latest = await deps.run('mise', ['latest', 'maven'], { timeoutMs: 60_000 });
  const version = latest.stdout.trim();
  if (latest.code !== 0 || !/^\d+\.\d+\.\d+$/.test(version)) {
    return { runtime: 'maven', requested: 'latest', status: 'failed', reason: 'unresolved' };
  }

  const installed = await miseInstall(`maven@${version}`, deps, MAVEN_RETRY);
  if (!installed.ok) {
    const reason = installed.kind === 'transient' ? 'transient' : 'install_failed';
    return { runtime: 'maven', requested: version, status: 'failed', reason };
  }
  await deps.run('mise', ['use', '--global', `maven@${version}`]);
  return { runtime: 'maven', requested: version, actual: version, status: 'installed' };
}

/** The real `run`: execFile with no shell; a timeout reads as exit 124, like timeout(1). */
export const run: Run = (file, args, opts = {}) =>
  new Promise((resolve) => {
    execFile(
      file,
      args,
      { timeout: opts.timeoutMs, env: opts.env, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024, killSignal: 'SIGKILL' },
      (error, stdout, stderr) => {
        const err = error as (NodeJS.ErrnoException & { killed?: boolean; code?: number | string }) | null;
        const code = !err ? 0 : err.killed ? 124 : typeof err.code === 'number' ? err.code : 1;
        resolve({ code, stdout: String(stdout ?? ''), stderr: String(stderr ?? '') });
      }
    );
  });

export const clock: Clock = {
  now: () => Date.now(),
  sleep: (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
  random: () => Math.random(),
};
