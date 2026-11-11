import { describe, it, expect } from 'vitest';
import {
  classifyMiseFailure,
  installMaven,
  installPhp,
  installPython,
  withRetry,
  type Clock,
  type Run,
  type RunResult,
} from '../runtime-install.js';

const NO_ATTESTATIONS = (v: string): string =>
  `mise ERROR Failed to install core:python@${v}: No GitHub artifact attestations found for python@${v}\n` +
  'To disable attestation verification, set MISE_PYTHON_GITHUB_ATTESTATIONS=false\n';
const VERIFY_FAILED = (v: string, inner = 'Verification failed: signature mismatch'): string =>
  `mise ERROR Failed to install core:python@${v}: GitHub artifact attestations verification failed for python@${v}: ${inner}\n`;
const TRANSIENT = 'mise ERROR error sending request for url (https://github.com/astral-sh/...): operation timed out\n';
const DOWNLOADED = (v: string): string =>
  `INFO  python@${v}  [1/3] download cpython-${v}+20261026-x86_64-unknown-linux-gnu-install_only_stripped.tar.gz\n` +
  'DEBUG GET https://mise-versions.jdx.dev/api/github/repos/astral-sh/python-build-standalone/attestations/sha256:' +
  `${'ab'.repeat(32)}\n`;

const ok = (stdout = '', stderr = ''): RunResult => ({ code: 0, stdout, stderr });
const fail = (stderr: string, code = 1): RunResult => ({ code, stdout: '', stderr });

/** A fake `run`: answers each call with the first matching script entry, recording the argv. */
function fakeRun(script: Array<[(argv: string[]) => boolean, RunResult | RunResult[]]>): Run & { calls: string[][] } {
  const calls: string[][] = [];
  const run = (async (file: string, args: string[]) => {
    const argv = [file, ...args];
    calls.push(argv);
    const entry = script.find(([match]) => match(argv));
    if (!entry) return ok();
    const [, answer] = entry;
    return Array.isArray(answer) ? (answer.length > 1 ? answer.shift()! : answer[0]) : answer;
  }) as Run & { calls: string[][] };
  run.calls = calls;
  return run;
}

const has = (...words: string[]) => (argv: string[]): boolean => words.every((w) => argv.includes(w));

function fakeClock(random = 0.5): Clock & { slept: number[]; t: number } {
  const clock = {
    t: 0,
    slept: [] as number[],
    now: () => clock.t,
    sleep: async (ms: number) => {
      clock.slept.push(ms);
      clock.t += ms;
    },
    random: () => random,
  };
  return clock;
}

const installs = (calls: string[][]): string[] =>
  calls.filter((c) => c.includes('install')).map((c) => c.find((a) => a.includes('@'))!);

describe('classifyMiseFailure', () => {
  it('recognises the no-attestations condition for the version asked for', () => {
    expect(classifyMiseFailure(NO_ATTESTATIONS('3.11.9'), 'python@3.11.9')).toBe('no_attestations');
  });

  it('doesn\'t treat another version\'s missing attestations as this one\'s', () => {
    expect(classifyMiseFailure(NO_ATTESTATIONS('3.11.8'), 'python@3.11.9')).toBe('failed');
  });

  it.each([
    ['a failed signature check', VERIFY_FAILED('3.12.1')],
    ['a bare verification failure', 'GitHub artifact attestations verification failed for python@3.12.1\nTo disable'],
    ['an attestation from another repository', VERIFY_FAILED('3.12.1', 'Repository verification failed: expected x/y, found a/b')],
    ['a SLSA subject mismatch', VERIFY_FAILED('3.12.1', 'SLSA subject mismatch: digest')],
    ['an API refusal', VERIFY_FAILED('3.12.1', 'API error: GitHub API returned 401 Unauthorized: {}')],
    ['a lockfile provenance downgrade', 'Lockfile requires github-attestations provenance for python@3.12.1 but no verification was used.'],
  ])('treats %s as a verification failure', (_name, output) => {
    expect(classifyMiseFailure(output, 'python@3.12.1')).toBe('verification_failed');
  });

  it.each([
    ['a network error while verifying', VERIFY_FAILED('3.12.1', 'HTTP error: error sending request for url')],
    ['a 503 from the attestations API', VERIFY_FAILED('3.12.1', 'API error: GitHub API returned 503 Service Unavailable: x')],
    ['a 429 from the attestations API', VERIFY_FAILED('3.12.1', 'API error: GitHub API returned 429 Too Many Requests: x')],
    ['an unreachable trust root', VERIFY_FAILED('3.12.1', 'Trust root error: tuf fetch failed')],
    ['a download timeout', TRANSIENT],
    ['a 502 on the download', 'HTTP status server error (502 Bad Gateway) for url (https://github.com/x)'],
    ['a reset connection', 'error: connection reset by peer'],
  ])('treats %s as transient', (_name, output) => {
    expect(classifyMiseFailure(output, 'python@3.12.1')).toBe('transient');
  });

  it('treats a refused download (the proxy says 403) as a plain failure', () => {
    expect(classifyMiseFailure('HTTP status client error (403 Forbidden) for url (https://x)', 'python@3.12.1')).toBe(
      'failed'
    );
  });

  it('never reads a verification failure as missing attestations, even when both are printed', () => {
    expect(classifyMiseFailure(NO_ATTESTATIONS('3.12.1') + VERIFY_FAILED('3.12.1'), 'python@3.12.1')).toBe(
      'verification_failed'
    );
  });
});

describe('withRetry', () => {
  const policy = { attempts: 4, maxTotalMs: 60_000, baseMs: 1_000 };

  it('backs off exponentially with jitter between retryable failures', async () => {
    const clock = fakeClock(0.5);
    let calls = 0;
    const result = await withRetry(
      async () => (++calls < 4 ? { retry: true as const } : { retry: false as const, value: 'done' }),
      policy,
      clock
    );

    expect(result).toEqual({ value: 'done', attempts: 4 });
    // base * 2^n, scaled into [50%, 100%] by the jitter (0.5 → 75%)
    expect(clock.slept).toEqual([750, 1500, 3000]);
  });

  it('spreads the delay with the random source', async () => {
    const low = fakeClock(0);
    const high = fakeClock(0.999);
    const op = async () => ({ retry: true as const });
    await withRetry(op, { ...policy, attempts: 2 }, low);
    await withRetry(op, { ...policy, attempts: 2 }, high);

    expect(low.slept).toEqual([500]);
    expect(high.slept[0]).toBeGreaterThan(990);
  });

  it('stops at the attempt cap', async () => {
    const clock = fakeClock();
    let calls = 0;
    const result = await withRetry(async () => (calls++, { retry: true as const }), policy, clock);

    expect(calls).toBe(4);
    expect(result).toEqual({ value: undefined, attempts: 4, exhausted: true });
  });

  it('stops when the next wait would pass the total time cap', async () => {
    const clock = fakeClock(1 - Number.EPSILON);
    let calls = 0;
    // Each attempt takes 10 s, or what's left of the budget, as its timeout would.
    const op = async (remainingMs: number) => (calls++, (clock.t += Math.min(10_000, remainingMs)), { retry: true as const });
    await withRetry(op, { ...policy, attempts: 10, maxTotalMs: 25_000 }, clock);

    // 10 s, wait 1 s, 10 s (21 s), wait 2 s (23 s), the last 2 s; a 4 s wait would pass 25 s
    expect(calls).toBe(3);
    expect(clock.t).toBe(25_000);
  });

  it('gives the remaining time budget to each attempt', async () => {
    const clock = fakeClock();
    const budgets: number[] = [];
    await withRetry(
      async (remainingMs: number) => (budgets.push(remainingMs), (clock.t += 5_000), { retry: true as const }),
      { attempts: 2, maxTotalMs: 20_000, baseMs: 1_000 },
      clock
    );

    expect(budgets).toEqual([20_000, 14_250]);
  });

  it('doesn\'t retry a failure that isn\'t retryable', async () => {
    const clock = fakeClock();
    let calls = 0;
    const result = await withRetry(async () => (calls++, { retry: false as const, value: 'hard' }), policy, clock);

    expect(calls).toBe(1);
    expect(result.value).toBe('hard');
    expect(clock.slept).toEqual([]);
  });
});

describe('installPython', () => {
  it('installs an attested version as asked, recording the artifact', async () => {
    const run = fakeRun([[has('install'), ok('', DOWNLOADED('3.12.7'))]]);

    const report = await installPython('3.12.7', { run, clock: fakeClock() });

    expect(report).toEqual({
      runtime: 'python',
      requested: '3.12.7',
      actual: '3.12.7',
      status: 'installed',
      artifact: `cpython-3.12.7+20261026-x86_64-unknown-linux-gnu-install_only_stripped.tar.gz sha256:${'ab'.repeat(32)}`,
    });
    expect(installs(run.calls)).toEqual(['python@3.12.7']);
  });

  describe('when the version asked for has no attestations', () => {
    const remote = ok(['3.10.16', '3.11.8', '3.11.9', '3.11.10', '3.11.11', '3.11.12rc1', '3.12.7'].join('\n'));

    it('falls back to the newest attested patch of the same minor, with requested and actual versions', async () => {
      const run = fakeRun([
        [has('install', 'python@3.11.9'), fail(NO_ATTESTATIONS('3.11.9'))],
        [has('install', 'python@3.11.11'), ok('', DOWNLOADED('3.11.11'))],
        [has('ls-remote'), remote],
        [has('where'), ok('/opt/home/.local/share/mise/installs/python/3.11.11\n')],
      ]);

      const report = await installPython('3.11.9', { run, clock: fakeClock() });

      expect(report).toMatchObject({ runtime: 'python', requested: '3.11.9', actual: '3.11.11', status: 'fallback' });
      expect(report.artifact).toContain('cpython-3.11.11+20261026');
      expect(installs(run.calls)).toEqual(['python@3.11.9', 'python@3.11.11']);
    });

    it('makes the fallback answer for the repository\'s pin without changing it', async () => {
      const run = fakeRun([
        [has('install', 'python@3.11.9'), fail(NO_ATTESTATIONS('3.11.9'))],
        [has('ls-remote'), remote],
        [has('where'), ok('/opt/home/.local/share/mise/installs/python/3.11.11\n')],
      ]);

      await installPython('3.11.9', { run, clock: fakeClock() });

      expect(run.calls).toContainEqual([
        'mise',
        'link',
        '--force',
        'python@3.11.9',
        '/opt/home/.local/share/mise/installs/python/3.11.11',
      ]);
      expect(run.calls.some((c) => c.includes('use') && !c.includes('--global'))).toBe(false);
    });

    it('tries the next older patch while the newer ones also lack attestations', async () => {
      const run = fakeRun([
        [has('install', 'python@3.11.9'), fail(NO_ATTESTATIONS('3.11.9'))],
        [has('install', 'python@3.11.11'), fail(NO_ATTESTATIONS('3.11.11'))],
        [has('ls-remote'), remote],
      ]);

      const report = await installPython('3.11.9', { run, clock: fakeClock() });

      expect(report).toMatchObject({ status: 'fallback', actual: '3.11.10' });
      expect(installs(run.calls)).toEqual(['python@3.11.9', 'python@3.11.11', 'python@3.11.10']);
    });

    it('never crosses a minor version', async () => {
      const run = fakeRun([
        [has('install'), fail(NO_ATTESTATIONS('3.11.9'))],
        [has('install', 'python@3.11.9'), fail(NO_ATTESTATIONS('3.11.9'))],
        [has('ls-remote'), ok('3.10.16\n3.11.9\n3.12.7\n4.11.20\n')],
      ]);

      const report = await installPython('3.11.9', { run, clock: fakeClock() });

      expect(report).toMatchObject({ requested: '3.11.9', status: 'failed', reason: 'no_attested_patch' });
      expect(installs(run.calls)).toEqual(['python@3.11.9']);
    });

    it('fails instead when the repository requires the exact version', async () => {
      const run = fakeRun([
        [has('install'), fail(NO_ATTESTATIONS('3.11.9'))],
        [has('ls-remote'), remote],
      ]);

      const report = await installPython('3.11.9', { run, clock: fakeClock(), exact: true });

      expect(report).toMatchObject({ requested: '3.11.9', status: 'failed', reason: 'no_attestations' });
      expect(run.calls.some((c) => c.includes('ls-remote'))).toBe(false);
      expect(installs(run.calls)).toEqual(['python@3.11.9']);
    });

    it('stops at a fallback candidate whose verification fails', async () => {
      const run = fakeRun([
        [has('install', 'python@3.11.9'), fail(NO_ATTESTATIONS('3.11.9'))],
        [has('install', 'python@3.11.11'), fail(VERIFY_FAILED('3.11.11'))],
        [has('ls-remote'), remote],
      ]);

      const report = await installPython('3.11.9', { run, clock: fakeClock() });

      expect(report).toMatchObject({ status: 'failed', reason: 'verification_failed' });
      expect(installs(run.calls)).toEqual(['python@3.11.9', 'python@3.11.11']);
    });

    it('has no fallback for a version that is not major.minor.patch', async () => {
      const run = fakeRun([
        [has('install'), fail(NO_ATTESTATIONS('3.11'))],
        [has('ls-remote'), remote],
      ]);

      const report = await installPython('3.11', { run, clock: fakeClock() });

      expect(report).toMatchObject({ status: 'failed', reason: 'no_attestations' });
      expect(installs(run.calls)).toEqual(['python@3.11']);
    });
  });

  it('fails hard on a verification failure, without retrying or falling back', async () => {
    const run = fakeRun([[has('install'), fail(VERIFY_FAILED('3.12.1'))]]);

    const report = await installPython('3.12.1', { run, clock: fakeClock() });

    expect(report).toMatchObject({ requested: '3.12.1', status: 'failed', reason: 'verification_failed' });
    expect(installs(run.calls)).toEqual(['python@3.12.1']);
    expect(run.calls.some((c) => c.includes('ls-remote'))).toBe(false);
  });

  it('retries a transient error, then fails without falling back', async () => {
    const clock = fakeClock();
    const run = fakeRun([[has('install'), fail(TRANSIENT)]]);

    const report = await installPython('3.12.1', { run, clock });

    expect(report).toMatchObject({ requested: '3.12.1', status: 'failed', reason: 'transient' });
    expect(installs(run.calls)).toEqual(['python@3.12.1', 'python@3.12.1', 'python@3.12.1']);
    expect(clock.slept).toHaveLength(2);
    expect(run.calls.some((c) => c.includes('ls-remote'))).toBe(false);
  });

  it('installs after a transient error clears', async () => {
    const run = fakeRun([[has('install'), [fail(TRANSIENT), ok('', DOWNLOADED('3.12.1'))]]]);

    const report = await installPython('3.12.1', { run, clock: fakeClock() });

    expect(report).toMatchObject({ status: 'installed', actual: '3.12.1' });
  });
});

describe('installPhp', () => {
  const remote = ok('8.2.28\n8.3.20\n8.3.21\n');

  it('builds the version asked for with bounded CPU and time', async () => {
    const run = fakeRun([[has('ls-remote'), remote]]);

    const report = await installPhp('8.3.21', { run, clock: fakeClock(), jobs: 2, timeoutS: 720 });

    expect(report).toEqual({ runtime: 'php', requested: '8.3.21', actual: '8.3.21', status: 'installed' });
    const build = run.calls.find((c) => c.includes('install'))!;
    expect(build).toEqual(['timeout', '-k', '30', '720', 'nice', '-n', '10', 'mise', 'install', 'php@8.3.21']);
  });

  it('caps the build jobs through nproc (OMP_NUM_THREADS)', async () => {
    const envs: Array<NodeJS.ProcessEnv | undefined> = [];
    const run: Run = async (file, args, opts) => {
      if (args.includes('install')) envs.push(opts?.env);
      return args.includes('ls-remote') ? remote : ok();
    };

    await installPhp('8.3.21', { run, clock: fakeClock(), jobs: 2, timeoutS: 720 });

    expect(envs[0]).toMatchObject({ OMP_NUM_THREADS: '2' });
  });

  it('builds without PEAR, whose installer would fetch from a host the proxy doesn\'t allow', async () => {
    const envs: Array<NodeJS.ProcessEnv | undefined> = [];
    const run: Run = async (file, args, opts) => {
      if (args.includes('install')) envs.push(opts?.env);
      return args.includes('ls-remote') ? remote : ok();
    };

    await installPhp('8.3.21', { run, clock: fakeClock(), jobs: 2, timeoutS: 720 });

    expect(envs[0]).toMatchObject({ PHP_EXTRA_CONFIGURE_OPTIONS: '--without-pear' });
  });

  it('refuses a version mise does not know, without building anything', async () => {
    const run = fakeRun([[has('ls-remote'), remote]]);

    const report = await installPhp('7.0.99', { run, clock: fakeClock(), jobs: 2, timeoutS: 720 });

    expect(report).toEqual({ runtime: 'php', requested: '7.0.99', status: 'failed', reason: 'unsupported' });
    expect(run.calls.some((c) => c.includes('install'))).toBe(false);
  });

  it('accepts a minor-version pin that mise can resolve', async () => {
    const run = fakeRun([[has('ls-remote'), remote]]);

    const report = await installPhp('8.3', { run, clock: fakeClock(), jobs: 2, timeoutS: 720 });

    expect(report.status).toBe('installed');
  });

  it('fails clearly on a timeout, with no other version tried', async () => {
    const run = fakeRun([
      [has('ls-remote'), remote],
      [has('install'), fail('', 124)],
    ]);

    const report = await installPhp('8.3.21', { run, clock: fakeClock(), jobs: 2, timeoutS: 720 });

    expect(report).toEqual({ runtime: 'php', requested: '8.3.21', status: 'failed', reason: 'timeout' });
    expect(installs(run.calls)).toEqual(['php@8.3.21']);
  });

  it('fails clearly on a failed build, with no other version tried', async () => {
    const run = fakeRun([
      [has('ls-remote'), remote],
      [has('install'), fail('configure: error: OpenSSL 1.1 required')],
    ]);

    const report = await installPhp('8.2.28', { run, clock: fakeClock(), jobs: 2, timeoutS: 720 });

    expect(report).toEqual({ runtime: 'php', requested: '8.2.28', status: 'failed', reason: 'build_failed' });
    expect(installs(run.calls)).toEqual(['php@8.2.28']);
  });

  it('builds the latest version when none is asked for', async () => {
    const run = fakeRun([]);

    const report = await installPhp(undefined, { run, clock: fakeClock(), jobs: 2, timeoutS: 720 });

    expect(report.status).toBe('installed');
    expect(installs(run.calls)).toEqual(['php@latest']);
  });
});

describe('installMaven', () => {
  it('installs the exact latest version once its download succeeds', async () => {
    const run = fakeRun([[has('latest', 'maven'), ok('3.9.11\n')]]);

    const report = await installMaven({ run, clock: fakeClock() });

    expect(report).toEqual({ runtime: 'maven', requested: '3.9.11', actual: '3.9.11', status: 'installed' });
    expect(run.calls).toContainEqual(['mise', 'use', '--global', 'maven@3.9.11']);
  });

  it('retries a timed-out distribution download of the same version, with backoff', async () => {
    const clock = fakeClock();
    const run = fakeRun([
      [has('latest', 'maven'), ok('3.9.11\n')],
      [has('install'), [fail(TRANSIENT), fail(TRANSIENT), ok()]],
    ]);

    const report = await installMaven({ run, clock });

    expect(report.status).toBe('installed');
    expect(installs(run.calls)).toEqual(['maven@3.9.11', 'maven@3.9.11', 'maven@3.9.11']);
    expect(clock.slept).toHaveLength(2);
    expect(clock.slept[1]).toBeGreaterThan(clock.slept[0]);
  });

  it('gives up after the attempt cap and fails clearly', async () => {
    const run = fakeRun([
      [has('latest', 'maven'), ok('3.9.11\n')],
      [has('install'), fail(TRANSIENT)],
    ]);

    const report = await installMaven({ run, clock: fakeClock() });

    expect(report).toEqual({ runtime: 'maven', requested: '3.9.11', status: 'failed', reason: 'transient' });
    expect(installs(run.calls)).toHaveLength(4);
  });

  it('gives up at the total time cap', async () => {
    const clock = fakeClock();
    // Each download hangs for 2 minutes, or until its timeout.
    const run: Run = async (file, args, opts) => {
      if (args.includes('latest')) return ok('3.9.11\n');
      clock.t += Math.min(120_000, opts?.timeoutMs ?? Infinity);
      return fail(TRANSIENT);
    };

    const report = await installMaven({ run, clock });

    expect(report.status).toBe('failed');
    expect(clock.t).toBeLessThanOrEqual(300_000);
  });

  it('doesn\'t retry a failed integrity check', async () => {
    const run = fakeRun([
      [has('latest', 'maven'), ok('3.9.11\n')],
      [has('install'), fail('mise ERROR checksum mismatch for apache-maven-3.9.11-bin.tar.gz')],
    ]);

    const report = await installMaven({ run, clock: fakeClock() });

    expect(report).toMatchObject({ status: 'failed', reason: 'install_failed' });
    expect(installs(run.calls)).toHaveLength(1);
  });
});
