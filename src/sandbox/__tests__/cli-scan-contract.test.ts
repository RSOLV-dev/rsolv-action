/**
 * The scan subcommand's contract with the host (3c "Sandbox CLI contract",
 * rsolv-host ScanRelay): its stdout carries frames only, and it writes nothing
 * to fd 2, because the host merges stderr into the frame channel. This runs
 * the CLI as it ships, built with build:sandbox's bundler settings.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { execFileSync, spawn } from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { fakeHost } from './fake-host.js';

const REPO = path.resolve(__dirname, '../../..');

describe('rsolv-sandbox scan, built', () => {
  let out: string;
  let work: string;

  beforeAll(() => {
    out = fs.mkdtempSync(path.join(os.tmpdir(), 'rsolv-sandbox-build-'));
    execFileSync('bun', ['build', 'src/sandbox/cli.ts', '--outdir', out, '--target', 'node', '--minify'], { cwd: REPO, stdio: 'ignore' });
    fs.copyFileSync(path.join(REPO, 'src/security/detector-worker.js'), path.join(out, 'detector-worker.js'));
    work = fs.mkdtempSync(path.join(os.tmpdir(), 'rsolv-scan-contract-'));
    fs.writeFileSync(path.join(work, 'app.js'), 'app.get("/", (req, res) => res.send(eval(req.query.x)));\n');
  }, 60_000);

  afterAll(() => {
    fs.rmSync(out, { recursive: true, force: true });
    fs.rmSync(work, { recursive: true, force: true });
  });

  it('writes frames only to stdout, nothing to fd 2, and exits 0 after done', async () => {
    const host = fakeHost({
      ensure_labels: () => ({ ok: true }),
      patterns: (args) => ({
        ok: {
          patterns: args.language === 'javascript'
            ? [{ id: 'js-eval', name: 'eval', type: 'code_injection', description: 'eval', severity: 'critical', regex: ['eval\\('], languages: ['javascript'], recommendation: 'no', cwe_id: 'CWE-95' }]
            : [],
        },
      }),
      severity_tiers: () => ({ ok: { tiers: {} } }),
      validate: () => ({ error: 'call limit' }),
      plan: () => ({ ok: null }),
      list_issues: () => ({ ok: [] }),
      create_issue: () => ({ ok: { number: 3, html_url: 'https://github.com/acme/app/issues/3' } }),
    });
    const env = { PATH: process.env.PATH ?? '', HOME: os.tmpdir(), LOG_LEVEL: 'debug', NODE_OPTIONS: '--trace-warnings' };
    const child = spawn(process.execPath, [path.join(out, 'cli.js'), 'scan'], { cwd: work, env, stdio: ['pipe', 'pipe', 'pipe'] });
    const stderr: Buffer[] = [];
    child.stderr.on('data', (chunk: Buffer) => stderr.push(chunk));
    host.toSandbox.pipe(child.stdin);
    child.stdout.pipe(host.writer);

    host.send({ repository: 'acme/app', max_issues: 3, issue_label: 'rsolv:detected' });
    const code = await new Promise<number | null>((resolve) => child.on('close', resolve));
    const done = await host.served;

    expect(Buffer.concat(stderr).toString('utf-8')).toBe('');
    expect(done?.call).toBe('done');
    expect((done?.args.issues as Array<{ number: number }>).map((i) => i.number)).toEqual([3]);
    expect(code).toBe(0);
  }, 60_000);
});
