import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { fakeHost, type HostTable } from './fake-host.js';
import { runScan } from '../scan.js';

const evalPattern = {
  id: 'js-eval-user-input',
  name: 'eval with user input',
  type: 'code_injection',
  description: 'eval of request data',
  severity: 'critical',
  regex: ['eval\\(\\s*req\\.'],
  languages: ['javascript'],
  recommendation: 'Never eval request data',
  cwe_id: 'CWE-95',
};

type Body = { vulnerabilities: Array<{ id: string }> };
type PlanBody = { findings: unknown[] };

function table(overrides: Partial<HostTable> = {}): HostTable {
  return {
    ensure_labels: () => ({ ok: true }),
    patterns: (args) => ({ ok: { patterns: args.language === 'javascript' ? [evalPattern] : [] } }),
    severity_tiers: () => ({ ok: { tiers: { 'CWE-95': 'critical' } } }),
    validate: (args) => ({
      ok: {
        validated: (args.body as Body).vulnerabilities.map((v) => ({ id: v.id, isValid: true, confidence: 0.9 })),
        stats: { total: 1, validated: 1, rejected: 0 },
      },
    }),
    plan: (args) => ({ ok: { selected: (args.body as PlanBody).findings, deferred: [], budget: { validate_used: 0, validate_limit: 10, effective_cap: 3 } } }),
    list_issues: () => ({ ok: [] }),
    create_issue: () => ({ ok: { number: 7, html_url: 'https://github.com/acme/app/issues/7' } }),
    ...overrides,
  };
}

describe('runScan', () => {
  let work: string;

  beforeEach(() => {
    vi.stubEnv('GITHUB_TOKEN', '');
    vi.stubEnv('RSOLV_API_KEY', '');
    work = fs.mkdtempSync(path.join(os.tmpdir(), 'rsolv-scan-'));
    fs.writeFileSync(path.join(work, 'app.js'), 'app.get("/", (req, res) => {\n  res.send(eval(req.query.x));\n});\n');
    fs.writeFileSync(path.join(work, 'package.json'), '{"name":"app"}');
  });

  afterEach(() => {
    vi.unstubAllEnvs();
    fs.rmSync(work, { recursive: true, force: true });
  });

  async function scan(hostTable: HostTable, config: unknown = { repository: 'acme/app', max_issues: 3, issue_label: 'rsolv:detected' }) {
    const host = fakeHost(hostTable);
    host.send(config);
    const outcome = await runScan(host.reader, host.writer, work).then(
      () => 'resolved',
      (error: Error) => error
    );
    return { host, outcome, done: await host.done() };
  }

  it('ensures the labels first, with only labels the host allows', async () => {
    const { host } = await scan(table());

    expect(host.received[0].call).toBe('ensure_labels');
    const labels = host.received[0].args.labels as Array<{ name: string; color: string; description: string }>;
    expect(labels.map((l) => l.name)).toEqual(['rsolv:detected', 'security', 'automated-scan', 'critical', 'high', 'medium', 'low']);
    labels.forEach((l) => expect(l.color).toMatch(/^[0-9a-f]{6}$/));
  });

  it('scans the local files and ends with done: the issues it filed, the manifests and the files scanned', async () => {
    const { host, outcome, done } = await scan(table());

    expect(outcome).toBe('resolved');
    const created = host.received.find((f) => f.call === 'create_issue')!;
    expect(done).toEqual({
      call: 'done',
      args: {
        issues: [
          {
            number: 7,
            cwe_id: 'CWE-95',
            title: created.args.title,
            body: created.args.body,
            vulnerability: { type: 'code_injection', description: expect.any(String), source: 'app.js', line: 2 },
          },
        ],
        manifest_files: { 'package.json': '{"name":"app"}' },
        files_scanned: ['app.js'],
      },
    });
  });

  it('sends the plan request with the findings', async () => {
    const { host } = await scan(table());

    const plan = host.received.find((f) => f.call === 'plan')!;
    expect(plan.args.body).toMatchObject({ max_issues: 3, findings: [{ cwe_id: 'CWE-95', file_path: 'app.js', line: 2 }] });
  });

  it('ends with an empty issue list when nothing is found', async () => {
    fs.writeFileSync(path.join(work, 'app.js'), 'console.log("fine");\n');

    const { done } = await scan(table());

    expect(done?.args.issues).toEqual([]);
  });

  it('fails without done when the host refuses the plan', async () => {
    const { outcome, done } = await scan(table({ plan: () => ({ error: 'invalid arguments' }) }));

    expect(outcome).toBeInstanceOf(Error);
    expect(done).toBeNull();
  });

  it('keeps the unvalidated findings when the host refuses validation', async () => {
    const { done } = await scan(table({ validate: () => ({ error: 'call limit' }) }));

    expect(done?.args.issues).toHaveLength(1);
  });

  it('carries on when the host refuses the labels', async () => {
    const { done } = await scan(table({ ensure_labels: () => ({ error: 'label not allowed' }) }));

    expect(done?.args.issues).toHaveLength(1);
  });

  it.each([
    [{ repository: 'acme', max_issues: 3, issue_label: 'rsolv:detected' }],
    [{ repository: 'acme/app', max_issues: 0, issue_label: 'rsolv:detected' }],
    [{ repository: 'acme/app', max_issues: 51, issue_label: 'rsolv:detected' }],
    [null],
  ])('refuses the config frame %j', async (config) => {
    const { outcome, host } = await scan(table(), config);

    expect(outcome).toEqual(new Error('bad config'));
    expect(host.received).toEqual([]);
  });
});
