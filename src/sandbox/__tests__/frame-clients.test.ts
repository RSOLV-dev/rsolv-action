import { describe, it, expect, beforeEach, vi } from 'vitest';
import { fakeHost, type HostTable } from './fake-host.js';
import { HostChannel, HostError, FramePatternSource, FrameScanPlatform, FrameForgeAdapter } from '../frame-clients.js';
import { IssueCreator } from '../../scanner/issue-creator.js';
import { VulnerabilityType, type Vulnerability } from '../../security/types.js';
import type { ScanConfig } from '../../scanner/types.js';

// The host's label allowlist (rsolv-host ScanRelay.allowed_label?/1, 3c Task 24)
const FIXED_LABELS = ['security', 'automated-scan', 'critical', 'high', 'medium', 'low'];
const LABEL = /^rsolv:(detected|vuln-[a-z0-9_-]{1,40}|cwe-(CWE-)?[0-9]{1,5})$/;
const hostAllows = (label: string): boolean => FIXED_LABELS.includes(label) || LABEL.test(label);

function channelFor(table: HostTable) {
  const host = fakeHost(table);
  return { host, channel: new HostChannel(host.reader, host.writer) };
}

describe('HostChannel', () => {
  it('sends {call, args} and resolves with the ok value', async () => {
    const { host, channel } = channelFor({ severity_tiers: () => ({ ok: { tiers: { 'CWE-89': 'high' } } }) });

    await expect(channel.call('severity_tiers', {})).resolves.toEqual({ tiers: { 'CWE-89': 'high' } });
    expect(host.received).toEqual([{ call: 'severity_tiers', args: {} }]);
  });

  it('rejects with a HostError carrying the host\'s message', async () => {
    const { channel } = channelFor({ plan: () => ({ error: 'invalid arguments' }) });

    await expect(channel.call('plan', {})).rejects.toEqual(new HostError('invalid arguments'));
  });

  it('serializes concurrent calls: one frame out, one answer in, in order', async () => {
    let n = 0;
    const { host, channel } = channelFor({ severity_tiers: () => ({ ok: ++n }) });

    const answers = await Promise.all([1, 2, 3].map(() => channel.call('severity_tiers', {})));

    expect(answers).toEqual([1, 2, 3]);
    expect(host.received).toHaveLength(3);
  });
});

describe('FramePatternSource', () => {
  const apiPattern = {
    id: 'js-eval',
    name: 'eval',
    type: 'code_injection',
    description: 'eval of user input',
    severity: 'critical',
    regex: ['eval\\('],
    languages: ['javascript'],
    recommendation: 'avoid eval',
    cwe_id: 'CWE-95',
  };

  it('asks the host for a language\'s patterns and maps them as ApiPatternSource does', async () => {
    const { host, channel } = channelFor({ patterns: () => ({ ok: { patterns: [apiPattern] } }) });

    const [pattern] = await new FramePatternSource(channel).getPatternsByLanguage('python');

    expect(host.received).toEqual([{ call: 'patterns', args: { language: 'python' } }]);
    expect(pattern).toMatchObject({ id: 'js-eval', type: VulnerabilityType.CODE_INJECTION, cweId: 'CWE-95' });
    expect(pattern.patterns.regex[0].test('eval(x)')).toBe(true);
  });

  it('asks once per language, however many files use it', async () => {
    const { host, channel } = channelFor({ patterns: () => ({ ok: { patterns: [apiPattern] } }) });
    const source = new FramePatternSource(channel);

    await source.getPatternsByLanguage('JavaScript');
    await source.getPatternsByLanguage('javascript');

    expect(host.received).toHaveLength(1);
  });
});

describe('FrameScanPlatform', () => {
  it('validate sends the request with the repository', async () => {
    const answer = { validated: [], stats: { total: 0, validated: 0, rejected: 0 } };
    const { host, channel } = channelFor({ validate: () => ({ ok: answer }) });
    const request = { vulnerabilities: [{ id: 'v' }], files: { 'a.js': { content: 'x' } } };

    await expect(new FrameScanPlatform(channel, 'acme/app').validateVulnerabilities(request as never))
      .resolves.toEqual(answer);
    expect(host.received).toEqual([
      { call: 'validate', args: { body: { ...request, repository: 'acme/app' } } },
    ]);
  });

  it('plan sends the request as the body and returns the plan', async () => {
    const plan = { selected: [], deferred: [], budget: {} };
    const { host, channel } = channelFor({ plan: () => ({ ok: plan }) });
    const request = { findings: [], max_issues: 3, namespace: 'acme/app' };

    await expect(new FrameScanPlatform(channel, 'acme/app').plan(request)).resolves.toEqual(plan);
    expect(host.received).toEqual([{ call: 'plan', args: { body: request } }]);
  });

  it('severityTiers returns the tiers', async () => {
    const { channel } = channelFor({ severity_tiers: () => ({ ok: { tiers: { 'CWE-79': 'high' } } }) });

    await expect(new FrameScanPlatform(channel, 'acme/app').severityTiers()).resolves.toEqual({ 'CWE-79': 'high' });
  });
});

describe('FrameForgeAdapter', () => {
  it('listIssues maps to list_issues with the label list', async () => {
    const { host, channel } = channelFor({
      list_issues: () => ({
        ok: [{ number: 4, title: 't', state: 'open', html_url: 'https://github.com/acme/app/issues/4', labels: ['rsolv:detected'] }],
      }),
    });

    const issues = await new FrameForgeAdapter(channel).listIssues('acme', 'app', 'rsolv:detected', 'open');

    expect(host.received).toEqual([{ call: 'list_issues', args: { labels: ['rsolv:detected'] } }]);
    expect(issues).toEqual([
      { number: 4, title: 't', url: 'https://github.com/acme/app/issues/4', labels: ['rsolv:detected'], state: 'open' },
    ]);
  });

  it('createIssue maps to create_issue and remembers what it posted', async () => {
    const { host, channel } = channelFor({ create_issue: () => ({ ok: { number: 9, html_url: 'https://github.com/acme/app/issues/9' } }) });
    const forge = new FrameForgeAdapter(channel);

    const issue = await forge.createIssue('acme', 'app', { title: 'T', body: 'B', labels: ['security'] });

    expect(host.received).toEqual([{ call: 'create_issue', args: { title: 'T', body: 'B', labels: ['security'] } }]);
    expect(issue).toEqual({ number: 9, title: 'T', url: 'https://github.com/acme/app/issues/9', labels: ['security'], state: 'open' });
    expect(forge.posted.get(9)).toEqual({ title: 'T', body: 'B' });
  });

  it.each(['addLabels', 'createComment', 'updateIssue', 'removeLabel', 'createPullRequest', 'listPullRequests', 'getFileTree', 'getFileContent'] as const)(
    '%s is not available in the sandbox scan',
    async (method) => {
      const { channel } = channelFor({});
      const forge = new FrameForgeAdapter(channel) as unknown as Record<string, () => Promise<unknown>>;

      await expect(forge[method]()).rejects.toThrow('not available in the sandbox scan');
    }
  );

  describe('with IssueCreator (label contract, 3c Task 24)', () => {
    const finding = (type: VulnerabilityType, severity: Vulnerability['severity'], cweId: string, filePath: string): Vulnerability => ({
      type,
      severity,
      cweId,
      filePath,
      line: 3,
      message: `${type} in ${filePath}`,
      description: `${type} found`,
      confidence: 80,
      remediation: 'fix it',
    } as Vulnerability);

    const config: ScanConfig = {
      repository: { owner: 'acme', name: 'app', defaultBranch: 'HEAD' },
      createIssues: true,
      issueLabel: 'rsolv:detected',
    };

    beforeEach(() => {
      vi.stubEnv('RSOLV_DEMO_MODE', '');
      vi.stubEnv('RSOLV_AUTO_FIX', '');
    });

    const types = Object.values(VulnerabilityType);
    const severities: Array<Vulnerability['severity']> = ['critical', 'high', 'medium', 'low'];

    it('only ever puts labels the host allows, for every vulnerability type and severity, and never needs the unavailable calls', async () => {
      let number = 100;
      const { host, channel } = channelFor({
        list_issues: () => ({
          ok: [{ number: 50, title: '[CWE-79] XSS in app/old.js:1', state: 'open', html_url: 'u', labels: ['rsolv:detected', 'rsolv:cwe-CWE-79'] }],
        }),
        create_issue: () => ({ ok: { number: ++number, html_url: `https://github.com/acme/app/issues/${number}` } }),
      });
      const forge = new FrameForgeAdapter(channel);
      const unavailable = ['addLabels', 'createComment', 'updateIssue'].map((m) => vi.spyOn(forge, m as 'addLabels'));

      const result = await new IssueCreator(forge).createIssuesFromFindings(
        [
          finding(VulnerabilityType.XSS, 'high', 'CWE-79', 'app/old.js'),
          ...types.map((type, i) => finding(type, severities[i % 4], `CWE-${20 + i}`, `app/f${i}.js`)),
        ],
        config
      );

      const labels = host.received.filter((f) => f.call === 'create_issue').flatMap((f) => f.args.labels as string[]);
      expect(result.issues).toHaveLength(types.length);
      expect(labels.length).toBeGreaterThan(0);
      expect(labels.filter((label) => !hostAllows(label))).toEqual([]);
      unavailable.forEach((spy) => expect(spy).not.toHaveBeenCalled());
    });
  });
});
