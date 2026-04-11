import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

vi.mock('fs', () => ({
  appendFileSync: vi.fn(),
}));

vi.mock('../../utils/logger.js', () => ({
  logger: {
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    debug: vi.fn(),
  },
}));

import { writeScanSummary, writeProcessSummary } from '../job-summary.js';
import { appendFileSync } from 'fs';

describe('writeScanSummary', () => {
  const summaryFile = '/tmp/test-step-summary';

  beforeEach(() => {
    process.env.GITHUB_STEP_SUMMARY = summaryFile;
    vi.mocked(appendFileSync).mockClear();
  });

  afterEach(() => {
    delete process.env.GITHUB_STEP_SUMMARY;
    vi.mocked(appendFileSync).mockClear();
  });

  it('writes scan summary with created issues', () => {
    writeScanSummary('arubis/test-repo', [
      { number: 1, cwe_id: 'CWE-89' },
      { number: 2, cwe_id: 'CWE-79' },
    ], 5);

    expect(appendFileSync).toHaveBeenCalledWith(
      summaryFile,
      expect.stringContaining('RSOLV Security Scan')
    );
    expect(appendFileSync).toHaveBeenCalledWith(
      summaryFile,
      expect.stringContaining('5')
    );
    expect(appendFileSync).toHaveBeenCalledWith(
      summaryFile,
      expect.stringContaining('CWE-89')
    );
  });

  it('writes clean message when no vulnerabilities found', () => {
    writeScanSummary('arubis/test-repo', [], 0);

    expect(appendFileSync).toHaveBeenCalledWith(
      summaryFile,
      expect.stringContaining('No vulnerabilities detected')
    );
  });

  it('does nothing when GITHUB_STEP_SUMMARY is not set', () => {
    delete process.env.GITHUB_STEP_SUMMARY;

    writeScanSummary('arubis/test-repo', [{ number: 1 }], 1);

    expect(appendFileSync).not.toHaveBeenCalled();
  });
});

describe('writeProcessSummary', () => {
  const summaryFile = '/tmp/test-step-summary';

  beforeEach(() => {
    process.env.GITHUB_STEP_SUMMARY = summaryFile;
    vi.mocked(appendFileSync).mockClear();
  });

  afterEach(() => {
    delete process.env.GITHUB_STEP_SUMMARY;
    vi.mocked(appendFileSync).mockClear();
  });

  it('writes validated result with PR link', () => {
    writeProcessSummary('arubis/test-repo', 42, {
      success: true,
      phase: 'process',
      data: {
        classification: 'validated',
        pr_url: 'https://github.com/arubis/test-repo/pull/123',
      },
    });

    expect(appendFileSync).toHaveBeenCalledWith(
      summaryFile,
      expect.stringContaining('Vulnerability confirmed')
    );
    expect(appendFileSync).toHaveBeenCalledWith(
      summaryFile,
      expect.stringContaining('pull/123')
    );
  });

  it('writes defense confirmed FP result', () => {
    writeProcessSummary('arubis/test-repo', 42, {
      success: true,
      phase: 'process',
      data: { classification: 'false_positive_defense_confirmed' },
    });

    expect(appendFileSync).toHaveBeenCalledWith(
      summaryFile,
      expect.stringContaining('Defense confirmed')
    );
  });

  it('writes counter-indicated FP result', () => {
    writeProcessSummary('arubis/test-repo', 42, {
      success: true,
      phase: 'process',
      data: { classification: 'false_positive_counter_indicated' },
    });

    expect(appendFileSync).toHaveBeenCalledWith(
      summaryFile,
      expect.stringContaining('False positive')
    );
  });

  it('writes failure result', () => {
    writeProcessSummary('arubis/test-repo', 42, {
      success: false,
      phase: 'process',
      error: 'API timeout',
    });

    expect(appendFileSync).toHaveBeenCalledWith(
      summaryFile,
      expect.stringContaining('failed')
    );
  });

  it('does nothing when GITHUB_STEP_SUMMARY is not set', () => {
    delete process.env.GITHUB_STEP_SUMMARY;

    writeProcessSummary('arubis/test-repo', 42, {
      success: true,
      phase: 'process',
      data: { classification: 'validated' },
    });

    expect(appendFileSync).not.toHaveBeenCalled();
  });

  it('includes RSOLV branding footer', () => {
    writeProcessSummary('arubis/test-repo', 42, {
      success: true,
      phase: 'process',
      data: { classification: 'validated' },
    });

    expect(appendFileSync).toHaveBeenCalledWith(
      summaryFile,
      expect.stringContaining('rsolv.dev')
    );
  });
});

describe('writeScanSummary with budget plan', () => {
  const summaryFile = '/tmp/test-step-summary';

  beforeEach(() => {
    process.env.GITHUB_STEP_SUMMARY = summaryFile;
    vi.mocked(appendFileSync).mockClear();
  });

  afterEach(() => {
    delete process.env.GITHUB_STEP_SUMMARY;
    vi.mocked(appendFileSync).mockClear();
  });

  it('renders budget info when scanPlan is provided', () => {
    const plan = {
      selected: [
        { cwe_id: 'CWE-89', severity: 'critical', file_path: 'a.ts', line: 1, type: 'sqli', confidence: 'high' },
      ],
      deferred: [
        { cwe_id: 'CWE-79', severity: 'high', file_path: 'b.ts', line: 2, type: 'xss', confidence: 'medium', reason: 'capacity_exceeded' as const },
      ],
      budget: {
        tier: 'pro',
        validate_limit: 25,
        validate_used: 24,
        validate_remaining: 1,
        overage_cap_cents: 0,
        overage_remaining_cents: 0,
        max_validations: 1,
        effective_cap: 1,
        period_ends_at: '2026-05-01T00:00:00Z',
        currency: 'usd',
      },
    };

    writeScanSummary('owner/repo', [], 2, plan);

    const written = vi.mocked(appendFileSync).mock.calls[0][1] as string;
    expect(written).toContain('Budget');
    expect(written).toContain('Pro plan');
    expect(written).toContain('Processing');
    expect(written).toContain('Deferred');
    expect(written).toContain('CWE-89');
    expect(written).toContain('CWE-79');
  });

  it('renders fallback message when scanPlan is null', () => {
    writeScanSummary('owner/repo', [{ number: 1, cwe_id: 'CWE-89' }], 5, null);

    const written = vi.mocked(appendFileSync).mock.calls[0][1] as string;
    expect(written).toContain('Budget');
    expect(written).toContain('unavailable');
    expect(written).toContain('conservative default');
  });
});
