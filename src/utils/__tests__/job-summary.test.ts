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
