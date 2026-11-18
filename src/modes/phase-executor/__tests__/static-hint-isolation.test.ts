/**
 * The static hint ("RSOLV static analysis thinks this may be safe because …")
 * is for the humans reading the issue. It must never reach the backend prompts:
 * a "may be safe" nudge biases VALIDATE toward a false-positive verdict, and
 * no proof must never become a false positive.
 */
import { describe, it, expect, beforeEach, vi } from 'vitest';
import { PhaseExecutor } from '../index.js';
import type { ActionConfig, IssueContext, ScanPhaseData } from '../../../types/index.js';

const { runValidation, runMitigation } = vi.hoisted(() => ({
  runValidation: vi.fn(),
  runMitigation: vi.fn()
}));

vi.mock('../../../ai/test-runner.js', () => ({
  TestRunner: vi.fn().mockImplementation(function () {
    return {
      ensureRuntime: vi.fn().mockResolvedValue(undefined),
      ensureDependencies: vi.fn().mockResolvedValue(undefined)
    };
  })
}));

vi.mock('../../../pipeline/validation-client.js', () => ({
  ValidationClient: vi.fn().mockImplementation(function () {
    return { runValidation };
  })
}));

vi.mock('../../../pipeline/mitigation-client.js', () => ({
  MitigationClient: vi.fn().mockImplementation(function () {
    return { runMitigation };
  })
}));

vi.mock('../../../github/api.js', () => ({
  getIssue: vi.fn(),
  addLabels: vi.fn().mockResolvedValue(undefined),
  removeLabel: vi.fn().mockResolvedValue(undefined)
}));

vi.mock('../utils/label-manager.js', () => ({
  applyValidationLabels: vi.fn().mockResolvedValue(undefined)
}));

vi.mock('child_process', () => ({
  exec: vi.fn(),
  execSync: vi.fn().mockReturnValue('')
}));

const HINT_LINE =
  '> RSOLV static analysis thinks this may be safe because Safe pattern detected: using parameterized query';

const issueWithHint = (): IssueContext => ({
  id: 'issue-7',
  number: 7,
  title: 'CWE-89: SQL injection in users.py',
  body: [
    '## Security Vulnerability Report',
    '',
    '### Description',
    'User input reaches a SQL string.',
    '',
    HINT_LINE,
    '',
    '### Vulnerable Code'
  ].join('\n'),
  labels: ['rsolv:detected'],
  assignees: [],
  repository: { owner: 'o', name: 'r', fullName: 'o/r', defaultBranch: 'main' },
  source: 'github',
  createdAt: '2026-11-18T00:00:00Z',
  updatedAt: '2026-11-18T00:00:00Z'
});

const scanData = {
  analysisData: { issueType: 'security', vulnerabilityType: 'CWE-89', cwe: 'CWE-89', filesToModify: [] }
} as unknown as ScanPhaseData;

describe('PhaseExecutor static hint isolation', () => {
  let executor: PhaseExecutor;

  beforeEach(() => {
    vi.clearAllMocks();
    runValidation.mockResolvedValue({ validated: false, classification: 'inconclusive' });
    runMitigation.mockResolvedValue({ success: false, error: 'stop here' });
    executor = new PhaseExecutor({
      githubToken: 't',
      rsolvApiKey: 'k',
      repository: { owner: 'o', name: 'r' }
    } as ActionConfig);
  });

  describe('when the issue body carries a static hint', () => {
    it('keeps the hint out of what VALIDATE reads, and keeps the rest', async () => {
      await executor.executeValidateForIssue(issueWithHint(), scanData);

      const description: string = runValidation.mock.calls[0][0].vulnerability.description;
      expect(description).not.toContain('may be safe');
      expect(description).not.toContain('parameterized query');
      expect(description).toContain('User input reaches a SQL string.');
    });

    it('keeps the hint out of what MITIGATE reads, and keeps the rest', async () => {
      await executor.executeMitigateForIssue(issueWithHint(), scanData, {});

      const body: string = runMitigation.mock.calls[0][0].issue.body;
      expect(body).not.toContain('may be safe');
      expect(body).not.toContain('parameterized query');
      expect(body).toContain('User input reaches a SQL string.');
    });

    it('drops the hint when GitHub hands the body back with CRLF line endings', async () => {
      const issue = issueWithHint();
      issue.body = issue.body.replace(/\n/g, '\r\n');

      await executor.executeValidateForIssue(issue, scanData);

      expect(runValidation.mock.calls[0][0].vulnerability.description).not.toContain('may be safe');
    });
  });
});
