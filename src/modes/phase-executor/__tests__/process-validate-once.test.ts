/**
 * mode=process re-queries pending work for up to five passes. An issue that
 * VALIDATE could not prove can stay `pending_action=validate`, so without a
 * per-run guard the loop pays for the same validation on every pass.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { PhaseExecutor } from '../index.js';
import type { ActionConfig } from '../../../types/index.js';

const getPendingIssues = vi.fn();

vi.mock('../../../pipeline/pipeline-run-client.js', () => ({
  PipelineRunClient: vi.fn().mockImplementation(function () {
    return { getPendingIssues, reportPR: vi.fn() };
  }),
}));

vi.mock('../../../utils/logger.js', () => ({
  logger: { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() },
}));

const pendingValidate = (issueNumber: number) => ({
  issue_number: issueNumber,
  cwe_id: 'CWE-79',
  pending_action: 'validate',
});

const inconclusive = (issueNumber: number) => ({
  success: false,
  phase: 'validate' as const,
  data: { validation: { [`issue_${issueNumber}`]: { classification: 'inconclusive' } } },
});

function executorWith(config: Partial<ActionConfig> = {}) {
  const executor = new PhaseExecutor({ apiKey: 'k', rsolvApiKey: 'k', ...config } as ActionConfig);
  const executeValidate = vi
    .spyOn(executor, 'executeValidate')
    .mockImplementation(async (options) => inconclusive(options.issueNumber as number));
  return { executor, executeValidate };
}

describe('PhaseExecutor.executeProcess', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('when an issue stays pending validate after an inconclusive result', () => {
    it('validates it exactly once in the run', async () => {
      getPendingIssues.mockResolvedValue([pendingValidate(7)]);
      const { executor, executeValidate } = executorWith();

      const result = await executor.executeProcess({ pipelineRunId: 'run-1' });

      expect(result.success).toBe(true);
      expect(executeValidate).toHaveBeenCalledTimes(1);
    });
  });

  describe('when maxValidations is set', () => {
    it('stops validating once the run has used that many', async () => {
      getPendingIssues.mockResolvedValue([pendingValidate(1), pendingValidate(2), pendingValidate(3)]);
      const { executor, executeValidate } = executorWith({ maxValidations: 2 });

      await executor.executeProcess({ pipelineRunId: 'run-1' });

      expect(executeValidate).toHaveBeenCalledTimes(2);
    });
  });
});
