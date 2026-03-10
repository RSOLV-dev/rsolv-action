/**
 * RED TESTS — Label Manager (RFC-096 Phase F.2 Step 3)
 *
 * Tests the extracted label management logic that maps backend classification
 * strings to GitHub label operations.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { applyValidationLabels } from '../label-manager.js';

// Mock the github api module
vi.mock('../../../../github/api.js', () => ({
  addLabels: vi.fn(),
  removeLabel: vi.fn(),
}));

vi.mock('../../../../utils/logger.js', () => ({
  logger: {
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    debug: vi.fn(),
  },
}));

import { addLabels, removeLabel } from '../../../../github/api.js';
import { logger } from '../../../../utils/logger.js';

const mockAddLabels = vi.mocked(addLabels);
const mockRemoveLabel = vi.mocked(removeLabel);

describe('applyValidationLabels', () => {
  const issueInfo = {
    owner: 'test-org',
    repo: 'test-repo',
    issueNumber: 42,
    currentLabels: ['rsolv:detected'],
  };

  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('adds rsolv:validated and removes rsolv:detected for classification=validated', async () => {
    await applyValidationLabels(issueInfo, 'validated');

    expect(mockAddLabels).toHaveBeenCalledWith(
      'test-org', 'test-repo', 42, ['rsolv:validated']
    );
    expect(mockRemoveLabel).toHaveBeenCalledWith(
      'test-org', 'test-repo', 42, 'rsolv:detected'
    );
  });

  it('adds rsolv:false-positive and removes rsolv:detected for classification=false_positive', async () => {
    await applyValidationLabels(issueInfo, 'false_positive');

    expect(mockAddLabels).toHaveBeenCalledWith(
      'test-org', 'test-repo', 42, ['rsolv:false-positive']
    );
    expect(mockRemoveLabel).toHaveBeenCalledWith(
      'test-org', 'test-repo', 42, 'rsolv:detected'
    );
  });

  it('adds rsolv:validation-inconclusive for classification=infrastructure_failure', async () => {
    await applyValidationLabels(issueInfo, 'infrastructure_failure');

    expect(mockAddLabels).toHaveBeenCalledWith(
      'test-org', 'test-repo', 42, ['rsolv:validation-inconclusive']
    );
    // Keep rsolv:detected — vulnerability may be real
    expect(mockRemoveLabel).not.toHaveBeenCalled();
  });

  it('adds rsolv:validation-inconclusive for classification=inconclusive', async () => {
    await applyValidationLabels(issueInfo, 'inconclusive');

    expect(mockAddLabels).toHaveBeenCalledWith(
      'test-org', 'test-repo', 42, ['rsolv:validation-inconclusive']
    );
    expect(mockRemoveLabel).not.toHaveBeenCalled();
  });

  it('adds rsolv:validation-unavailable for classification=no_test_framework', async () => {
    await applyValidationLabels(issueInfo, 'no_test_framework');

    expect(mockAddLabels).toHaveBeenCalledWith(
      'test-org', 'test-repo', 42, ['rsolv:validation-unavailable']
    );
    // Keep rsolv:detected — vulnerability may be real
    expect(mockRemoveLabel).not.toHaveBeenCalled();
  });

  it('adds rsolv:validation-inconclusive for classification=max_turns_exceeded', async () => {
    await applyValidationLabels(issueInfo, 'max_turns_exceeded');

    expect(mockAddLabels).toHaveBeenCalledWith(
      'test-org', 'test-repo', 42, ['rsolv:validation-inconclusive']
    );
    // Keep rsolv:detected — vulnerability likely real
    expect(mockRemoveLabel).not.toHaveBeenCalled();
  });

  it('does not remove rsolv:detected when it is not in currentLabels', async () => {
    const issueWithoutDetected = { ...issueInfo, currentLabels: [] };
    await applyValidationLabels(issueWithoutDetected, 'validated');

    expect(mockAddLabels).toHaveBeenCalledWith(
      'test-org', 'test-repo', 42, ['rsolv:validated']
    );
    expect(mockRemoveLabel).not.toHaveBeenCalled();
  });

  it('does not throw when label operations fail', async () => {
    mockAddLabels.mockRejectedValueOnce(new Error('API error'));

    // Should not throw — label failures are non-fatal
    await expect(
      applyValidationLabels(issueInfo, 'validated')
    ).resolves.not.toThrow();
  });

  it('maps test_passed_unexpectedly to rsolv:validation-inconclusive', async () => {
    await applyValidationLabels(issueInfo, 'test_passed_unexpectedly');

    expect(mockAddLabels).toHaveBeenCalledWith(
      'test-org', 'test-repo', 42, ['rsolv:validation-inconclusive']
    );
    // Keep rsolv:detected — test passed unexpectedly, needs investigation
    expect(mockRemoveLabel).not.toHaveBeenCalled();
  });

  it('maps static_test to rsolv:validation-inconclusive', async () => {
    await applyValidationLabels(issueInfo, 'static_test');

    expect(mockAddLabels).toHaveBeenCalledWith(
      'test-org', 'test-repo', 42, ['rsolv:validation-inconclusive']
    );
    // Keep rsolv:detected — static test, behavioral test needed
    expect(mockRemoveLabel).not.toHaveBeenCalled();
  });

  it('handles unknown classification gracefully (no-op)', async () => {
    await applyValidationLabels(issueInfo, 'unknown_value');

    expect(mockAddLabels).not.toHaveBeenCalled();
    expect(mockRemoveLabel).not.toHaveBeenCalled();
  });

  it('handles undefined classification gracefully (no-op)', async () => {
    await applyValidationLabels(issueInfo, undefined);

    expect(mockAddLabels).not.toHaveBeenCalled();
    expect(mockRemoveLabel).not.toHaveBeenCalled();
  });

  describe('retry behavior', () => {
    beforeEach(() => {
      vi.useFakeTimers();
    });

    afterEach(() => {
      vi.useRealTimers();
    });

    it('retries on GitHub API failure up to 3 times', async () => {
      mockAddLabels
        .mockRejectedValueOnce(new Error('rate limit'))
        .mockRejectedValueOnce(new Error('rate limit'))
        .mockRejectedValueOnce(new Error('rate limit'));

      const promise = applyValidationLabels(issueInfo, 'infrastructure_failure');
      // Advance through retry delays (1s + 2s)
      await vi.advanceTimersByTimeAsync(1000);
      await vi.advanceTimersByTimeAsync(2000);
      await promise;

      // Should have attempted 3 times
      expect(mockAddLabels).toHaveBeenCalledTimes(3);
    });

    it('succeeds on second attempt after initial failure', async () => {
      mockAddLabels
        .mockRejectedValueOnce(new Error('network timeout'))
        .mockResolvedValueOnce(undefined);

      const promise = applyValidationLabels(issueInfo, 'infrastructure_failure');
      await vi.advanceTimersByTimeAsync(1000);
      await promise;

      expect(mockAddLabels).toHaveBeenCalledTimes(2);
    });

    it('logs warning after all retries exhausted', async () => {
      mockAddLabels
        .mockRejectedValueOnce(new Error('API error'))
        .mockRejectedValueOnce(new Error('API error'))
        .mockRejectedValueOnce(new Error('API error'));

      const promise = applyValidationLabels(issueInfo, 'infrastructure_failure');
      await vi.advanceTimersByTimeAsync(1000);
      await vi.advanceTimersByTimeAsync(2000);
      await promise;

      // The outer catch logs a final warning
      expect(logger.warn).toHaveBeenCalledWith(
        expect.stringContaining('Failed to update labels'),
        expect.any(Error)
      );
    });
  });
});
