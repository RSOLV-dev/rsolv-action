/**
 * Tests for TestRunner service
 * RFC-060 Phase 3.2: Test execution service
 */

import { describe, test, expect, beforeEach, vi } from 'vitest';
import { TestRunner } from '../test-runner.js';

// Hoist mock function
const { mockExecAsync } = vi.hoisted(() => ({
  mockExecAsync: vi.fn()
}));

vi.mock('child_process', () => ({
  exec: vi.fn()
}));

vi.mock('util', () => ({
  promisify: () => mockExecAsync
}));

describe('TestRunner', () => {
  let testRunner: TestRunner;

  beforeEach(() => {
    vi.clearAllMocks();
    testRunner = new TestRunner();
  });

  describe('#runTest', () => {
    test('returns success when tests pass', async () => {
      mockExecAsync.mockResolvedValue({
        stdout: 'All tests passed',
        stderr: ''
      });

      const result = await testRunner.runTest('npm test');

      expect(result.passed).toBe(true);
      expect(result.output).toContain('All tests passed');
    });

    test('returns failure when tests fail', async () => {
      const error = new Error('Tests failed');
      (error as any).stdout = 'Test output';
      (error as any).stderr = 'Test error';
      mockExecAsync.mockRejectedValue(error);

      const result = await testRunner.runTest('npm test');

      expect(result.passed).toBe(false);
      expect(result.output).toBe('Test outputTest error');
    });

    test('combines stdout and stderr in output', async () => {
      mockExecAsync.mockResolvedValue({
        stdout: 'stdout content',
        stderr: 'stderr content'
      });

      const result = await testRunner.runTest('npm test');

      expect(result.output).toBe('stdout contentstderr content');
    });
  });

  describe('#validate', () => {
    test('returns true when npm test is available', async () => {
      mockExecAsync.mockResolvedValue({
        stdout: '8.0.0',
        stderr: ''
      });

      const isValid = await testRunner.validate();

      expect(isValid).toBe(true);
    });

    test('returns false when npm test is not available', async () => {
      mockExecAsync.mockRejectedValue(new Error('Command not found'));

      const isValid = await testRunner.validate();

      expect(isValid).toBe(false);
    });
  });
});
