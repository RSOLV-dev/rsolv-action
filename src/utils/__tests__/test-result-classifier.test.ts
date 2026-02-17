/**
 * TDD Tests for Test Result Classifier (root cause #31)
 *
 * Covers Gradle cache permissions vs Java version mismatch classification,
 * plus baseline classifier behavior for key patterns.
 */

import { describe, test, expect } from 'vitest';
import { classifyTestResult, isInfrastructureFailure, parseTestOutputCounts } from '../test-result-classifier.js';

describe('classifyTestResult', () => {
  describe('Gradle errors — root cause #31', () => {
    test('classifies Gradle cache permission error as runtime_error with permissions reason', () => {
      const result = classifyTestResult(
        1,
        '',
        'FAILURE: Build failed with an exception.\n* What went wrong:\nCould not open settings generic class cache for settings file'
      );
      expect(result.type).toBe('runtime_error');
      expect(result.isValidFailure).toBe(false);
      expect(result.reason).toMatch(/cache.*perm|GRADLE_USER_HOME/i);
    });

    test('classifies Java class version mismatch as runtime_error with version reason', () => {
      const result = classifyTestResult(
        1,
        '',
        'Unsupported class file major version 65'
      );
      expect(result.type).toBe('runtime_error');
      expect(result.isValidFailure).toBe(false);
      expect(result.reason).toMatch(/version|incompatible/i);
      // Should NOT mention permissions
      expect(result.reason).not.toMatch(/perm|GRADLE_USER_HOME/i);
    });
  });

  describe('exit code specials', () => {
    test('exit code 0 returns test_passed', () => {
      const result = classifyTestResult(0, '1 passing', '');
      expect(result.type).toBe('test_passed');
      expect(result.isValidFailure).toBe(false);
    });

    test('exit code 127 returns command_not_found', () => {
      const result = classifyTestResult(127, '', 'bash: jest: command not found');
      expect(result.type).toBe('command_not_found');
    });

    test('exit code 137 returns oom_killed', () => {
      const result = classifyTestResult(137, '', '');
      expect(result.type).toBe('oom_killed');
    });
  });

  describe('error patterns', () => {
    test('SyntaxError returns syntax_error', () => {
      const result = classifyTestResult(1, '', 'SyntaxError: Unexpected token');
      expect(result.type).toBe('syntax_error');
      expect(result.isValidFailure).toBe(false);
    });

    test('ModuleNotFoundError returns missing_dependency', () => {
      const result = classifyTestResult(1, '', 'ModuleNotFoundError: No module named flask');
      expect(result.type).toBe('missing_dependency');
    });
  });

  describe('valid test failures', () => {
    test('AssertionError is a valid failure', () => {
      const result = classifyTestResult(1, 'AssertionError: expected true to be false', '');
      expect(result.type).toBe('test_failed');
      expect(result.isValidFailure).toBe(true);
    });

    test('pytest FAILED pattern is a valid failure', () => {
      const result = classifyTestResult(1, 'FAILED test_vuln.py::test_sqli - assert 0 == 1', '');
      expect(result.type).toBe('test_failed');
      expect(result.isValidFailure).toBe(true);
    });
  });
});

describe('isInfrastructureFailure', () => {
  test('runtime_error is infrastructure failure', () => {
    expect(isInfrastructureFailure({ type: 'runtime_error', isValidFailure: false, reason: '' })).toBe(true);
  });

  test('test_failed is NOT infrastructure failure', () => {
    expect(isInfrastructureFailure({ type: 'test_failed', isValidFailure: true, reason: '' })).toBe(false);
  });

  test('test_passed is NOT infrastructure failure', () => {
    expect(isInfrastructureFailure({ type: 'test_passed', isValidFailure: false, reason: '' })).toBe(false);
  });
});

describe('parseTestOutputCounts', () => {
  test('parses Mocha output', () => {
    expect(parseTestOutputCounts('  3 passing\n  1 failing')).toEqual({ passed: 3, failed: 1, total: 4 });
  });

  test('parses pytest output', () => {
    expect(parseTestOutputCounts('2 passed, 1 failed')).toEqual({ passed: 2, failed: 1, total: 3 });
  });

  test('parses RSpec output', () => {
    expect(parseTestOutputCounts('5 examples, 2 failures')).toEqual({ passed: 3, failed: 2, total: 5 });
  });
});
