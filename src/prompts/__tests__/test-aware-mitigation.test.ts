/**
 * Tests for Test-Aware Mitigation Prompt Templates
 * RFC-060 Phase 3.2: Prompt templates for test-aware fix generation
 */

import { describe, test, expect } from 'vitest';
import { buildTestAwarePrompt, getTrustScoreExplanation } from '../test-aware-mitigation.js';
import type { IssueContext, TestContext } from '../test-aware-mitigation.js';

describe('buildTestAwarePrompt', () => {
  const issueContext: IssueContext = {
    issueId: 'issue-123',
    title: 'SQL Injection vulnerability',
    description: 'User input not sanitized in database queries'
  };

  const testContext: TestContext = {
    testPath: '__tests__/security/sql-injection.test.js',
    testContent: 'describe("SQL Injection", () => { it("sanitizes input", () => {}); })',
    testFramework: 'jest',
    testCommand: 'npm test -- __tests__/security/sql-injection.test.js'
  };

  test('includes issue context in prompt', () => {
    const prompt = buildTestAwarePrompt(issueContext, testContext);

    expect(prompt).toContain('issue-123');
    expect(prompt).toContain('SQL Injection vulnerability');
    expect(prompt).toContain('User input not sanitized in database queries');
  });

  test('includes test file path', () => {
    const prompt = buildTestAwarePrompt(issueContext, testContext);

    expect(prompt).toContain('__tests__/security/sql-injection.test.js');
  });

  test('includes test content in code block', () => {
    const prompt = buildTestAwarePrompt(issueContext, testContext);

    expect(prompt).toContain('```javascript');
    expect(prompt).toContain(testContext.testContent);
    expect(prompt).toContain('```');
  });

  test('includes test framework when provided', () => {
    const prompt = buildTestAwarePrompt(issueContext, testContext);

    expect(prompt).toContain('Framework: jest');
  });

  test('includes test command when provided', () => {
    const prompt = buildTestAwarePrompt(issueContext, testContext);

    expect(prompt).toContain('Run command: npm test -- __tests__/security/sql-injection.test.js');
  });

  test('omits framework when not provided', () => {
    const minimalContext: TestContext = {
      testPath: '__tests__/test.js',
      testContent: 'test content'
    };

    const prompt = buildTestAwarePrompt(issueContext, minimalContext);

    expect(prompt).not.toContain('Framework:');
  });

  test('omits command when not provided', () => {
    const minimalContext: TestContext = {
      testPath: '__tests__/test.js',
      testContent: 'test content'
    };

    const prompt = buildTestAwarePrompt(issueContext, minimalContext);

    expect(prompt).not.toContain('Run command:');
  });

  test('includes RED phase instruction', () => {
    const prompt = buildTestAwarePrompt(issueContext, testContext);

    expect(prompt).toContain('This test currently FAILS (RED phase) and must PASS after your fix');
  });

  test('includes fix requirements', () => {
    const prompt = buildTestAwarePrompt(issueContext, testContext);

    expect(prompt).toContain('Your fix must make this test pass');
    expect(prompt).toContain('Preserve all existing behavioral contracts');
    expect(prompt).toContain('Make minimal, incremental changes');
    expect(prompt).toContain('address the root cause');
  });

  test('uses custom base prompt when provided', () => {
    const customBase = 'Custom fix instruction for XSS';
    const prompt = buildTestAwarePrompt(issueContext, testContext, customBase);

    expect(prompt).toContain('Custom fix instruction for XSS');
  });

  test('generates default prompt when base not provided', () => {
    const prompt = buildTestAwarePrompt(issueContext, testContext);

    expect(prompt).toContain('Fix the security vulnerability for issue issue-123');
  });
});

describe('getTrustScoreExplanation', () => {
  test('explains perfect fix (pre-fail, post-pass)', () => {
    const explanation = getTrustScoreExplanation(false, true, 100);

    expect(explanation).toContain('100/100');
    expect(explanation).toContain('Perfect fix');
    expect(explanation).toContain('Test failed before fix and passes after');
  });

  test('explains false positive (both pass)', () => {
    const explanation = getTrustScoreExplanation(true, true, 50);

    expect(explanation).toContain('50/100');
    expect(explanation).toContain('Warning');
    expect(explanation).toContain('Test was already passing');
    expect(explanation).toContain('Possible false positive');
  });

  test('explains failed fix (both fail)', () => {
    const explanation = getTrustScoreExplanation(false, false, 0);

    expect(explanation).toContain('0/100');
    expect(explanation).toContain('Fix did not work');
    expect(explanation).toContain('Test still failing');
  });

  test('explains regression (pre-pass, post-fail)', () => {
    const explanation = getTrustScoreExplanation(true, false, 0);

    expect(explanation).toContain('0/100');
    expect(explanation).toContain('Critical');
    expect(explanation).toContain('Fix broke the test that was passing');
  });
});
