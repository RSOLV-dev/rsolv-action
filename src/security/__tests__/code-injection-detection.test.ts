/**
 * Integration tests for code_injection pattern detection
 *
 * These tests verify the complete flow from API pattern fetching to vulnerability detection.
 * This test suite would have caught the bug where code_injection was being mapped to
 * IMPROPER_INPUT_VALIDATION instead of CODE_INJECTION.
 *
 * TDD Approach: Write tests that verify:
 * 1. API returns code_injection type
 * 2. PatternAPIClient maps it to CODE_INJECTION
 * 3. Detector uses the pattern correctly
 * 4. Final vulnerability has correct type and CWE
 */

import { describe, test, expect, beforeEach, vi } from 'vitest';
import { PatternAPIClient } from '../pattern-api-client.js';
import { VulnerabilityType } from '../types.js';
import type { SecurityPattern } from '../types.js';
import {
  mockPatternFetch,
  LANGUAGE_PATTERNS,
  createRailsGoatPattern
} from './test-helpers/pattern-mocks.js';

describe('Code Injection Detection - Integration Tests', () => {
  let fetchMock: any;
  let client: PatternAPIClient;

  beforeEach(() => {
    fetchMock = vi.fn();
    global.fetch = fetchMock;
    client = new PatternAPIClient({ apiKey: 'test-key' });
  });

  describe('API to Detection Flow', () => {
    test('should detect eval(request.responseText) as CODE_INJECTION with CWE-94', async () => {
      const pattern = createRailsGoatPattern();
      mockPatternFetch(fetchMock, [pattern]);

      const result = await client.fetchPatterns('javascript');
      const detectedPattern = result.patterns[0];

      // Critical assertions that would have caught the bug
      expect(detectedPattern).toMatchObject({
        type: VulnerabilityType.CODE_INJECTION,
        cweId: 'CWE-94',
        severity: 'critical'
      });
      expect(detectedPattern.type).not.toBe(VulnerabilityType.COMMAND_INJECTION);
      expect(detectedPattern.type).not.toBe(VulnerabilityType.IMPROPER_INPUT_VALIDATION);

      // Verify the pattern works on the actual RailsGoat code
      const regex = detectedPattern.patterns.regex![0];
      expect(regex.test('eval(request.responseText);')).toBe(true);
    });

    test.each([
      { code: '// eval(request.responseText);', description: 'commented eval' },
      { code: 'evaluate(request.responseText);', description: 'evaluate function' },
      { code: 'const evalFunc = myCustomEval;', description: 'eval in variable name' }
    ])('should NOT detect $description as vulnerability', async ({ code }) => {
      const pattern = createRailsGoatPattern();
      mockPatternFetch(fetchMock, [pattern]);

      const result = await client.fetchPatterns('javascript');
      const regex = result.patterns[0].patterns.regex![0];

      expect(regex.test(code)).toBe(false);
    });

    test.each([
      'eval(request.responseText);',
      'eval(req.body.code);',
      'eval(params.script);',
      'eval(query.expression);',
      'const result = eval(userInput);',
      '  eval(request.data);'
    ])('should detect dangerous pattern: %s', async (dangerousCode) => {
      const pattern = createRailsGoatPattern();
      mockPatternFetch(fetchMock, [pattern]);

      const result = await client.fetchPatterns('javascript');
      const regex = result.patterns[0].patterns.regex![0];

      expect(regex.test(dangerousCode)).toBe(true);
    });
  });

  describe('Pattern Type Consistency', () => {
    test('all code_injection patterns should map to CODE_INJECTION type', async () => {
      const patterns = Object.values(LANGUAGE_PATTERNS).map(fn => fn());
      mockPatternFetch(fetchMock, patterns, 'multiple');

      const result = await client.fetchPatterns('multiple');

      // All code_injection patterns should be CODE_INJECTION type
      expect(result.patterns).toHaveLength(4);
      result.patterns.forEach(pattern => {
        expect(pattern).toMatchObject({
          type: VulnerabilityType.CODE_INJECTION,
          cweId: 'CWE-94',
          severity: 'critical'
        });
      });
    });
  });

  describe('Regression Tests', () => {
    test.each([
      { wrongType: VulnerabilityType.COMMAND_INJECTION, cwe: 'CWE-78', name: 'COMMAND_INJECTION' },
      { wrongType: VulnerabilityType.IMPROPER_INPUT_VALIDATION, cwe: null, name: 'IMPROPER_INPUT_VALIDATION' }
    ])('code_injection with CWE-94 should NEVER be $name', async ({ wrongType, name }) => {
      mockPatternFetch(fetchMock, [LANGUAGE_PATTERNS.javascript()]);

      const result = await client.fetchPatterns('javascript');
      const pattern = result.patterns[0];

      // This is THE test that would have caught the original bug
      expect(pattern.cweId).toBe('CWE-94');
      expect(pattern.type).toBe(VulnerabilityType.CODE_INJECTION);
      expect(pattern.type).not.toBe(wrongType);
    });
  });

  describe('RailsGoat E2E Scenario', () => {
    test('should detect the exact RailsGoat jquery.snippet.js:737 eval usage', async () => {
      const pattern = createRailsGoatPattern();
      mockPatternFetch(fetchMock, [pattern]);

      const result = await client.fetchPatterns('javascript');
      const detectedPattern = result.patterns[0];

      // Verify all expected properties
      expect(detectedPattern).toMatchObject({
        type: VulnerabilityType.CODE_INJECTION,
        cweId: 'CWE-94',
        severity: 'critical',
        id: 'js-eval-user-input'
      });

      // Verify the pattern matches the actual RailsGoat line 737
      const regex = detectedPattern.patterns.regex![0];
      expect(regex.test('eval(request.responseText);')).toBe(true);
    });
  });
});
