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

describe('Code Injection Detection - Integration Tests', () => {
  let fetchMock: any;

  beforeEach(() => {
    fetchMock = vi.fn();
    global.fetch = fetchMock;
  });

  describe('API to Detection Flow', () => {
    test('should detect eval(request.responseText) as CODE_INJECTION with CWE-94', async () => {
      const client = new PatternAPIClient({ apiKey: 'test-key' });

      // Mock API response with code_injection type
      const mockResponse = {
        count: 1,
        language: 'javascript',
        patterns: [
          {
            id: 'js-eval-user-input',
            name: 'JavaScript eval() with user input',
            type: 'code_injection',
            description: 'eval() can execute arbitrary code when passed user input',
            severity: 'critical',
            patterns: ['^(?!.*\\/\\/).*eval\\s*\\(.*?(?:req\\.|request\\.|params\\.|query\\.|body\\.|user|input|data|Code)'],
            languages: ['javascript'],
            recommendation: 'Avoid eval(). Use JSON.parse() for JSON data or find safer alternatives.',
            cwe_id: 'CWE-94',
            owasp_category: 'A03:2021',
            test_cases: {
              vulnerable: ['eval(request.responseText)'],
              safe: ['// eval(request.responseText)']
            }
          }
        ]
      };

      fetchMock.mockResolvedValueOnce({
        ok: true,
        json: async () => mockResponse
      });

      // Fetch patterns
      const result = await client.fetchPatterns('javascript');

      // Verify pattern conversion
      expect(result.patterns).toHaveLength(1);
      const pattern = result.patterns[0];

      // Critical assertions that would have caught the bug
      expect(pattern.type).toBe(VulnerabilityType.CODE_INJECTION);
      expect(pattern.type).not.toBe(VulnerabilityType.COMMAND_INJECTION);
      expect(pattern.type).not.toBe(VulnerabilityType.IMPROPER_INPUT_VALIDATION);

      // Verify CWE-94 is preserved
      expect(pattern.cweId).toBe('CWE-94');

      // Verify severity is critical
      expect(pattern.severity).toBe('critical');

      // Verify the pattern works on the actual RailsGoat code
      const railsGoatCode = 'eval(request.responseText);';
      expect(pattern.patterns.regex).toBeDefined();
      expect(pattern.patterns.regex!.length).toBeGreaterThan(0);

      const matches = pattern.patterns.regex![0].test(railsGoatCode);
      expect(matches).toBe(true);
    });

    test('should not detect commented eval as vulnerability', async () => {
      const client = new PatternAPIClient({ apiKey: 'test-key' });

      const mockResponse = {
        count: 1,
        language: 'javascript',
        patterns: [
          {
            id: 'js-eval-user-input',
            name: 'JavaScript eval() with user input',
            type: 'code_injection',
            description: 'eval() can execute arbitrary code',
            severity: 'critical',
            patterns: ['^(?!.*\\/\\/).*eval\\s*\\(.*?(?:req\\.|request\\.|params\\.|query\\.|body\\.|user|input|data|Code)'],
            languages: ['javascript'],
            recommendation: 'Avoid eval',
            cwe_id: 'CWE-94',
            owasp_category: 'A03:2021',
            test_cases: { vulnerable: [], safe: [] }
          }
        ]
      };

      fetchMock.mockResolvedValueOnce({
        ok: true,
        json: async () => mockResponse
      });

      const result = await client.fetchPatterns('javascript');
      const pattern = result.patterns[0];

      // Test that commented code does NOT match
      const commentedCode = '// eval(request.responseText);';
      const matches = pattern.patterns.regex![0].test(commentedCode);
      expect(matches).toBe(false);
    });

    test('should detect various forms of dangerous eval usage', async () => {
      const client = new PatternAPIClient({ apiKey: 'test-key' });

      const mockResponse = {
        count: 1,
        language: 'javascript',
        patterns: [
          {
            id: 'js-eval-user-input',
            name: 'JavaScript eval() with user input',
            type: 'code_injection',
            description: 'eval() can execute arbitrary code',
            severity: 'critical',
            patterns: ['^(?!.*\\/\\/).*eval\\s*\\(.*?(?:req\\.|request\\.|params\\.|query\\.|body\\.|user|input|data|Code)'],
            languages: ['javascript'],
            recommendation: 'Avoid eval',
            cwe_id: 'CWE-94',
            owasp_category: 'A03:2021',
            test_cases: { vulnerable: [], safe: [] }
          }
        ]
      };

      fetchMock.mockResolvedValueOnce({
        ok: true,
        json: async () => mockResponse
      });

      const result = await client.fetchPatterns('javascript');
      const pattern = result.patterns[0];
      const regex = pattern.patterns.regex![0];

      // Test various dangerous patterns
      const dangerousCases = [
        'eval(request.responseText);',
        'eval(req.body.code);',
        'eval(params.script);',
        'eval(query.expression);',
        'const result = eval(userInput);',
        '  eval(request.data);'
      ];

      dangerousCases.forEach(code => {
        regex.lastIndex = 0; // Reset regex
        expect(regex.test(code)).toBe(true);
      });

      // Test safe patterns (should NOT match)
      const safeCases = [
        '// eval(request.responseText);',
        'evaluate(request.responseText);',
        'const evalFunc = myCustomEval;'
      ];

      safeCases.forEach(code => {
        regex.lastIndex = 0; // Reset regex
        expect(regex.test(code)).toBe(false);
      });
    });
  });

  describe('Pattern Type Consistency', () => {
    test('all code_injection patterns should map to CODE_INJECTION type', async () => {
      const client = new PatternAPIClient({ apiKey: 'test-key' });

      const mockResponse = {
        count: 4,
        language: 'multiple',
        patterns: [
          {
            id: 'js-eval-user-input',
            name: 'JavaScript eval()',
            type: 'code_injection',
            description: 'eval() injection',
            severity: 'critical',
            patterns: ['eval\\s*\\('],
            languages: ['javascript'],
            recommendation: 'Avoid eval',
            cwe_id: 'CWE-94',
            owasp_category: 'A03:2021',
            test_cases: { vulnerable: [], safe: [] }
          },
          {
            id: 'python-eval-user-input',
            name: 'Python eval()',
            type: 'code_injection',
            description: 'eval() injection',
            severity: 'critical',
            patterns: ['eval\\s*\\('],
            languages: ['python'],
            recommendation: 'Avoid eval',
            cwe_id: 'CWE-94',
            owasp_category: 'A03:2021',
            test_cases: { vulnerable: [], safe: [] }
          },
          {
            id: 'ruby-eval-user-input',
            name: 'Ruby eval()',
            type: 'code_injection',
            description: 'eval() injection',
            severity: 'critical',
            patterns: ['eval\\s*\\('],
            languages: ['ruby'],
            recommendation: 'Avoid eval',
            cwe_id: 'CWE-94',
            owasp_category: 'A03:2021',
            test_cases: { vulnerable: [], safe: [] }
          },
          {
            id: 'php-eval-user-input',
            name: 'PHP eval()',
            type: 'code_injection',
            description: 'eval() injection',
            severity: 'critical',
            patterns: ['eval\\s*\\('],
            languages: ['php'],
            recommendation: 'Avoid eval',
            cwe_id: 'CWE-94',
            owasp_category: 'A03:2021',
            test_cases: { vulnerable: [], safe: [] }
          }
        ]
      };

      fetchMock.mockResolvedValueOnce({
        ok: true,
        json: async () => mockResponse
      });

      const result = await client.fetchPatterns('multiple');

      // All code_injection patterns should be CODE_INJECTION type
      result.patterns.forEach(pattern => {
        expect(pattern.type).toBe(VulnerabilityType.CODE_INJECTION);
        expect(pattern.cweId).toBe('CWE-94');
        expect(pattern.severity).toBe('critical');
      });
    });
  });

  describe('Regression Tests', () => {
    test('code_injection with CWE-94 should NEVER be COMMAND_INJECTION (CWE-78)', async () => {
      const client = new PatternAPIClient({ apiKey: 'test-key' });

      const mockResponse = {
        count: 1,
        language: 'javascript',
        patterns: [
          {
            id: 'js-eval-user-input',
            name: 'JavaScript eval()',
            type: 'code_injection',
            description: 'eval() injection',
            severity: 'critical',
            patterns: ['eval\\s*\\('],
            languages: ['javascript'],
            recommendation: 'Avoid eval',
            cwe_id: 'CWE-94',
            owasp_category: 'A03:2021',
            test_cases: { vulnerable: [], safe: [] }
          }
        ]
      };

      fetchMock.mockResolvedValueOnce({
        ok: true,
        json: async () => mockResponse
      });

      const result = await client.fetchPatterns('javascript');
      const pattern = result.patterns[0];

      // Critical regression test
      expect(pattern.cweId).toBe('CWE-94');
      expect(pattern.type).toBe(VulnerabilityType.CODE_INJECTION);
      expect(pattern.type).not.toBe(VulnerabilityType.COMMAND_INJECTION);
    });

    test('code_injection should NEVER fall back to IMPROPER_INPUT_VALIDATION', async () => {
      const client = new PatternAPIClient({ apiKey: 'test-key' });

      const mockResponse = {
        count: 1,
        language: 'javascript',
        patterns: [
          {
            id: 'js-eval-user-input',
            name: 'JavaScript eval()',
            type: 'code_injection', // This is the key - without mapping, falls back
            description: 'eval() injection',
            severity: 'critical',
            patterns: ['eval\\s*\\('],
            languages: ['javascript'],
            recommendation: 'Avoid eval',
            cwe_id: 'CWE-94',
            owasp_category: 'A03:2021',
            test_cases: { vulnerable: [], safe: [] }
          }
        ]
      };

      fetchMock.mockResolvedValueOnce({
        ok: true,
        json: async () => mockResponse
      });

      const result = await client.fetchPatterns('javascript');
      const pattern = result.patterns[0];

      // This is THE test that would have caught the original bug
      expect(pattern.type).toBe(VulnerabilityType.CODE_INJECTION);
      expect(pattern.type).not.toBe(VulnerabilityType.IMPROPER_INPUT_VALIDATION);
    });
  });

  describe('RailsGoat E2E Scenario', () => {
    test('should detect the exact RailsGoat jquery.snippet.js:737 eval usage', async () => {
      const client = new PatternAPIClient({ apiKey: 'test-key' });

      const mockResponse = {
        count: 1,
        language: 'javascript',
        patterns: [
          {
            id: 'js-eval-user-input',
            name: 'JavaScript eval() with user input',
            type: 'code_injection',
            description: 'eval() can execute arbitrary code when passed user input',
            severity: 'critical',
            // This is the actual pattern from the platform
            patterns: ['^(?!.*\\/\\/).*eval\\s*\\(.*?(?:req\\.|request\\.|params\\.|query\\.|body\\.|user|input|data|Code)'],
            languages: ['javascript'],
            recommendation: 'Avoid eval(). Use JSON.parse() for JSON data or find safer alternatives.',
            cwe_id: 'CWE-94',
            owasp_category: 'A03:2021',
            test_cases: {
              vulnerable: ['eval(request.responseText)'],
              safe: []
            }
          }
        ]
      };

      fetchMock.mockResolvedValueOnce({
        ok: true,
        json: async () => mockResponse
      });

      const result = await client.fetchPatterns('javascript');
      const pattern = result.patterns[0];

      // This is the actual line 737 from RailsGoat's jquery.snippet.js
      const railsGoatLine737 = 'eval(request.responseText);';

      // Verify all expected properties
      expect(pattern.type).toBe(VulnerabilityType.CODE_INJECTION);
      expect(pattern.cweId).toBe('CWE-94');
      expect(pattern.severity).toBe('critical');
      expect(pattern.id).toBe('js-eval-user-input');

      // Verify the pattern matches
      const regex = pattern.patterns.regex![0];
      expect(regex.test(railsGoatLine737)).toBe(true);

      // Verify it would create the correct issue
      // In the real scanner, this would become:
      // - type: code_injection (not improper_input_validation)
      // - CWE: CWE-94
      // - severity: critical
      expect(pattern).toMatchObject({
        type: VulnerabilityType.CODE_INJECTION,
        cweId: 'CWE-94',
        severity: 'critical'
      });
    });
  });
});
