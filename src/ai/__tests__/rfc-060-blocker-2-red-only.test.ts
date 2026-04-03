/**
 * RFC-060 Blocker 2: RED-only Test Generation
 * Following TDD: RED → GREEN → REFACTOR
 *
 * These tests verify that ai-test-generator only generates RED tests,
 * not RED+GREEN+REFACTOR as it currently does.
 */

import { describe, test, expect, beforeEach, vi } from 'vitest';
import { AITestGenerator } from '../ai-test-generator.js';
import type { Vulnerability } from '../types.js';

describe('RFC-060 Blocker 2: AI Test Generator RED-only Tests', () => {
  let generator: AITestGenerator;
  let mockVulnerability: Vulnerability;

  beforeEach(() => {
    generator = new AITestGenerator({
      provider: 'anthropic',
      apiKey: 'test-key',
      model: 'claude-3',
      maxTokens: 4000
    });

    mockVulnerability = {
      type: 'SQL_INJECTION',
      severity: 'HIGH',
      file: 'src/user.js',
      line: 42,
      description: 'Direct SQL query construction with user input',
      message: 'SQL injection vulnerability in getUserById function',
      codeSnippet: 'const query = `SELECT * FROM users WHERE id = ${userId}`;'
    };
  });

  describe('Prompt Generation', () => {
    test('should request RED-only tests in prompt, not RED+GREEN+REFACTOR', () => {
      // This test will FAIL initially because current prompt requests 3 test types

      const prompt = (generator as any).constructTestGenerationPrompt(mockVulnerability, {
        language: 'javascript',
        testFramework: 'jest'
      });

      // Verify prompt requests RED-only tests
      expect(prompt).not.toContain('THREE test cases');
      expect(prompt).not.toContain('GREEN test:');
      expect(prompt).not.toContain('REFACTOR test:');
      expect(prompt).toContain('RED test');
      expect(prompt).toContain('Generate RED tests'); // From line 1 of prompt
    });

    test('should support multiple RED tests for complex vulnerabilities', () => {
      // This test will FAIL initially

      const prompt = (generator as any).constructTestGenerationPrompt(mockVulnerability, {
        language: 'javascript',
        testFramework: 'jest'
      });

      // Verify prompt supports multiple RED tests based on complexity
      expect(prompt).toContain('multiple RED tests');
      expect(prompt).toContain('Different exploit techniques for same vulnerability type');
    });
  });

  describe('Response Format', () => {
    test('should accept single RED test format', () => {
      // RED PHASE: Parser should handle { red: {...} } format

      const response = JSON.stringify({
        red: {
          testName: 'should be vulnerable to SQL injection',
          testCode: 'test("SQL injection", () => { /* test code */ })',
          attackVector: '\'; DROP TABLE users; --',
          expectedBehavior: 'should_fail_on_vulnerable_code'
        }
      });

      const result = (generator as any).parseTestSuite(response);

      expect(result).toBeDefined();
      expect(result?.red).toBeDefined();
      expect(result?.green).toBeUndefined();
      expect(result?.refactor).toBeUndefined();
    });

    test('should accept multiple RED tests format', () => {
      // RED PHASE: Parser should handle { redTests: [{...}, {...}] } format

      const response = JSON.stringify({
        redTests: [
          {
            testName: 'should be vulnerable to SQL injection via id param',
            testCode: 'test("SQL injection via id", () => { /* test 1 */ })',
            attackVector: '\'; DROP TABLE users; --',
            expectedBehavior: 'should_fail_on_vulnerable_code'
          },
          {
            testName: 'should be vulnerable to SQL injection via name param',
            testCode: 'test("SQL injection via name", () => { /* test 2 */ })',
            attackVector: 'admin\'--',
            expectedBehavior: 'should_fail_on_vulnerable_code'
          }
        ]
      });

      const result = (generator as any).parseTestSuite(response);

      expect(result).toBeDefined();
      expect(result?.redTests).toBeDefined();
      expect(result?.redTests).toHaveLength(2);
      expect(result?.green).toBeUndefined();
      expect(result?.refactor).toBeUndefined();
    });

    test('should reject response with GREEN or REFACTOR tests', () => {
      // RED PHASE: Should not accept old format with green/refactor

      const response = JSON.stringify({
        red: {
          testName: 'red test',
          testCode: 'test code',
          attackVector: 'attack',
          expectedBehavior: 'should_fail_on_vulnerable_code'
        },
        green: {
          testName: 'green test',
          testCode: 'test code',
          validInput: 'valid',
          expectedBehavior: 'should_pass_on_fixed_code'
        },
        refactor: {
          testName: 'refactor test',
          testCode: 'test code',
          testCases: [],
          expectedBehavior: 'should_pass_on_both'
        }
      });

      const result = (generator as any).parseTestSuite(response);

      // Should accept the RED test but ignore GREEN/REFACTOR
      expect(result).toBeDefined();
      expect(result?.red).toBeDefined();
      // GREEN and REFACTOR should be stripped or undefined
      expect(result?.green).toBeUndefined();
      expect(result?.refactor).toBeUndefined();
    });
  });

  describe('Response Format in Prompt', () => {
    test('should specify RED-only response format in prompt', () => {
      // RED PHASE: Prompt should request RED-only JSON structure

      const prompt = (generator as any).constructTestGenerationPrompt(mockVulnerability, {
        language: 'javascript',
        testFramework: 'jest'
      });

      // Should show single RED test format
      expect(prompt).toContain('"red":');
      expect(prompt).not.toContain('"green":');
      expect(prompt).not.toContain('"refactor":');

      // Or multiple RED tests format
      const hasMultipleFormat = prompt.includes('"redTests"');
      const hasSingleFormat = prompt.includes('"red":');
      expect(hasSingleFormat || hasMultipleFormat).toBe(true);
    });
  });
});
