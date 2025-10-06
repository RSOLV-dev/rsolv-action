/**
 * RFC-060 Blocker 2: Verify test generator produces RED-only tests
 * Tests should fail on vulnerable code and pass on fixed code
 */

import { describe, it, expect } from 'vitest';
import { AITestGenerator } from '../ai-test-generator.js';

describe('AITestGenerator - RED-only Tests (RFC-060 Blocker 2)', () => {
  it('should generate prompt requesting only RED tests, not RED+GREEN+REFACTOR', () => {
    // RED TEST: Current prompt asks for "THREE test cases" with RED, GREEN, and REFACTOR
    // After fix: Prompt should ask for "RED tests only"

    const generator = new AITestGenerator({
      provider: 'mock',
      apiKey: 'test-key',
      model: 'test-model'
    });

    const vulnerability = {
      type: 'SQL_INJECTION',
      severity: 'critical',
      filePath: 'db/query.js',
      line: 42,
      description: 'SQL injection vulnerability',
      message: 'User input concatenated into SQL query'
    };

    const options = {
      language: 'javascript',
      testFramework: 'jest'
    };

    // Access the private buildPrompt method to verify its content
    const prompt = (generator as any).buildPrompt(vulnerability, '', options);

    // Verify: Prompt should NOT request three test types
    expect(prompt).not.toContain('Generate THREE test cases');
    expect(prompt).not.toContain('GREEN test:');
    expect(prompt).not.toContain('REFACTOR test:');

    // Verify: Prompt SHOULD request RED tests
    expect(prompt).toContain('RED test');
    expect(prompt).toMatch(/one or more RED tests?/i);
  });

  it('should accept multiple RED tests for complex vulnerabilities', () => {
    // RED TEST: Current response format expects exactly 3 test types
    // After fix: Should support array of RED tests

    const generator = new AITestGenerator({
      provider: 'mock',
      apiKey: 'test-key',
      model: 'test-model'
    });

    const vulnerability = {
      type: 'SQL_INJECTION',
      severity: 'critical',
      filePath: 'db/query.js',
      line: 42,
      description: 'Multiple SQL injection points',
      message: 'User input in login AND search'
    };

    const options = {
      language: 'javascript',
      testFramework: 'jest'
    };

    const prompt = (generator as any).buildPrompt(vulnerability, '', options);

    // Verify: Prompt should support multiple RED tests
    expect(prompt).toMatch(/multiple.*RED tests?/i);
    expect(prompt).not.toContain('"green"');
    expect(prompt).not.toContain('"refactor"');
  });
});
