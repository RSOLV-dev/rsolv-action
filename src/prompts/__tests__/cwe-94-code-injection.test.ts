/**
 * Tests for CWE-94 (Code Injection) Assertion Template
 * RFC-103: RED Test Generation Quality Improvements
 *
 * Code Injection (eval, Function constructor, vm.runInContext)
 * is distinct from Command Injection (CWE-78) and very common in JS.
 */

import { describe, it, expect } from 'vitest';
import { getAssertionTemplate, SUPPORTED_CWES } from '../vulnerability-assertion-templates.js';

describe('CWE-94 Code Injection Template', () => {
  it('is included in supported CWEs', () => {
    expect(SUPPORTED_CWES).toContain('CWE-94');
  });

  it('has a complete template', () => {
    const template = getAssertionTemplate('CWE-94');

    expect(template).toBeDefined();
    expect(template!.name).toBe('Code Injection');
    expect(template!.assertionGoal).toBeDefined();
    expect(template!.attackPayload).toBeDefined();
    expect(template!.testStrategy).toBeDefined();
  });

  it('assertion goal focuses on dynamic code execution', () => {
    const template = getAssertionTemplate('CWE-94');

    expect(template!.assertionGoal).toMatch(/eval|Function|dynamic.*code|execute/i);
  });

  it('attack payload demonstrates code execution', () => {
    const template = getAssertionTemplate('CWE-94');

    // Should include a payload that would execute if eval'd
    expect(template!.attackPayload).toMatch(/require|process|child_process|exec/i);
  });

  it('test strategy captures the vulnerable pattern', () => {
    const template = getAssertionTemplate('CWE-94');

    expect(template!.testStrategy).toMatch(/source.*code|regex|pattern|detect/i);
  });

  describe('framework hints', () => {
    it('has hints for all major JS frameworks', () => {
      const template = getAssertionTemplate('CWE-94');

      expect(template!.frameworkHints.mocha).toBeDefined();
      expect(template!.frameworkHints.jest).toBeDefined();
    });

    it('mocha hint works without sinon/chai', () => {
      const template = getAssertionTemplate('CWE-94');
      const mochaHint = template!.frameworkHints.mocha;

      // Should NOT require sinon or chai - use what's available
      expect(mochaHint).toMatch(/fs\.readFileSync|source code|regex/i);
      // Should mention using available assertion libraries
      expect(mochaHint).toMatch(/assert|should|expect/i);
    });

    it('jest hint uses native Jest assertions', () => {
      const template = getAssertionTemplate('CWE-94');
      const jestHint = template!.frameworkHints.jest;

      expect(jestHint).toMatch(/expect\(|toMatch|toContain/i);
    });

    it('has hints for non-JS ecosystems too', () => {
      const template = getAssertionTemplate('CWE-94');

      // Code injection exists in Python (exec/eval), Ruby (eval), PHP (eval), etc.
      expect(template!.frameworkHints.pytest).toBeDefined();
      expect(template!.frameworkHints.rspec).toBeDefined();
      expect(template!.frameworkHints.phpunit).toBeDefined();
    });
  });
});

describe('Code Injection vs Command Injection distinction', () => {
  it('CWE-94 (Code Injection) is different from CWE-78 (Command Injection)', () => {
    const codeInjection = getAssertionTemplate('CWE-94');
    const commandInjection = getAssertionTemplate('CWE-78');

    expect(codeInjection).toBeDefined();
    expect(commandInjection).toBeDefined();

    // Code Injection targets eval/Function
    expect(codeInjection!.assertionGoal).not.toMatch(/shell|subprocess|system\(/i);

    // Command Injection targets shell execution
    expect(commandInjection!.assertionGoal).toMatch(/shell|command/i);
  });

  it('CWE-94 attack payload is code, not shell commands', () => {
    const codeInjection = getAssertionTemplate('CWE-94');
    const commandInjection = getAssertionTemplate('CWE-78');

    // Code injection payload should be JavaScript/Python/etc code
    expect(codeInjection!.attackPayload).not.toMatch(/^;|^\||^&&/);

    // Command injection payload should be shell metacharacters
    expect(commandInjection!.attackPayload).toMatch(/;|cat|passwd/);
  });
});
