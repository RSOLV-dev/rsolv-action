/**
 * Tests for Assertion Style Guidance
 * RFC-103: RED Test Generation Quality Improvements
 *
 * Ensures LLM uses AVAILABLE assertion libraries correctly,
 * not libraries that aren't installed.
 */

import { describe, it, expect } from 'vitest';
import {
  getAssertionStyleGuidance,
  AssertionStyle,
  ASSERTION_LIBRARY_STYLES,
} from '../assertion-style-guidance.js';

describe('getAssertionStyleGuidance', () => {
  describe('BDD-style libraries (should, chai, expect)', () => {
    it('returns BDD guidance when "should" is detected', () => {
      const guidance = getAssertionStyleGuidance('javascript', ['should', 'mocha']);

      expect(guidance.style).toBe('bdd');
      expect(guidance.preferredLibrary).toBe('should');
      expect(guidance.syntaxExample).toContain('.should.');
      expect(guidance.doNotUse).toContain('assert');
    });

    it('returns BDD guidance when "chai" is detected', () => {
      const guidance = getAssertionStyleGuidance('javascript', ['chai', 'mocha']);

      expect(guidance.style).toBe('bdd');
      expect(guidance.preferredLibrary).toBe('chai');
      expect(guidance.syntaxExample).toContain('expect(');
      expect(guidance.importStatement).toContain('require(\'chai\')');
    });

    it('returns BDD guidance when "expect.js" is detected', () => {
      const guidance = getAssertionStyleGuidance('javascript', ['expect.js', 'mocha']);

      expect(guidance.style).toBe('bdd');
      expect(guidance.preferredLibrary).toBe('expect.js');
    });
  });

  describe('Jest/Vitest style', () => {
    it('returns jest-style guidance when "jest" is detected', () => {
      const guidance = getAssertionStyleGuidance('javascript', ['jest']);

      expect(guidance.style).toBe('jest');
      expect(guidance.preferredLibrary).toBe('jest');
      expect(guidance.syntaxExample).toContain('expect(');
      expect(guidance.syntaxExample).toContain('.toBe(');
      expect(guidance.importStatement).toBe(''); // Jest globals are auto-available
    });

    it('returns jest-style guidance when "vitest" is detected', () => {
      const guidance = getAssertionStyleGuidance('javascript', ['vitest']);

      expect(guidance.style).toBe('jest');
      expect(guidance.preferredLibrary).toBe('vitest');
      expect(guidance.importStatement).toContain('from \'vitest\'');
    });
  });

  describe('TDD-style (assert)', () => {
    it('returns tdd guidance when only "assert" is available', () => {
      const guidance = getAssertionStyleGuidance('javascript', ['assert', 'mocha']);

      expect(guidance.style).toBe('tdd');
      expect(guidance.preferredLibrary).toBe('assert');
      expect(guidance.syntaxExample).toContain('assert.');
      expect(guidance.versionWarning).toBeDefined();
      expect(guidance.versionWarning).toContain('Node.js');
    });

    it('includes safe assertion methods for Node assert', () => {
      const guidance = getAssertionStyleGuidance('javascript', ['assert']);

      expect(guidance.safeAssertions).toContain('assert.ok');
      expect(guidance.safeAssertions).toContain('assert.strictEqual');
      expect(guidance.safeAssertions).toContain('assert.deepStrictEqual');
      // These require Node 16+
      expect(guidance.unsafeAssertions).toContain('assert.match');
      expect(guidance.unsafeAssertions).toContain('assert.doesNotMatch');
    });
  });

  describe('Priority ordering', () => {
    it('prefers chai over should when both available', () => {
      const guidance = getAssertionStyleGuidance('javascript', ['should', 'chai', 'mocha']);

      expect(guidance.preferredLibrary).toBe('chai');
    });

    it('prefers jest/vitest over chai when both available', () => {
      const guidance = getAssertionStyleGuidance('javascript', ['chai', 'jest']);

      expect(guidance.preferredLibrary).toBe('jest');
    });

    it('prefers BDD libraries over plain assert', () => {
      const guidance = getAssertionStyleGuidance('javascript', ['assert', 'should']);

      expect(guidance.preferredLibrary).toBe('should');
    });
  });

  describe('Fallback behavior', () => {
    it('returns safe Node assert guidance when no libraries detected', () => {
      const guidance = getAssertionStyleGuidance('javascript', []);

      expect(guidance.style).toBe('tdd');
      expect(guidance.preferredLibrary).toBe('assert');
      expect(guidance.versionWarning).toBeDefined();
    });

    it('handles unknown libraries gracefully', () => {
      const guidance = getAssertionStyleGuidance('javascript', ['unknown-lib', 'another-lib']);

      expect(guidance.style).toBe('tdd');
      expect(guidance.preferredLibrary).toBe('assert');
    });
  });

  describe('TypeScript support', () => {
    it('includes TypeScript import syntax when ecosystem is typescript', () => {
      const guidance = getAssertionStyleGuidance('typescript', ['jest']);

      expect(guidance.importStatement).toContain('import');
    });

    it('uses require syntax for JavaScript', () => {
      const guidance = getAssertionStyleGuidance('javascript', ['chai']);

      expect(guidance.importStatement).toContain('require');
    });
  });

  describe('doNotUse guidance', () => {
    it('warns against using unavailable libraries', () => {
      const guidance = getAssertionStyleGuidance('javascript', ['should', 'mocha']);

      // Should warn against common libraries that aren't detected
      expect(guidance.doNotUse).toContain('chai');
      expect(guidance.doNotUse).toContain('sinon');
      expect(guidance.doNotUse).toContain('jest');
    });

    it('does not warn against detected libraries', () => {
      const guidance = getAssertionStyleGuidance('javascript', ['chai', 'sinon', 'mocha']);

      expect(guidance.doNotUse).not.toContain('chai');
      expect(guidance.doNotUse).not.toContain('sinon');
    });
  });
});

describe('ASSERTION_LIBRARY_STYLES', () => {
  it('categorizes common assertion libraries', () => {
    expect(ASSERTION_LIBRARY_STYLES['should']).toBe('bdd');
    expect(ASSERTION_LIBRARY_STYLES['chai']).toBe('bdd');
    expect(ASSERTION_LIBRARY_STYLES['expect.js']).toBe('bdd');
    expect(ASSERTION_LIBRARY_STYLES['jest']).toBe('jest');
    expect(ASSERTION_LIBRARY_STYLES['vitest']).toBe('jest');
    expect(ASSERTION_LIBRARY_STYLES['assert']).toBe('tdd');
  });
});
