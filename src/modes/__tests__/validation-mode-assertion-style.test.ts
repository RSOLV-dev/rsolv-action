/**
 * Tests for Assertion Style Guidance Integration in ValidationMode
 * RFC-103: RED Test Generation Quality Improvements
 *
 * Verifies that assertion style guidance is correctly integrated into
 * the LLM prompt based on available test libraries.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { getAssertionStyleGuidance } from '../../prompts/assertion-style-guidance.js';

describe('ValidationMode Assertion Style Integration', () => {
  describe('getAssertionStyleGuidance', () => {
    it('recommends BDD style when should is available', () => {
      const guidance = getAssertionStyleGuidance('javascript', ['should', 'mocha']);

      expect(guidance.style).toBe('bdd');
      expect(guidance.preferredLibrary).toBe('should');
      expect(guidance.syntaxExample).toContain('.should.');
    });

    it('recommends Jest style when Jest is available', () => {
      const guidance = getAssertionStyleGuidance('javascript', ['jest']);

      expect(guidance.style).toBe('jest');
      expect(guidance.preferredLibrary).toBe('jest');
      expect(guidance.syntaxExample).toContain('expect(');
      expect(guidance.syntaxExample).toContain('.toBe(');
    });

    it('recommends TDD style with safe methods when only assert is available', () => {
      const guidance = getAssertionStyleGuidance('javascript', ['assert', 'mocha']);

      expect(guidance.style).toBe('tdd');
      expect(guidance.preferredLibrary).toBe('assert');
      expect(guidance.versionWarning).toBeDefined();
      expect(guidance.safeAssertions).toContain('assert.ok');
      expect(guidance.safeAssertions).toContain('assert.strictEqual');
      expect(guidance.unsafeAssertions).toContain('assert.match');
      expect(guidance.unsafeAssertions).toContain('assert.doesNotMatch');
    });

    it('warns against unavailable libraries in doNotUse', () => {
      const guidance = getAssertionStyleGuidance('javascript', ['mocha', 'assert']);

      expect(guidance.doNotUse).toContain('chai');
      expect(guidance.doNotUse).toContain('sinon');
      expect(guidance.doNotUse).toContain('jest');
      // Should not warn against assert since it's available
      expect(guidance.doNotUse).not.toContain('assert');
    });
  });

  describe('Ecosystem-Framework mapping', () => {
    it('JavaScript frameworks use JavaScript ecosystem', () => {
      const jsFrameworks = ['jest', 'vitest', 'mocha', 'jasmine'];
      for (const framework of jsFrameworks) {
        const guidance = getAssertionStyleGuidance('javascript', [framework]);
        // Should not crash and should return valid guidance
        expect(guidance.style).toBeDefined();
        expect(guidance.preferredLibrary).toBeDefined();
      }
    });

    it('Python ecosystem works with pytest libraries', () => {
      const guidance = getAssertionStyleGuidance('python', ['pytest', 'pytest-mock']);

      // Python defaults to TDD style (assert-based)
      expect(guidance.style).toBe('tdd');
      expect(guidance.preferredLibrary).toBe('assert');
    });

    it('Ruby ecosystem works with RSpec', () => {
      const guidance = getAssertionStyleGuidance('ruby', ['rspec', 'webmock']);

      // Ruby with RSpec not in JS library list, falls back to assert
      expect(guidance.style).toBe('tdd');
      expect(guidance.preferredLibrary).toBe('assert');
    });

    it('TypeScript uses ES import syntax', () => {
      const guidance = getAssertionStyleGuidance('typescript', ['jest']);

      expect(guidance.importStatement).toContain('import');
      expect(guidance.importStatement).toContain('@jest/globals');
    });
  });

  describe('Priority ordering ensures best library is selected', () => {
    it('prefers Jest over Chai when both available', () => {
      const guidance = getAssertionStyleGuidance('javascript', ['chai', 'jest']);

      expect(guidance.preferredLibrary).toBe('jest');
      expect(guidance.style).toBe('jest');
    });

    it('prefers Vitest over Mocha/assert', () => {
      const guidance = getAssertionStyleGuidance('javascript', ['mocha', 'assert', 'vitest']);

      expect(guidance.preferredLibrary).toBe('vitest');
      expect(guidance.style).toBe('jest');
    });

    it('prefers Chai over Should when both available', () => {
      const guidance = getAssertionStyleGuidance('javascript', ['should', 'chai']);

      expect(guidance.preferredLibrary).toBe('chai');
      expect(guidance.style).toBe('bdd');
    });
  });

  describe('Vitest always uses ES import syntax', () => {
    it('uses ES import even with javascript ecosystem', () => {
      const guidance = getAssertionStyleGuidance('javascript', ['vitest']);

      // Vitest is ESM-first, should always use ES imports
      expect(guidance.importStatement).toContain("from 'vitest'");
      expect(guidance.importStatement).not.toContain('require');
    });

    it('uses ES import with typescript ecosystem', () => {
      const guidance = getAssertionStyleGuidance('typescript', ['vitest']);

      expect(guidance.importStatement).toContain("from 'vitest'");
    });
  });

  describe('Node assert version warnings', () => {
    it('warns about unsafe assert methods requiring Node 16+', () => {
      const guidance = getAssertionStyleGuidance('javascript', ['assert', 'mocha']);

      expect(guidance.versionWarning).toContain('Node 16+');
      expect(guidance.versionWarning).toContain('assert.match');
      expect(guidance.versionWarning).toContain('assert.doesNotMatch');
    });

    it('lists safe methods that work on all Node versions', () => {
      const guidance = getAssertionStyleGuidance('javascript', ['assert']);

      expect(guidance.safeAssertions).toContain('assert.ok');
      expect(guidance.safeAssertions).toContain('assert.strictEqual');
      expect(guidance.safeAssertions).toContain('assert.deepStrictEqual');
      expect(guidance.safeAssertions).toContain('assert.throws');
    });
  });
});
