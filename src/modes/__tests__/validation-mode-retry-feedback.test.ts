/**
 * Tests for Retry Feedback Functions
 * RFC-103: RED Test Generation Quality Improvements
 */

import { describe, it, expect } from 'vitest';
import { buildRetryFeedback, extractMissingModule } from '../retry-feedback.js';

describe('Retry Feedback', () => {
  describe('buildRetryFeedback', () => {
    it('provides specific guidance for TestPassedUnexpectedly', () => {
      const attempt = {
        attempt: 1,
        error: 'TestPassedUnexpectedly',
        generatedCode: 'it("tests user search") { expect(search("test")).toBeDefined() }',
        errorMessage: 'Test passed but should have failed'
      };
      const vulnerability = { type: 'SQL Injection', cweId: 'CWE-89' };

      const feedback = buildRetryFeedback(attempt, vulnerability, []);

      expect(feedback).toContain('WHY YOUR PREVIOUS TEST FAILED');
      expect(feedback).toContain('VULNERABLE');
      expect(feedback).toContain('SQL Injection');
    });

    it('includes the actual syntax error for SyntaxError', () => {
      const attempt = {
        attempt: 1,
        error: 'SyntaxError',
        errorMessage: 'SyntaxError: Unexpected token at line 5'
      };

      const feedback = buildRetryFeedback(attempt, { type: 'XSS', cweId: 'CWE-79' }, []);

      expect(feedback).toContain('SYNTAX ERROR');
      expect(feedback).toContain('Unexpected token at line 5');
    });

    it('lists available libraries for MissingDependency', () => {
      const attempt = {
        attempt: 1,
        error: 'MissingDependency',
        errorMessage: "Cannot find module 'chai'"
      };
      const availableLibraries = ['mocha', 'assert', 'sinon'];

      const feedback = buildRetryFeedback(attempt, {}, availableLibraries);

      expect(feedback).toContain('chai');
      expect(feedback).toContain('not available');
      expect(feedback).toContain('mocha');
      expect(feedback).toContain('assert');
      expect(feedback).toContain('sinon');
    });

    it('handles runtime_error with missing module message', () => {
      const attempt = {
        attempt: 1,
        error: 'runtime_error',
        errorMessage: "Error: Cannot find module 'express-validator'"
      };
      const availableLibraries = ['express', 'body-parser'];

      const feedback = buildRetryFeedback(attempt, {}, availableLibraries);

      expect(feedback).toContain('express-validator');
      expect(feedback).toContain('not available');
    });

    it('handles TestExecutionError with module not found', () => {
      const attempt = {
        attempt: 1,
        error: 'TestExecutionError',
        errorMessage: "MODULE_NOT_FOUND: Cannot find module 'supertest'"
      };
      const availableLibraries = ['jest', 'assert'];

      const feedback = buildRetryFeedback(attempt, {}, availableLibraries);

      expect(feedback).toContain('supertest');
    });

    it('provides generic feedback for unknown error types', () => {
      const attempt = {
        attempt: 1,
        error: 'UnknownError',
        errorMessage: 'Something went wrong'
      };

      const feedback = buildRetryFeedback(attempt, { type: 'XSS', cweId: 'CWE-79' }, []);

      expect(feedback).toContain('PREVIOUS ATTEMPT FAILED');
      expect(feedback).toContain('Something went wrong');
    });

    it('includes assertion template guidance when CWE is supported', () => {
      const attempt = {
        attempt: 1,
        error: 'TestPassedUnexpectedly',
        errorMessage: 'Test passed'
      };
      const vulnerability = { type: 'SQL Injection', cweId: 'CWE-89' };

      const feedback = buildRetryFeedback(attempt, vulnerability, []);

      // Should include assertion strategy from template (behavioral)
      expect(feedback).toContain('ASSERTION STRATEGY');
      expect(feedback).toContain('mock the database layer');
    });

    it('skips assertion template for unsupported CWE', () => {
      const attempt = {
        attempt: 1,
        error: 'TestPassedUnexpectedly',
        errorMessage: 'Test passed'
      };
      const vulnerability = { type: 'Unknown Vuln', cweId: 'CWE-99999' };

      const feedback = buildRetryFeedback(attempt, vulnerability, []);

      // Should still provide generic test-passed feedback
      expect(feedback).toContain('WHY YOUR PREVIOUS TEST FAILED');
      // But not the specific assertion strategy
      expect(feedback).not.toContain('ASSERTION STRATEGY');
    });

    it('provides static test rejection feedback for StaticTestNotAcceptable', () => {
      const attempt = {
        attempt: 1,
        error: 'StaticTestNotAcceptable',
        errorMessage: 'Static source analysis — not acceptable for CWE-89',
        retryGuidance: {
          feedback: 'STATIC TEST REJECTED: Your test reads source files...',
          behavioral_hint: 'Assertion goal for SQL Injection: mock the database layer',
          few_shot_example: 'describe("SQL Injection", () => { it("should pass payload unescaped"...'
        }
      };
      const vulnerability = { type: 'SQL Injection', cweId: 'CWE-89' };

      const feedback = buildRetryFeedback(attempt, vulnerability, []);

      expect(feedback).toContain('STATIC TEST REJECTED');
      expect(feedback).toContain('STATIC TEST REJECTED: Your test reads source files');
      expect(feedback).toContain('Assertion goal for SQL Injection');
      expect(feedback).toContain('should pass payload unescaped');
    });

    it('handles StaticTestNotAcceptable without retryGuidance (generic fallback)', () => {
      const attempt = {
        attempt: 1,
        error: 'StaticTestNotAcceptable',
        errorMessage: 'Static source analysis — not acceptable for CWE-89'
      };
      const vulnerability = { type: 'SQL Injection', cweId: 'CWE-89' };

      const feedback = buildRetryFeedback(attempt, vulnerability, []);

      expect(feedback).toContain('STATIC TEST REJECTED');
      expect(feedback).toContain('DO NOT read source files');
    });

    it('includes few_shot_example section when provided in retryGuidance', () => {
      const attempt = {
        attempt: 1,
        error: 'StaticTestNotAcceptable',
        errorMessage: 'Static source analysis',
        retryGuidance: {
          feedback: 'Generate a BEHAVIORAL test',
          behavioral_hint: 'Mock the database layer',
          few_shot_example: 'const dbStub = sinon.stub(db, "query");'
        }
      };

      const feedback = buildRetryFeedback(attempt, { cweId: 'CWE-89' }, []);

      expect(feedback).toContain('EXAMPLE BEHAVIORAL TEST');
      expect(feedback).toContain('sinon.stub');
    });

    it('omits few_shot section when few_shot_example is null', () => {
      const attempt = {
        attempt: 1,
        error: 'StaticTestNotAcceptable',
        errorMessage: 'Static source analysis',
        retryGuidance: {
          feedback: 'Generate a BEHAVIORAL test',
          behavioral_hint: 'Mock the database layer',
          few_shot_example: null
        }
      };

      const feedback = buildRetryFeedback(attempt, { cweId: 'CWE-89' }, []);

      expect(feedback).toContain('BEHAVIORAL test');
      expect(feedback).not.toContain('EXAMPLE BEHAVIORAL TEST');
    });
  });

  describe('extractMissingModule', () => {
    it('extracts module name from Node error', () => {
      expect(extractMissingModule("Cannot find module 'chai'")).toBe('chai');
      expect(extractMissingModule("Error: Cannot find module 'express-validator'")).toBe('express-validator');
    });

    it('extracts module name from Python error', () => {
      expect(extractMissingModule("ModuleNotFoundError: No module named 'pytest_mock'"))
        .toBe('pytest_mock');
      expect(extractMissingModule("ImportError: No module named 'flask'"))
        .toBe('flask');
    });

    it('extracts module name from Ruby error', () => {
      expect(extractMissingModule('cannot load such file -- rspec'))
        .toBe('rspec');
      expect(extractMissingModule('LoadError: cannot load such file -- factory_bot'))
        .toBe('factory_bot');
    });

    it('extracts module name from PHP error', () => {
      expect(extractMissingModule("Class 'PHPUnit\\Framework\\TestCase' not found"))
        .toBe('PHPUnit\\Framework\\TestCase');
    });

    it('extracts module name from Java error', () => {
      expect(extractMissingModule('java.lang.ClassNotFoundException: org.junit.Test'))
        .toBe('org.junit.Test');
    });

    it('returns unknown for unrecognized format', () => {
      expect(extractMissingModule('Some other error')).toBe('unknown');
      expect(extractMissingModule('')).toBe('unknown');
    });

    it('handles null/undefined input gracefully', () => {
      expect(extractMissingModule(null as unknown as string)).toBe('unknown');
      expect(extractMissingModule(undefined as unknown as string)).toBe('unknown');
    });
  });
});
