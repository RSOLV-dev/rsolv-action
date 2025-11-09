/**
 * Tests for pattern helper functions
 */

import { describe, it, expect } from 'vitest';
import {
  createCodeInjectionPattern,
  createDeserializationPattern,
  createPrototypePollutionPattern,
  isCodeInjectionPattern,
  isPrototypePollutionPattern,
  isDeserializationPattern,
  CWE_IDS,
  OWASP_CATEGORIES
} from '../pattern-helpers.js';
import { VulnerabilityType } from '../types.js';

describe('Pattern Helpers', () => {
  describe('createCodeInjectionPattern', () => {
    it('should create a valid code injection pattern', () => {
      const pattern = createCodeInjectionPattern({
        id: 'test-eval',
        name: 'Test Eval',
        language: 'javascript',
        patterns: [/eval\s*\(/gi]
      });

      expect(pattern.id).toBe('test-eval');
      expect(pattern.type).toBe(VulnerabilityType.CODE_INJECTION);
      expect(pattern.cweId).toBe(CWE_IDS.CODE_INJECTION);
      expect(pattern.severity).toBe('critical');
      expect(pattern.languages).toEqual(['javascript']);
      expect(pattern.patterns.regex).toHaveLength(1);
    });

    it('should use custom description and remediation', () => {
      const pattern = createCodeInjectionPattern({
        id: 'test-eval',
        name: 'Test Eval',
        language: 'python',
        patterns: [/eval\s*\(/gi],
        description: 'Custom description',
        remediation: 'Custom remediation'
      });

      expect(pattern.description).toBe('Custom description');
      expect(pattern.remediation).toBe('Custom remediation');
    });
  });

  describe('createDeserializationPattern', () => {
    it('should create a valid deserialization pattern', () => {
      const pattern = createDeserializationPattern({
        id: 'test-pickle',
        name: 'Test Pickle',
        language: 'python',
        patterns: [/pickle\.loads?\s*\(/gi]
      });

      expect(pattern.id).toBe('test-pickle');
      expect(pattern.type).toBe(VulnerabilityType.INSECURE_DESERIALIZATION);
      expect(pattern.cweId).toBe(CWE_IDS.INSECURE_DESERIALIZATION);
      expect(pattern.severity).toBe('high');
      expect(pattern.languages).toEqual(['python']);
    });
  });

  describe('createPrototypePollutionPattern', () => {
    it('should create a valid prototype pollution pattern', () => {
      const pattern = createPrototypePollutionPattern({
        id: 'test-proto',
        name: 'Test Proto',
        patterns: [/__proto__\s*=/gi]
      });

      expect(pattern.id).toBe('test-proto');
      expect(pattern.type).toBe(VulnerabilityType.PROTOTYPE_POLLUTION);
      expect(pattern.cweId).toBe(CWE_IDS.PROTOTYPE_POLLUTION);
      expect(pattern.severity).toBe('high');
      expect(pattern.languages).toEqual(['javascript', 'typescript']);
    });
  });

  describe('Type Guards', () => {
    it('should correctly identify code injection patterns', () => {
      const codeInjection = createCodeInjectionPattern({
        id: 'test',
        name: 'Test',
        language: 'javascript',
        patterns: [/eval/gi]
      });

      const deserialization = createDeserializationPattern({
        id: 'test',
        name: 'Test',
        language: 'python',
        patterns: [/pickle/gi]
      });

      expect(isCodeInjectionPattern(codeInjection)).toBe(true);
      expect(isCodeInjectionPattern(deserialization)).toBe(false);
    });

    it('should correctly identify prototype pollution patterns', () => {
      const protoPollution = createPrototypePollutionPattern({
        id: 'test',
        name: 'Test',
        patterns: [/__proto__/gi]
      });

      const codeInjection = createCodeInjectionPattern({
        id: 'test',
        name: 'Test',
        language: 'javascript',
        patterns: [/eval/gi]
      });

      expect(isPrototypePollutionPattern(protoPollution)).toBe(true);
      expect(isPrototypePollutionPattern(codeInjection)).toBe(false);
    });

    it('should correctly identify deserialization patterns', () => {
      const deserialization = createDeserializationPattern({
        id: 'test',
        name: 'Test',
        language: 'python',
        patterns: [/pickle/gi]
      });

      const protoPollution = createPrototypePollutionPattern({
        id: 'test',
        name: 'Test',
        patterns: [/__proto__/gi]
      });

      expect(isDeserializationPattern(deserialization)).toBe(true);
      expect(isDeserializationPattern(protoPollution)).toBe(false);
    });
  });

  describe('Constants', () => {
    it('should have correct CWE IDs', () => {
      expect(CWE_IDS.CODE_INJECTION).toBe('CWE-94');
      expect(CWE_IDS.PROTOTYPE_POLLUTION).toBe('CWE-1321');
      expect(CWE_IDS.INSECURE_DESERIALIZATION).toBe('CWE-502');
      expect(CWE_IDS.COMMAND_INJECTION).toBe('CWE-78');
    });

    it('should have correct OWASP categories', () => {
      expect(OWASP_CATEGORIES.INJECTION).toBe('A03:2021');
      expect(OWASP_CATEGORIES.SOFTWARE_DATA_INTEGRITY).toBe('A08:2021');
    });
  });
});
