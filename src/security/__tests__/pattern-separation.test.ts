/**
 * Test coverage for pattern separation (v3.8.0):
 * - code_injection (CWE-94)
 * - prototype_pollution (CWE-1321)
 * - insecure_deserialization (CWE-502)
 */

import { describe, it, expect } from 'vitest';
import { getMinimalPatterns } from '../minimal-patterns.js';
import { VulnerabilityType } from '../types.js';

describe('Pattern Separation - v3.8.0', () => {
  const patterns = getMinimalPatterns();

  describe('Code Injection (CWE-94)', () => {
    it('should have CODE_INJECTION type for JavaScript eval patterns', () => {
      const jsEval = patterns.find(p => p.id === 'js-eval');

      expect(jsEval).toBeDefined();
      expect(jsEval?.type).toBe(VulnerabilityType.CODE_INJECTION);
      expect(jsEval?.cweId).toBe('CWE-94');
      expect(jsEval?.severity).toBe('critical');
      expect(jsEval?.languages).toContain('javascript');
      expect(jsEval?.languages).toContain('typescript');
    });

    it('should have CODE_INJECTION type for Python eval patterns', () => {
      const pythonEval = patterns.find(p => p.id === 'python-eval');

      expect(pythonEval).toBeDefined();
      expect(pythonEval?.type).toBe(VulnerabilityType.CODE_INJECTION);
      expect(pythonEval?.cweId).toBe('CWE-94');
      expect(pythonEval?.severity).toBe('critical');
      expect(pythonEval?.languages).toContain('python');
    });

    it('should have CODE_INJECTION type for Ruby eval patterns', () => {
      const rubyEval = patterns.find(p => p.id === 'ruby-eval');

      expect(rubyEval).toBeDefined();
      expect(rubyEval?.type).toBe(VulnerabilityType.CODE_INJECTION);
      expect(rubyEval?.cweId).toBe('CWE-94');
      expect(rubyEval?.severity).toBe('critical');
      expect(rubyEval?.languages).toContain('ruby');
    });

    it('should have CODE_INJECTION type for PHP eval patterns', () => {
      const phpEval = patterns.find(p => p.id === 'php-eval');

      expect(phpEval).toBeDefined();
      expect(phpEval?.type).toBe(VulnerabilityType.CODE_INJECTION);
      expect(phpEval?.cweId).toBe('CWE-94');
      expect(phpEval?.severity).toBe('critical');
      expect(phpEval?.languages).toContain('php');
    });

    it('should have CODE_INJECTION type for Elixir eval patterns', () => {
      const elixirEval = patterns.find(p => p.id === 'elixir-code-eval');

      expect(elixirEval).toBeDefined();
      expect(elixirEval?.type).toBe(VulnerabilityType.CODE_INJECTION);
      expect(elixirEval?.cweId).toBe('CWE-94');
      expect(elixirEval?.severity).toBe('critical');
      expect(elixirEval?.languages).toContain('elixir');
    });

    it('should NOT classify code injection as command injection', () => {
      const codeInjectionPatterns = patterns.filter(p => p.cweId === 'CWE-94');

      expect(codeInjectionPatterns.length).toBeGreaterThan(0);

      codeInjectionPatterns.forEach(pattern => {
        expect(pattern.type).toBe(VulnerabilityType.CODE_INJECTION);
        expect(pattern.type).not.toBe(VulnerabilityType.COMMAND_INJECTION);
      });
    });
  });

  describe('Prototype Pollution (CWE-1321)', () => {
    it('should have PROTOTYPE_POLLUTION pattern for JavaScript', () => {
      const prototypePollution = patterns.find(p => p.id === 'prototype-pollution');

      expect(prototypePollution).toBeDefined();
      expect(prototypePollution?.type).toBe(VulnerabilityType.PROTOTYPE_POLLUTION);
      expect(prototypePollution?.cweId).toBe('CWE-1321');
      expect(prototypePollution?.severity).toBe('high');
      expect(prototypePollution?.languages).toContain('javascript');
      expect(prototypePollution?.languages).toContain('typescript');
    });

    it('should detect __proto__ assignments', () => {
      const prototypePollution = patterns.find(p => p.id === 'prototype-pollution');

      expect(prototypePollution?.patterns.regex).toBeDefined();
      expect(prototypePollution?.patterns.regex?.length).toBeGreaterThan(0);

      // Test that the pattern matches __proto__
      const protoPattern = prototypePollution?.patterns.regex?.find(
        regex => regex.source.includes('__proto__')
      );
      expect(protoPattern).toBeDefined();
    });

    it('should detect Object.assign with user input', () => {
      const prototypePollution = patterns.find(p => p.id === 'prototype-pollution');

      const objectAssignPattern = prototypePollution?.patterns.regex?.find(
        regex => regex.source.includes('Object') && regex.source.includes('assign')
      );
      expect(objectAssignPattern).toBeDefined();
    });

    it('should NOT classify prototype pollution as insecure deserialization', () => {
      const prototypePollution = patterns.find(p => p.id === 'prototype-pollution');

      expect(prototypePollution?.type).not.toBe(VulnerabilityType.INSECURE_DESERIALIZATION);
    });
  });

  describe('Insecure Deserialization (CWE-502)', () => {
    it('should reserve INSECURE_DESERIALIZATION for Python pickle', () => {
      const pythonPickle = patterns.find(p => p.id === 'python-pickle');

      expect(pythonPickle).toBeDefined();
      expect(pythonPickle?.type).toBe(VulnerabilityType.INSECURE_DESERIALIZATION);
      expect(pythonPickle?.cweId).toBe('CWE-502');
      expect(pythonPickle?.languages).toContain('python');
    });

    it('should reserve INSECURE_DESERIALIZATION for Ruby YAML', () => {
      const rubyYaml = patterns.find(p => p.id === 'ruby-yaml');

      expect(rubyYaml).toBeDefined();
      expect(rubyYaml?.type).toBe(VulnerabilityType.INSECURE_DESERIALIZATION);
      expect(rubyYaml?.cweId).toBe('CWE-502');
      expect(rubyYaml?.languages).toContain('ruby');
    });

    it('should NOT classify eval as insecure deserialization', () => {
      const evalPatterns = patterns.filter(p =>
        p.id.includes('eval') &&
        (p.id === 'js-eval' || p.id === 'python-eval' || p.id === 'ruby-eval' ||
         p.id === 'php-eval' || p.id === 'elixir-code-eval')
      );

      expect(evalPatterns.length).toBeGreaterThan(0);

      evalPatterns.forEach(pattern => {
        expect(pattern.type).not.toBe(VulnerabilityType.INSECURE_DESERIALIZATION);
        expect(pattern.type).toBe(VulnerabilityType.CODE_INJECTION);
      });
    });
  });

  describe('Pattern Separation Completeness', () => {
    it('should have distinct patterns for all three vulnerability types', () => {
      const codeInjection = patterns.filter(p => p.type === VulnerabilityType.CODE_INJECTION);
      const prototypePollution = patterns.filter(p => p.type === VulnerabilityType.PROTOTYPE_POLLUTION);
      const insecureDeser = patterns.filter(p => p.type === VulnerabilityType.INSECURE_DESERIALIZATION);

      expect(codeInjection.length).toBeGreaterThan(0);
      expect(prototypePollution.length).toBeGreaterThan(0);
      expect(insecureDeser.length).toBeGreaterThan(0);

      // Ensure no overlap
      const allIds = [
        ...codeInjection.map(p => p.id),
        ...prototypePollution.map(p => p.id),
        ...insecureDeser.map(p => p.id)
      ];
      const uniqueIds = new Set(allIds);
      expect(allIds.length).toBe(uniqueIds.size); // No duplicates
    });

    it('should map correct CWE IDs to vulnerability types', () => {
      const cweMapping = new Map([
        [VulnerabilityType.CODE_INJECTION, 'CWE-94'],
        [VulnerabilityType.PROTOTYPE_POLLUTION, 'CWE-1321'],
        [VulnerabilityType.INSECURE_DESERIALIZATION, 'CWE-502']
      ]);

      patterns.forEach(pattern => {
        if (cweMapping.has(pattern.type)) {
          expect(pattern.cweId).toBe(cweMapping.get(pattern.type));
        }
      });
    });

    it('should have working regex patterns (no serialization issues)', () => {
      const testPatterns = [
        patterns.find(p => p.id === 'js-eval'),
        patterns.find(p => p.id === 'prototype-pollution'),
        patterns.find(p => p.id === 'python-pickle')
      ];

      testPatterns.forEach(pattern => {
        expect(pattern).toBeDefined();
        expect(pattern?.patterns.regex).toBeDefined();

        pattern?.patterns.regex?.forEach(regex => {
          expect(regex).toBeInstanceOf(RegExp);
          expect(regex.source).toBeTruthy();
          // Test that regex can be used (no serialization corruption)
          expect(() => regex.test('test')).not.toThrow();
        });
      });
    });
  });

  describe('Backward Compatibility', () => {
    it('should still have COMMAND_INJECTION for OS commands', () => {
      const commandInjection = patterns.filter(p =>
        p.type === VulnerabilityType.COMMAND_INJECTION
      );

      expect(commandInjection.length).toBeGreaterThan(0);

      // Should be CWE-78, not CWE-94
      commandInjection.forEach(pattern => {
        expect(pattern.cweId).toBe('CWE-78');
        expect(pattern.cweId).not.toBe('CWE-94');
      });
    });
  });
});
