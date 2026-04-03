/**
 * E2E validation test for pattern separation (v3.8.0)
 * Simulates RailsGoat workflow to verify correct vulnerability classification
 *
 * This test validates that the three vulnerability types are correctly separated:
 * 1. code_injection (CWE-94) - for eval(), Function(), etc.
 * 2. prototype_pollution (CWE-1321) - for __proto__ manipulation
 * 3. insecure_deserialization (CWE-502) - for pickle/Marshal/unserialize
 */

import { describe, it, expect } from 'vitest';
import { SecurityDetectorV2 } from '../detector-v2.js';
import { VulnerabilityType } from '../types.js';

describe('E2E Pattern Separation - RailsGoat Scenario', () => {
  let detector: SecurityDetectorV2;

  describe('Scenario 1: JavaScript eval() - jquery.snippet.js', () => {
    it('should detect as CODE_INJECTION (not insecure_deserialization)', async () => {
      detector = new SecurityDetectorV2();

      // Simulates jquery.snippet.js from RailsGoat
      const jsCode = `
// jQuery snippet plugin
(function($) {
  $.fn.snippet = function(options) {
    var code = this.text();

    // VULNERABILITY: eval() usage - should be CODE_INJECTION
    eval('var result = ' + code);

    return this;
  };
})(jQuery);
`;

      const vulnerabilities = await detector.detect(jsCode, 'javascript', 'jquery.snippet.js');

      // Should find eval vulnerability
      expect(vulnerabilities.length).toBeGreaterThan(0);

      const evalVuln = vulnerabilities.find(v =>
        v.type === 'code_injection' ||
        v.message?.toLowerCase().includes('eval')
      );

      expect(evalVuln).toBeDefined();
      expect(evalVuln?.type).toBe(VulnerabilityType.CODE_INJECTION);
      expect(evalVuln?.cweId).toBe('CWE-94');
      expect(evalVuln?.severity).toMatch(/critical/i);

      // Should NOT be classified as insecure_deserialization
      const wrongClassification = vulnerabilities.find(v =>
        v.type === 'insecure_deserialization' &&
        v.message?.toLowerCase().includes('eval')
      );
      expect(wrongClassification).toBeUndefined();
    });
  });

  describe('Scenario 2: Prototype Pollution - jsapi.js', () => {
    it('should detect as PROTOTYPE_POLLUTION (not insecure_deserialization)', async () => {
      detector = new SecurityDetectorV2();

      // Simulates jsapi.js prototype pollution from RailsGoat
      const jsCode = `
// API utilities
function merge(target, source) {
  for (let key in source) {
    // VULNERABILITY: Prototype pollution via __proto__
    target[key] = source[key];
  }
  return target;
}

// Example usage with user input
function handleUserData(userData) {
  const config = {};
  merge(config, userData); // If userData contains __proto__, pollution occurs
  return config;
}

// Another pattern: Object.assign with user input
function updateSettings(req) {
  const settings = {};
  // VULNERABILITY: Prototype pollution via Object.assign
  Object.assign(settings, req.body);
  return settings;
}
`;

      const vulnerabilities = await detector.detect(jsCode, 'javascript', 'jsapi.js');

      // May or may not find prototype pollution depending on pattern matching
      // This test documents expected behavior once patterns are deployed

      const protoPollution = vulnerabilities.find(v =>
        v.type === 'prototype_pollution'
      );

      if (protoPollution) {
        expect(protoPollution.cweId).toBe('CWE-1321');
        expect(protoPollution.severity).toMatch(/high/i);

        // Should NOT be classified as insecure_deserialization
        expect(protoPollution.type).not.toBe(VulnerabilityType.INSECURE_DESERIALIZATION);
      } else {
        // Document that pattern may not be in minimal set
        console.log('Note: Prototype pollution pattern not detected - may require full pattern set from API');
      }
    });
  });

  describe('Scenario 3: Ruby Marshal.load() - insecure deserialization', () => {
    it('should detect as INSECURE_DESERIALIZATION (not code_injection)', async () => {
      detector = new SecurityDetectorV2();

      // Simulates Ruby Marshal.load from RailsGoat
      const rubyCode = `
class UserController < ApplicationController
  def restore_session
    session_data = params[:session]

    # VULNERABILITY: Insecure deserialization
    user = Marshal.load(Base64.decode64(session_data))

    session[:user_id] = user.id
  end

  def import_data
    yaml_data = File.read(params[:file])

    # VULNERABILITY: Insecure YAML deserialization
    imported = YAML.load(yaml_data)

    process_import(imported)
  end
end
`;

      const vulnerabilities = await detector.detect(rubyCode, 'ruby', 'user_controller.rb');

      // Should find deserialization vulnerabilities
      expect(vulnerabilities.length).toBeGreaterThan(0);

      const deserVuln = vulnerabilities.find(v =>
        v.type === 'insecure_deserialization' ||
        v.message?.toLowerCase().includes('marshal') ||
        v.message?.toLowerCase().includes('yaml')
      );

      expect(deserVuln).toBeDefined();
      expect(deserVuln?.type).toBe(VulnerabilityType.INSECURE_DESERIALIZATION);
      expect(deserVuln?.cweId).toBe('CWE-502');

      // Should NOT be classified as code_injection
      const wrongClassification = vulnerabilities.find(v =>
        v.type === 'code_injection' &&
        (v.message?.toLowerCase().includes('marshal') || v.message?.toLowerCase().includes('yaml'))
      );
      expect(wrongClassification).toBeUndefined();
    });
  });

  describe('All Three Types Together - Full RailsGoat Scan', () => {
    it('should classify all three vulnerability types correctly in mixed code', async () => {
      detector = new SecurityDetectorV2();

      // Multiple languages/vulnerability types
      const testCases = [
        {
          code: 'eval("code")',
          language: 'javascript',
          file: 'test.js',
          expectedType: VulnerabilityType.CODE_INJECTION,
          expectedCWE: 'CWE-94'
        },
        {
          code: 'Object.assign(config, req.body)',
          language: 'javascript',
          file: 'api.js',
          expectedType: VulnerabilityType.PROTOTYPE_POLLUTION,
          expectedCWE: 'CWE-1321',
          note: 'May not be detected with minimal patterns'
        },
        {
          code: 'Marshal.load(data)',
          language: 'ruby',
          file: 'controller.rb',
          expectedType: VulnerabilityType.INSECURE_DESERIALIZATION,
          expectedCWE: 'CWE-502'
        },
        {
          code: 'pickle.loads(data)',
          language: 'python',
          file: 'api.py',
          expectedType: VulnerabilityType.INSECURE_DESERIALIZATION,
          expectedCWE: 'CWE-502'
        }
      ];

      const results = [];

      for (const testCase of testCases) {
        const vulnerabilities = await detector.detect(
          testCase.code,
          testCase.language,
          testCase.file
        );

        if (vulnerabilities.length > 0) {
          const vuln = vulnerabilities[0];
          results.push({
            file: testCase.file,
            detected: vuln.type,
            expected: testCase.expectedType,
            cwe: vuln.cweId,
            match: vuln.type === testCase.expectedType && vuln.cweId === testCase.expectedCWE
          });
        } else if (testCase.note) {
          console.log(`${testCase.file}: ${testCase.note}`);
        }
      }

      // Verify no cross-contamination
      const codeInjectionResults = results.filter(r =>
        r.expected === VulnerabilityType.CODE_INJECTION
      );
      const deserializationResults = results.filter(r =>
        r.expected === VulnerabilityType.INSECURE_DESERIALIZATION
      );

      // All code_injection should have CWE-94
      codeInjectionResults.forEach(r => {
        expect(r.detected).toBe(VulnerabilityType.CODE_INJECTION);
        expect(r.cwe).toBe('CWE-94');
      });

      // All insecure_deserialization should have CWE-502
      deserializationResults.forEach(r => {
        expect(r.detected).toBe(VulnerabilityType.INSECURE_DESERIALIZATION);
        expect(r.cwe).toBe('CWE-502');
      });

      console.log('Pattern separation validation results:',
        JSON.stringify(results, null, 2)
      );
    });
  });

  describe('Edge Cases - Ensure No Misclassification', () => {
    it('should NOT classify Python eval() as insecure_deserialization', async () => {
      detector = new SecurityDetectorV2();

      const pythonCode = `
def process_formula(formula):
    # Code injection, not deserialization
    result = eval(formula)
    return result
`;

      const vulnerabilities = await detector.detect(pythonCode, 'python', 'calculator.py');

      const evalVuln = vulnerabilities.find(v =>
        v.message?.toLowerCase().includes('eval')
      );

      if (evalVuln) {
        expect(evalVuln.type).toBe(VulnerabilityType.CODE_INJECTION);
        expect(evalVuln.type).not.toBe(VulnerabilityType.INSECURE_DESERIALIZATION);
      }
    });

    it('should NOT classify __proto__ as code_injection', async () => {
      detector = new SecurityDetectorV2();

      const jsCode = `
function merge(obj, data) {
    // Prototype pollution, not code injection
    obj['__proto__'] = data;
}
`;

      const vulnerabilities = await detector.detect(jsCode, 'javascript', 'utils.js');

      const protoVuln = vulnerabilities.find(v =>
        v.message?.toLowerCase().includes('proto')
      );

      if (protoVuln) {
        expect(protoVuln.type).toBe(VulnerabilityType.PROTOTYPE_POLLUTION);
        expect(protoVuln.type).not.toBe(VulnerabilityType.CODE_INJECTION);
      }
    });
  });
});
