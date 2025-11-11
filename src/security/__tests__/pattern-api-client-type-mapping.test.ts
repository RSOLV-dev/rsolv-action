import { describe, it, expect, beforeEach, vi } from 'vitest';
import { PatternAPIClient } from '../pattern-api-client';
import { VulnerabilityType } from '../types';

// Mock fetch globally
global.fetch = vi.fn();

describe('PatternAPIClient Type Mapping', () => {
  let client: PatternAPIClient;
  const mockApiKey = 'test_api_key';
  const mockApiUrl = 'https://api.rsolv.dev/api/v1/patterns';

  beforeEach(() => {
    vi.clearAllMocks();
    (global.fetch as any) = vi.fn();

    client = new PatternAPIClient({
      apiKey: mockApiKey,
      apiUrl: mockApiUrl
    });
  });

  describe('mapVulnerabilityType', () => {
    /**
     * TDD Test - RED Phase
     * This test will FAIL until we add 'prototype_pollution' to the typeMap
     *
     * Context: Platform API returns type: "prototype_pollution" but RSOLV-action
     * incorrectly converts it to IMPROPER_INPUT_VALIDATION because the mapping
     * doesn't exist in pattern-api-client.ts:318
     */
    it('should map prototype_pollution to PROTOTYPE_POLLUTION enum', async () => {
      // Arrange: Mock API response with prototype_pollution type
      const mockApiPattern = {
        id: 'js-prototype-pollution-001',
        name: 'Prototype Pollution via Object.assign',
        type: 'prototype_pollution', // This is what the API returns
        severity: 'high',
        description: 'Detects prototype pollution vulnerabilities',
        patterns: ['__proto__', 'constructor.prototype'],
        languages: ['javascript'],
        cwe_id: 'CWE-1321',
        owasp_category: 'A08:2021',
        recommendation: 'Use Object.create(null) or freeze prototypes',
        test_cases: {
          vulnerable: ['obj[key] = value'],
          safe: ['Object.defineProperty(obj, key, {value, writable: false})']
        }
      };

      (global.fetch as any).mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          patterns: [mockApiPattern],
          metadata: { count: 1 }
        })
      });

      // Act: Fetch patterns which will call convertToSecurityPattern
      const result = await client.fetchPatterns('javascript');
      const pattern = result.patterns[0];

      // Assert: Verify correct type mapping
      // This should FAIL initially because 'prototype_pollution' is not in typeMap
      expect(pattern.type).toBe(VulnerabilityType.PROTOTYPE_POLLUTION);
      expect(pattern.type).not.toBe(VulnerabilityType.IMPROPER_INPUT_VALIDATION);

      // Additional assertions to verify the pattern was converted correctly
      expect(pattern.id).toBe('js-prototype-pollution-001');
      expect(pattern.name).toBe('Prototype Pollution via Object.assign');
      expect(pattern.severity).toBe('high');
      expect(pattern.cweId).toBe('CWE-1321');
    });

    it('should handle code_injection type correctly (already exists)', async () => {
      const mockApiPattern = {
        id: 'js-code-injection-001',
        name: 'Code Injection via eval',
        type: 'code_injection',
        severity: 'critical',
        description: 'Detects code injection via eval',
        patterns: ['eval('],
        languages: ['javascript'],
        cwe_id: 'CWE-94',
        owasp_category: 'A03:2021',
        recommendation: 'Never use eval with user input',
        test_cases: {
          vulnerable: ['eval(userInput)'],
          safe: ['JSON.parse(userInput)']
        }
      };

      (global.fetch as any).mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          patterns: [mockApiPattern],
          metadata: { count: 1 }
        })
      });

      const result = await client.fetchPatterns('javascript');
      const pattern = result.patterns[0];

      expect(pattern.type).toBe(VulnerabilityType.CODE_INJECTION);
      expect(pattern.type).not.toBe(VulnerabilityType.IMPROPER_INPUT_VALIDATION);
    });

    it('should handle insecure_deserialization type correctly (already exists)', async () => {
      const mockApiPattern = {
        id: 'js-insecure-deser-001',
        name: 'Insecure Deserialization',
        type: 'insecure_deserialization',
        severity: 'high',
        description: 'Detects insecure deserialization',
        patterns: ['unserialize('],
        languages: ['javascript'],
        cwe_id: 'CWE-502',
        owasp_category: 'A08:2021',
        recommendation: 'Validate serialized data',
        test_cases: {
          vulnerable: ['unserialize(data)'],
          safe: ['JSON.parse(data)']
        }
      };

      (global.fetch as any).mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          patterns: [mockApiPattern],
          metadata: { count: 1 }
        })
      });

      const result = await client.fetchPatterns('javascript');
      const pattern = result.patterns[0];

      expect(pattern.type).toBe(VulnerabilityType.INSECURE_DESERIALIZATION);
      expect(pattern.type).not.toBe(VulnerabilityType.IMPROPER_INPUT_VALIDATION);
    });

    it('should fall back to IMPROPER_INPUT_VALIDATION for unknown types', async () => {
      const mockApiPattern = {
        id: 'js-unknown-001',
        name: 'Unknown Vulnerability',
        type: 'unknown_vulnerability_type',
        severity: 'medium',
        description: 'Unknown type',
        patterns: ['pattern'],
        languages: ['javascript'],
        cwe_id: 'CWE-000',
        owasp_category: 'A00:2021',
        recommendation: 'Fix it',
        test_cases: {
          vulnerable: ['bad()'],
          safe: ['good()']
        }
      };

      (global.fetch as any).mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          patterns: [mockApiPattern],
          metadata: { count: 1 }
        })
      });

      const result = await client.fetchPatterns('javascript');
      const pattern = result.patterns[0];

      // Unknown types should fall back to IMPROPER_INPUT_VALIDATION
      expect(pattern.type).toBe(VulnerabilityType.IMPROPER_INPUT_VALIDATION);
    });
  });

  describe('Regression prevention for separated types', () => {
    it('should keep code_injection, insecure_deserialization, and prototype_pollution as separate types', async () => {
      const mockPatterns = [
        {
          id: 'ci-001',
          name: 'Code Injection',
          type: 'code_injection',
          severity: 'critical',
          description: 'CI',
          patterns: ['eval'],
          languages: ['javascript'],
          cwe_id: 'CWE-94',
          owasp_category: 'A03:2021',
          recommendation: 'Avoid eval',
          test_cases: { vulnerable: ['eval()'], safe: ['parse()'] }
        },
        {
          id: 'id-001',
          name: 'Insecure Deserialization',
          type: 'insecure_deserialization',
          severity: 'high',
          description: 'ID',
          patterns: ['unserialize'],
          languages: ['javascript'],
          cwe_id: 'CWE-502',
          owasp_category: 'A08:2021',
          recommendation: 'Validate',
          test_cases: { vulnerable: ['unserialize()'], safe: ['JSON.parse()'] }
        },
        {
          id: 'pp-001',
          name: 'Prototype Pollution',
          type: 'prototype_pollution',
          severity: 'high',
          description: 'PP',
          patterns: ['__proto__'],
          languages: ['javascript'],
          cwe_id: 'CWE-1321',
          owasp_category: 'A08:2021',
          recommendation: 'Freeze',
          test_cases: { vulnerable: ['obj[key]=val'], safe: ['defineProperty()'] }
        }
      ];

      (global.fetch as any).mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          patterns: mockPatterns,
          metadata: { count: 3 }
        })
      });

      const result = await client.fetchPatterns('javascript');

      // Verify all three types are distinct
      const types = result.patterns.map(p => p.type);
      expect(types).toContain(VulnerabilityType.CODE_INJECTION);
      expect(types).toContain(VulnerabilityType.INSECURE_DESERIALIZATION);
      expect(types).toContain(VulnerabilityType.PROTOTYPE_POLLUTION);

      // Verify none fell back to IMPROPER_INPUT_VALIDATION
      expect(types).not.toContain(VulnerabilityType.IMPROPER_INPUT_VALIDATION);

      // Verify we got exactly 3 distinct types
      expect(new Set(types).size).toBe(3);
    });
  });
});
