import { describe, it, expect, beforeEach, vi } from 'vitest';
import { PatternAPIClient } from '../pattern-api-client';
import { VulnerabilityType } from '../types';

global.fetch = vi.fn();

describe('PatternAPIClient Type Mapping', () => {
  let client: PatternAPIClient;

  beforeEach(() => {
    vi.clearAllMocks();
    (global.fetch as any) = vi.fn();
    client = new PatternAPIClient({
      apiKey: 'test_api_key',
      apiUrl: 'https://api.rsolv.dev/api/v1/patterns'
    });
  });

  // Helper to create mock API pattern and test type mapping
  async function testTypeMapping(apiType: string, expectedType: VulnerabilityType) {
    (global.fetch as any).mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        patterns: [{
          id: 'test-id',
          name: 'Test Pattern',
          type: apiType,
          severity: 'high',
          description: 'Test',
          patterns: ['test'],
          languages: ['javascript'],
          cwe_id: 'CWE-000',
          owasp_category: 'A00:2021',
          recommendation: 'Fix it',
          test_cases: { vulnerable: ['bad()'], safe: ['good()'] }
        }],
        metadata: { count: 1 }
      })
    });

    const result = await client.fetchPatterns('javascript');
    return result.patterns[0].type;
  }

  describe('mapVulnerabilityType', () => {
    it('should map prototype_pollution to PROTOTYPE_POLLUTION enum', async () => {
      const type = await testTypeMapping('prototype_pollution', VulnerabilityType.PROTOTYPE_POLLUTION);
      expect(type).toBe(VulnerabilityType.PROTOTYPE_POLLUTION);
      expect(type).not.toBe(VulnerabilityType.IMPROPER_INPUT_VALIDATION);
    });

    it('should map code_injection correctly', async () => {
      const type = await testTypeMapping('code_injection', VulnerabilityType.CODE_INJECTION);
      expect(type).toBe(VulnerabilityType.CODE_INJECTION);
    });

    it('should map insecure_deserialization correctly', async () => {
      const type = await testTypeMapping('insecure_deserialization', VulnerabilityType.INSECURE_DESERIALIZATION);
      expect(type).toBe(VulnerabilityType.INSECURE_DESERIALIZATION);
    });

    it('should fall back to IMPROPER_INPUT_VALIDATION for unknown types', async () => {
      const type = await testTypeMapping('unknown_type', VulnerabilityType.IMPROPER_INPUT_VALIDATION);
      expect(type).toBe(VulnerabilityType.IMPROPER_INPUT_VALIDATION);
    });
  });

  describe('Regression prevention for separated types', () => {
    it('should keep code_injection, insecure_deserialization, and prototype_pollution as separate types', async () => {
      (global.fetch as any).mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          patterns: [
            { id: '1', name: 'CI', type: 'code_injection', severity: 'high', description: 'CI',
              patterns: ['eval'], languages: ['javascript'], cwe_id: 'CWE-94', owasp_category: 'A03',
              recommendation: 'Fix', test_cases: { vulnerable: ['bad()'], safe: ['good()'] } },
            { id: '2', name: 'ID', type: 'insecure_deserialization', severity: 'high', description: 'ID',
              patterns: ['unserialize'], languages: ['javascript'], cwe_id: 'CWE-502', owasp_category: 'A08',
              recommendation: 'Fix', test_cases: { vulnerable: ['bad()'], safe: ['good()'] } },
            { id: '3', name: 'PP', type: 'prototype_pollution', severity: 'high', description: 'PP',
              patterns: ['__proto__'], languages: ['javascript'], cwe_id: 'CWE-1321', owasp_category: 'A08',
              recommendation: 'Fix', test_cases: { vulnerable: ['bad()'], safe: ['good()'] } }
          ],
          metadata: { count: 3 }
        })
      });

      const result = await client.fetchPatterns('javascript');
      const types = result.patterns.map(p => p.type);

      expect(types).toContain(VulnerabilityType.CODE_INJECTION);
      expect(types).toContain(VulnerabilityType.INSECURE_DESERIALIZATION);
      expect(types).toContain(VulnerabilityType.PROTOTYPE_POLLUTION);
      expect(types).not.toContain(VulnerabilityType.IMPROPER_INPUT_VALIDATION);
      expect(new Set(types).size).toBe(3);
    });
  });
});
