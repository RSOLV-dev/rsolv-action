import { describe, it, expect } from 'vitest';
import { prioritizeFindings, getCweSeverityTier, fetchSeverityTiers } from '../finding-prioritizer.js';
import type { SeverityTierMap } from '../finding-prioritizer.js';
import type { VulnerabilityGroup } from '../types.js';
import type { Severity } from '../../security/types.js';

/** Tier map matching what the platform serves via Registry.severity_tiers/0 */
const TIERS: SeverityTierMap = {
  'CWE-89': 'critical',   // SQL injection
  'CWE-78': 'critical',   // Command injection
  'CWE-94': 'critical',   // Code injection
  'CWE-502': 'critical',  // Insecure deserialization
  'CWE-79': 'high',       // XSS
  'CWE-22': 'high',       // Path traversal
  'CWE-352': 'high',      // CSRF
  'CWE-918': 'high',      // SSRF
  'CWE-327': 'medium',    // Weak crypto algorithm
  'CWE-338': 'medium',    // Weak random
  'CWE-798': 'low',       // Hardcoded credentials
  'CWE-200': 'low',       // Information exposure
};

function makeGroup(overrides: {
  type: string;
  severity: Severity;
  cweId?: string;
  confidence?: number;
  count?: number;
}): VulnerabilityGroup {
  const { type, severity, cweId, confidence = 80, count = 1 } = overrides;
  return {
    type,
    severity,
    count,
    files: ['test.py'],
    vulnerabilities: [{
      type: type as any,
      severity,
      line: 1,
      message: 'test',
      description: 'test',
      confidence,
      cweId,
    }],
  };
}

describe('finding-prioritizer', () => {
  describe('getCweSeverityTier', () => {
    it('returns Critical for CWE-89 (SQL injection)', () => {
      expect(getCweSeverityTier('CWE-89', TIERS)).toBe('critical');
    });

    it('returns Critical for CWE-78 (command injection)', () => {
      expect(getCweSeverityTier('CWE-78', TIERS)).toBe('critical');
    });

    it('returns High for CWE-79 (XSS)', () => {
      expect(getCweSeverityTier('CWE-79', TIERS)).toBe('high');
    });

    it('returns Medium for CWE-327 (weak crypto)', () => {
      expect(getCweSeverityTier('CWE-327', TIERS)).toBe('medium');
    });

    it('returns Low for CWE-798 (hardcoded credentials)', () => {
      expect(getCweSeverityTier('CWE-798', TIERS)).toBe('low');
    });

    it('returns undefined for unknown CWE', () => {
      expect(getCweSeverityTier('CWE-99999', TIERS)).toBeUndefined();
    });

    it('returns undefined when no CWE provided', () => {
      expect(getCweSeverityTier(undefined, TIERS)).toBeUndefined();
    });
  });

  describe('prioritizeFindings', () => {
    it('ranks SQLi (CWE-89 Critical) above hardcoded creds (CWE-798 Low)', () => {
      const groups = [
        makeGroup({ type: 'hardcoded_secrets', severity: 'high', cweId: 'CWE-798', confidence: 90 }),
        makeGroup({ type: 'sql_injection', severity: 'high', cweId: 'CWE-89', confidence: 80 }),
      ];

      const result = prioritizeFindings(groups, TIERS);

      expect(result[0].type).toBe('sql_injection');
      expect(result[1].type).toBe('hardcoded_secrets');
    });

    it('ranks command injection (CWE-78 Critical) above XSS (CWE-79 High)', () => {
      const groups = [
        makeGroup({ type: 'xss', severity: 'high', cweId: 'CWE-79' }),
        makeGroup({ type: 'command_injection', severity: 'high', cweId: 'CWE-78' }),
      ];

      const result = prioritizeFindings(groups, TIERS);

      expect(result[0].type).toBe('command_injection');
      expect(result[1].type).toBe('xss');
    });

    it('sorts by confidence within the same CWE tier', () => {
      const groups = [
        makeGroup({ type: 'sql_injection', severity: 'critical', cweId: 'CWE-89', confidence: 70 }),
        makeGroup({ type: 'command_injection', severity: 'critical', cweId: 'CWE-78', confidence: 95 }),
        makeGroup({ type: 'code_injection', severity: 'critical', cweId: 'CWE-94', confidence: 85 }),
      ];

      const result = prioritizeFindings(groups, TIERS);

      expect(result.map(g => g.type)).toEqual([
        'command_injection',  // 95 confidence
        'code_injection',     // 85 confidence
        'sql_injection',      // 70 confidence
      ]);
    });

    it('falls back to pattern severity when CWE is missing', () => {
      const groups = [
        makeGroup({ type: 'unknown_vuln', severity: 'low' }),
        makeGroup({ type: 'sql_injection', severity: 'critical', cweId: 'CWE-89' }),
        makeGroup({ type: 'another_vuln', severity: 'high' }),
      ];

      const result = prioritizeFindings(groups, TIERS);

      // CWE-89 Critical tier first, then pattern severity high, then low
      expect(result[0].type).toBe('sql_injection');
      expect(result[1].type).toBe('another_vuln');
      expect(result[2].type).toBe('unknown_vuln');
    });

    it('CWE tier overrides pattern severity', () => {
      // hardcoded_secrets has pattern severity "critical" but CWE-798 is Low tier
      const groups = [
        makeGroup({ type: 'hardcoded_secrets', severity: 'critical', cweId: 'CWE-798' }),
        makeGroup({ type: 'path_traversal', severity: 'medium', cweId: 'CWE-22' }),
      ];

      const result = prioritizeFindings(groups, TIERS);

      // CWE-22 is High tier, CWE-798 is Low tier — CWE tier wins
      expect(result[0].type).toBe('path_traversal');
      expect(result[1].type).toBe('hardcoded_secrets');
    });

    it('preserves original array (returns new array)', () => {
      const groups = [
        makeGroup({ type: 'hardcoded_secrets', severity: 'high', cweId: 'CWE-798' }),
        makeGroup({ type: 'sql_injection', severity: 'high', cweId: 'CWE-89' }),
      ];
      const original = [...groups];

      prioritizeFindings(groups, TIERS);

      expect(groups[0].type).toBe(original[0].type);
      expect(groups[1].type).toBe(original[1].type);
    });

    it('handles empty array', () => {
      expect(prioritizeFindings([], TIERS)).toEqual([]);
    });

    it('handles single element', () => {
      const groups = [makeGroup({ type: 'sql_injection', severity: 'critical', cweId: 'CWE-89' })];
      const result = prioritizeFindings(groups, TIERS);
      expect(result).toHaveLength(1);
      expect(result[0].type).toBe('sql_injection');
    });

    it('uses max confidence from group vulnerabilities', () => {
      const highConfGroup: VulnerabilityGroup = {
        type: 'sql_injection',
        severity: 'critical',
        count: 2,
        files: ['a.py', 'b.py'],
        vulnerabilities: [
          { type: 'sql_injection' as any, severity: 'critical', line: 1, message: '', description: '', confidence: 60, cweId: 'CWE-89' },
          { type: 'sql_injection' as any, severity: 'critical', line: 5, message: '', description: '', confidence: 95, cweId: 'CWE-89' },
        ],
      };
      const lowConfGroup: VulnerabilityGroup = {
        type: 'command_injection',
        severity: 'critical',
        count: 1,
        files: ['c.py'],
        vulnerabilities: [
          { type: 'command_injection' as any, severity: 'critical', line: 1, message: '', description: '', confidence: 80, cweId: 'CWE-78' },
        ],
      };

      const result = prioritizeFindings([lowConfGroup, highConfGroup], TIERS);

      // Both Critical tier, but sql_injection group has max confidence 95 > 80
      expect(result[0].type).toBe('sql_injection');
      expect(result[1].type).toBe('command_injection');
    });

    it('reproduces the pygoat problem: SQLi should outrank hardcoded creds', () => {
      const groups = [
        makeGroup({ type: 'hardcoded_secrets', severity: 'high', cweId: 'CWE-798', confidence: 90 }),
        makeGroup({ type: 'insecure_deserialization', severity: 'critical', cweId: 'CWE-502', confidence: 85 }),
        makeGroup({ type: 'code_injection', severity: 'critical', cweId: 'CWE-94', confidence: 80 }),
        makeGroup({ type: 'sql_injection', severity: 'critical', cweId: 'CWE-89', confidence: 88 }),
        makeGroup({ type: 'command_injection', severity: 'high', cweId: 'CWE-78', confidence: 75 }),
        makeGroup({ type: 'weak_cryptography', severity: 'medium', cweId: 'CWE-327', confidence: 70 }),
      ];

      const result = prioritizeFindings(groups, TIERS);
      const top3 = result.slice(0, 3);

      // All three top slots should be Critical tier CWEs
      expect(top3.map(g => g.type)).toEqual([
        'sql_injection',           // Critical tier, confidence 88
        'insecure_deserialization', // Critical tier, confidence 85
        'code_injection',          // Critical tier, confidence 80
      ]);

      // hardcoded_secrets should be last (Low tier)
      expect(result[result.length - 1].type).toBe('hardcoded_secrets');
    });
  });

  describe('fetchSeverityTiers', () => {
    it('fetches tier map from platform API', async () => {
      const mockResponse = {
        ok: true,
        json: async () => ({ tiers: { 'CWE-89': 'critical', 'CWE-798': 'low' } }),
        status: 200,
        statusText: 'OK',
      };
      const originalFetch = globalThis.fetch;
      globalThis.fetch = async () => mockResponse as Response;

      try {
        const tiers = await fetchSeverityTiers('https://api.example.com', 'test-key');
        expect(tiers).toEqual({ 'CWE-89': 'critical', 'CWE-798': 'low' });
      } finally {
        globalThis.fetch = originalFetch;
      }
    });

    it('throws on non-OK response', async () => {
      const mockResponse = {
        ok: false,
        status: 500,
        statusText: 'Internal Server Error',
      };
      const originalFetch = globalThis.fetch;
      globalThis.fetch = async () => mockResponse as Response;

      try {
        await expect(fetchSeverityTiers('https://api.example.com', 'test-key'))
          .rejects.toThrow('Failed to fetch severity tiers: 500 Internal Server Error');
      } finally {
        globalThis.fetch = originalFetch;
      }
    });

    it('sends x-api-key header', async () => {
      let capturedHeaders: HeadersInit | undefined;
      const mockResponse = {
        ok: true,
        json: async () => ({ tiers: {} }),
        status: 200,
        statusText: 'OK',
      };
      const originalFetch = globalThis.fetch;
      globalThis.fetch = async (_url: any, init: any) => {
        capturedHeaders = init?.headers;
        return mockResponse as Response;
      };

      try {
        await fetchSeverityTiers('https://api.example.com', 'my-api-key');
        expect(capturedHeaders).toEqual({ 'x-api-key': 'my-api-key' });
      } finally {
        globalThis.fetch = originalFetch;
      }
    });
  });
});
