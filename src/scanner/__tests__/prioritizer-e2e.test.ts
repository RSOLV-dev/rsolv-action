/**
 * E2E verification: CWE severity tier prioritization on real pygoat-like data.
 * This simulates the exact pygoat scenario from Run 015-018 where hardcoded
 * credentials (CWE-798, Low tier) were selected over SQL injection (CWE-89, Critical tier).
 *
 * NOTE: vulnerability descriptions reference real vulnerability patterns found in
 * intentionally-vulnerable demo apps. No actual vulnerable code is present in this test.
 */
import { describe, it, expect } from 'vitest';
import { prioritizeFindings, getCweSeverityTier } from '../finding-prioritizer.js';
import type { VulnerabilityGroup } from '../types.js';

describe('RFC-133 E2E: pygoat scan prioritization', () => {
  it('verifies real pygoat findings are prioritized correctly with max_issues=3', () => {
    // These are the actual vulnerability types pygoat produces across runs.
    // Each entry represents a SCAN finding (metadata only, no actual vulnerable code).
    const pygoatFindings: VulnerabilityGroup[] = [
      // Insertion order matches what the scanner produces (pre-prioritization)
      {
        type: 'hardcoded_secrets',
        severity: 'high',
        count: 5,
        files: ['introduction/views.py', 'settings.py'],
        vulnerabilities: [
          { type: 'hardcoded_secrets' as any, severity: 'high', line: 12, message: 'Hardcoded secret', description: 'SECRET_KEY in settings', confidence: 92, cweId: 'CWE-798', filePath: 'settings.py' },
          { type: 'hardcoded_secrets' as any, severity: 'high', line: 45, message: 'Hardcoded cred', description: 'Password in view', confidence: 88, cweId: 'CWE-798', filePath: 'introduction/views.py' },
        ],
        isVendor: false,
      },
      {
        type: 'insecure_deserialization',
        severity: 'critical',
        count: 2,
        files: ['introduction/views.py'],
        vulnerabilities: [
          { type: 'insecure_deserialization' as any, severity: 'critical', line: 78, message: 'Unsafe deserialization', description: 'Insecure deserialization of untrusted data', confidence: 85, cweId: 'CWE-502', filePath: 'introduction/views.py' },
        ],
        isVendor: false,
      },
      {
        type: 'code_injection',
        severity: 'critical',
        count: 3,
        files: ['introduction/views.py'],
        vulnerabilities: [
          { type: 'code_injection' as any, severity: 'critical', line: 112, message: 'Dynamic execution', description: 'Code injection via dynamic execution', confidence: 80, cweId: 'CWE-94', filePath: 'introduction/views.py' },
        ],
        isVendor: false,
      },
      {
        type: 'sql_injection',
        severity: 'critical',
        count: 4,
        files: ['introduction/views.py', 'introduction/models.py'],
        vulnerabilities: [
          { type: 'sql_injection' as any, severity: 'critical', line: 156, message: 'Raw SQL', description: 'SQL injection via string format', confidence: 90, cweId: 'CWE-89', filePath: 'introduction/views.py' },
          { type: 'sql_injection' as any, severity: 'critical', line: 23, message: 'Raw SQL', description: 'SQL injection in model', confidence: 88, cweId: 'CWE-89', filePath: 'introduction/models.py' },
        ],
        isVendor: false,
      },
      {
        type: 'command_injection',
        severity: 'high',
        count: 1,
        files: ['introduction/views.py'],
        vulnerabilities: [
          { type: 'command_injection' as any, severity: 'high', line: 200, message: 'System command', description: 'Command injection via os module', confidence: 75, cweId: 'CWE-78', filePath: 'introduction/views.py' },
        ],
        isVendor: false,
      },
      {
        type: 'weak_cryptography',
        severity: 'medium',
        count: 2,
        files: ['introduction/views.py'],
        vulnerabilities: [
          { type: 'weak_cryptography' as any, severity: 'medium', line: 67, message: 'Weak hash', description: 'Weak hashing algorithm', confidence: 70, cweId: 'CWE-327', filePath: 'introduction/views.py' },
        ],
        isVendor: false,
      },
    ];

    // WITHOUT prioritization (old behavior): first 3 = hardcoded_secrets, insecure_deserialization, code_injection
    const oldTop3 = pygoatFindings.slice(0, 3).map(g => g.type);
    expect(oldTop3).toEqual(['hardcoded_secrets', 'insecure_deserialization', 'code_injection']);

    // WITH prioritization: should be all Critical CWEs, ordered by confidence
    const prioritized = prioritizeFindings(pygoatFindings);
    const newTop3 = prioritized.slice(0, 3).map(g => g.type);

    // SQL injection (CWE-89, confidence 90) should be first
    // Insecure deserialization (CWE-502, confidence 85) second
    // Code injection (CWE-94, confidence 80) third
    // Hardcoded secrets (CWE-798, Low tier) should NOT be in top 3
    expect(newTop3).toEqual(['sql_injection', 'insecure_deserialization', 'code_injection']);
    expect(newTop3).not.toContain('hardcoded_secrets');

    // Verify CWE tiers are correct
    expect(getCweSeverityTier('CWE-89')).toBe('critical');
    expect(getCweSeverityTier('CWE-502')).toBe('critical');
    expect(getCweSeverityTier('CWE-94')).toBe('critical');
    expect(getCweSeverityTier('CWE-798')).toBe('low');

    // Hardcoded secrets should be last
    expect(prioritized[prioritized.length - 1].type).toBe('hardcoded_secrets');
  });
});
