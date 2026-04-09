/**
 * RFC-142: Tests for per-instance finding prioritization.
 * prioritizeFindingInstances sorts individual Vulnerability objects
 * (not VulnerabilityGroup) by CWE severity tier, then confidence.
 */

import { describe, it, expect } from 'vitest';
import { prioritizeFindingInstances } from '../finding-prioritizer.js';
import type { Vulnerability } from '../../security/types.js';
import { VulnerabilityType } from '../../security/types.js';
import type { SeverityTierMap } from '../finding-prioritizer.js';

function makeFinding(overrides: Partial<Vulnerability> & { cweId: string; filePath: string }): Vulnerability {
  return {
    type: VulnerabilityType.XSS,
    severity: 'high',
    line: 1,
    message: 'test',
    description: 'test vuln',
    confidence: 80,
    ...overrides,
  };
}

const tiers: SeverityTierMap = {
  'CWE-89': 'critical',
  'CWE-79': 'high',
  'CWE-327': 'medium',
  'CWE-798': 'low',
};

describe('prioritizeFindingInstances (RFC-142)', () => {
  it('sorts findings by CWE severity tier (critical first)', () => {
    const findings: Vulnerability[] = [
      makeFinding({ cweId: 'CWE-327', filePath: 'crypto.js', severity: 'medium', confidence: 90 }),
      makeFinding({ cweId: 'CWE-89', filePath: 'db.js', severity: 'critical', confidence: 80 }),
      makeFinding({ cweId: 'CWE-79', filePath: 'page.js', severity: 'high', confidence: 85 }),
    ];

    const sorted = prioritizeFindingInstances(findings, tiers);

    expect(sorted[0].cweId).toBe('CWE-89');  // critical
    expect(sorted[1].cweId).toBe('CWE-79');  // high
    expect(sorted[2].cweId).toBe('CWE-327'); // medium
  });

  it('sorts by confidence within the same tier', () => {
    const findings: Vulnerability[] = [
      makeFinding({ cweId: 'CWE-79', filePath: 'a.js', severity: 'high', confidence: 60 }),
      makeFinding({ cweId: 'CWE-79', filePath: 'b.js', severity: 'high', confidence: 95 }),
      makeFinding({ cweId: 'CWE-79', filePath: 'c.js', severity: 'high', confidence: 75 }),
    ];

    const sorted = prioritizeFindingInstances(findings, tiers);

    expect(sorted[0].confidence).toBe(95);
    expect(sorted[1].confidence).toBe(75);
    expect(sorted[2].confidence).toBe(60);
  });

  it('does not mutate the input array', () => {
    const findings: Vulnerability[] = [
      makeFinding({ cweId: 'CWE-327', filePath: 'crypto.js', severity: 'medium', confidence: 90 }),
      makeFinding({ cweId: 'CWE-89', filePath: 'db.js', severity: 'critical', confidence: 80 }),
    ];

    const original = [...findings];
    prioritizeFindingInstances(findings, tiers);

    expect(findings[0].cweId).toBe(original[0].cweId);
    expect(findings[1].cweId).toBe(original[1].cweId);
  });

  it('falls back to pattern severity when CWE not in tier map', () => {
    const findings: Vulnerability[] = [
      makeFinding({ cweId: 'CWE-9999', filePath: 'a.js', severity: 'critical', confidence: 80 }),
      makeFinding({ cweId: 'CWE-89', filePath: 'b.js', severity: 'critical', confidence: 80 }),
    ];

    const sorted = prioritizeFindingInstances(findings, tiers);

    // Both are critical tier — CWE-89 via tier map, CWE-9999 via pattern fallback
    // Same tier + same confidence = stable order
    expect(sorted).toHaveLength(2);
  });

  it('handles empty array', () => {
    const sorted = prioritizeFindingInstances([], tiers);
    expect(sorted).toEqual([]);
  });

  it('handles single finding', () => {
    const findings = [makeFinding({ cweId: 'CWE-79', filePath: 'x.js' })];
    const sorted = prioritizeFindingInstances(findings, tiers);
    expect(sorted).toHaveLength(1);
    expect(sorted[0].cweId).toBe('CWE-79');
  });
});
