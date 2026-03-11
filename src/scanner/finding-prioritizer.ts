import type { VulnerabilityGroup } from './types.js';
import type { Severity } from '../security/types.js';
import { SEVERITY_PRIORITY } from '../security/severity.js';

/**
 * CWE-based severity tiers from RFC-133.
 * More precise than pattern-level severity — reflects actual exploitability/impact.
 */
const CWE_SEVERITY_TIERS: Record<string, Severity> = {
  // Critical: injection + deserialization + XXE
  'CWE-89': 'critical',   // SQL Injection
  'CWE-78': 'critical',   // OS Command Injection
  'CWE-77': 'critical',   // Command Injection
  'CWE-94': 'critical',   // Code Injection
  'CWE-95': 'critical',   // Eval Injection
  'CWE-502': 'critical',  // Insecure Deserialization
  'CWE-611': 'critical',  // XXE

  // High: XSS, SSRF, path traversal, CSRF, access control
  'CWE-79': 'high',       // XSS
  'CWE-918': 'high',      // SSRF
  'CWE-22': 'high',       // Path Traversal
  'CWE-352': 'high',      // CSRF
  'CWE-862': 'high',      // Broken Access Control
  'CWE-284': 'high',      // Improper Access Control
  'CWE-287': 'high',      // Improper Authentication
  'CWE-90': 'high',       // LDAP Injection
  'CWE-643': 'high',      // XPath Injection
  'CWE-98': 'high',       // Remote File Inclusion
  'CWE-1321': 'high',     // Prototype Pollution

  // Medium: weak crypto, sensitive data
  'CWE-327': 'medium',    // Weak Cryptographic Algorithm
  'CWE-328': 'medium',    // Weak Hash
  'CWE-256': 'medium',    // Weak Password Storage
  'CWE-312': 'medium',    // Sensitive Data Cleartext
  'CWE-330': 'medium',    // Insecure Randomness
  'CWE-338': 'medium',    // Weak PRNG
  'CWE-521': 'medium',    // Weak Password Requirements
  'CWE-295': 'medium',    // Improper Certificate Validation

  // Low: hardcoded secrets, info exposure, debug
  'CWE-798': 'low',       // Hardcoded Credentials
  'CWE-259': 'low',       // Hardcoded Password
  'CWE-200': 'low',       // Information Exposure
  'CWE-489': 'low',       // Debug Mode
  'CWE-601': 'low',       // Open Redirect
};

/**
 * Look up the CWE-based severity tier for a given CWE ID.
 * Returns undefined if the CWE is not in the tier mapping.
 */
export function getCweSeverityTier(cweId: string | undefined): Severity | undefined {
  if (!cweId) return undefined;
  return CWE_SEVERITY_TIERS[cweId];
}

/**
 * Get the effective severity tier for a vulnerability group.
 * Uses CWE tier if available, falls back to pattern-level severity.
 */
function getEffectiveTier(group: VulnerabilityGroup): Severity {
  const cweId = group.vulnerabilities[0]?.cweId;
  return getCweSeverityTier(cweId) ?? group.severity;
}

/**
 * Get the maximum confidence score across all vulnerabilities in a group.
 */
function getMaxConfidence(group: VulnerabilityGroup): number {
  return Math.max(...group.vulnerabilities.map(v => v.confidence));
}

/**
 * Sort vulnerability groups by CWE severity tier (Critical > High > Medium > Low),
 * then by confidence (descending) within the same tier.
 *
 * Returns a new array — does not mutate the input.
 */
export function prioritizeFindings(groups: VulnerabilityGroup[]): VulnerabilityGroup[] {
  return [...groups].sort((a, b) => {
    const tierA = SEVERITY_PRIORITY[getEffectiveTier(a)];
    const tierB = SEVERITY_PRIORITY[getEffectiveTier(b)];

    if (tierA !== tierB) return tierA - tierB;

    // Within same tier, higher confidence first
    return getMaxConfidence(b) - getMaxConfidence(a);
  });
}
