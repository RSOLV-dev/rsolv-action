import type { VulnerabilityGroup } from './types.js';
import type { Severity } from '../security/types.js';
import { SEVERITY_PRIORITY } from '../security/severity.js';
import { logger } from '../utils/logger.js';

/** Map of CWE ID → severity tier string, as returned by the platform API. */
export type SeverityTierMap = Record<string, string>;

/**
 * Fetch CWE severity tiers from the platform's vulnerability type registry.
 * The platform is the single source of truth (RFC-133).
 */
export async function fetchSeverityTiers(apiBaseUrl: string, apiKey: string): Promise<SeverityTierMap> {
  const url = `${apiBaseUrl}/api/v1/vulnerability-types/severity-tiers`;
  const response = await fetch(url, {
    headers: { 'x-api-key': apiKey },
  });

  if (!response.ok) {
    throw new Error(`Failed to fetch severity tiers: ${response.status} ${response.statusText}`);
  }

  const data = await response.json() as { tiers: SeverityTierMap };
  logger.info(`Loaded ${Object.keys(data.tiers).length} CWE severity tiers from platform`);
  return data.tiers;
}

/**
 * Look up the CWE-based severity tier for a given CWE ID.
 * Returns undefined if the CWE is not in the tier mapping.
 */
export function getCweSeverityTier(cweId: string | undefined, tiers: SeverityTierMap): Severity | undefined {
  if (!cweId) return undefined;
  const tier = tiers[cweId];
  if (tier && tier in SEVERITY_PRIORITY) return tier as Severity;
  return undefined;
}

/**
 * Get the effective severity tier for a vulnerability group.
 * Uses CWE tier if available, falls back to pattern-level severity.
 */
function getEffectiveTier(group: VulnerabilityGroup, tiers: SeverityTierMap): Severity {
  const cweId = group.vulnerabilities[0]?.cweId;
  return getCweSeverityTier(cweId, tiers) ?? group.severity;
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
 * @param groups - Vulnerability groups to sort
 * @param tiers - CWE severity tier map from the platform
 * @returns New sorted array — does not mutate the input.
 */
export function prioritizeFindings(groups: VulnerabilityGroup[], tiers: SeverityTierMap): VulnerabilityGroup[] {
  return [...groups].sort((a, b) => {
    const tierA = SEVERITY_PRIORITY[getEffectiveTier(a, tiers)];
    const tierB = SEVERITY_PRIORITY[getEffectiveTier(b, tiers)];

    if (tierA !== tierB) return tierA - tierB;

    return getMaxConfidence(b) - getMaxConfidence(a);
  });
}
