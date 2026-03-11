import { logger } from '../utils/logger.js';

/** Valid scan output destinations (RFC-133 Phase 2) */
export type ScanOutputDestination = 'issues' | 'report' | 'dashboard';

const VALID_DESTINATIONS: Set<string> = new Set(['issues', 'report', 'dashboard']);

/**
 * Parse scan_output from action input (comma-separated string) or YAML config (array).
 *
 * Returns a deduplicated array of valid destination strings.
 * Default: ['issues'] (backward compatible with pre-RFC-133 behavior).
 */
export function parseScanOutput(
  input: string | string[] | undefined
): ScanOutputDestination[] {
  if (input === undefined || input === '') {
    return ['issues'];
  }

  const raw: string[] = Array.isArray(input)
    ? input
    : input.split(',').map(s => s.trim());

  const valid = raw.filter(d => {
    if (VALID_DESTINATIONS.has(d)) return true;
    logger.warn(`Ignoring unknown scan_output destination: "${d}"`);
    return false;
  });

  // Deduplicate while preserving order
  return [...new Set(valid)] as ScanOutputDestination[];
}
