/**
 * Shared severity types and utilities
 * Centralizes severity-related logic to prevent inconsistencies
 */

/**
 * Vulnerability severity levels in priority order
 */
export type Severity = 'critical' | 'high' | 'medium' | 'low';

/**
 * Severity levels in priority order (highest to lowest)
 * Use this for iteration or ordering operations
 */
export const SEVERITY_LEVELS: readonly Severity[] = ['critical', 'high', 'medium', 'low'] as const;

/**
 * Severity priority mapping (lower number = higher priority)
 * Use this for sorting or comparison operations
 */
export const SEVERITY_PRIORITY: Readonly<Record<Severity, number>> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3
} as const;

/**
 * Compares two severity levels
 * @returns negative if a has higher priority, positive if b has higher priority, 0 if equal
 */
export function compareSeverity(a: Severity, b: Severity): number {
  return SEVERITY_PRIORITY[a] - SEVERITY_PRIORITY[b];
}

/**
 * Checks if a severity level is critical or high
 */
export function isHighSeverity(severity: Severity): boolean {
  return severity === 'critical' || severity === 'high';
}

/**
 * Normalizes severity string to lowercase canonical form
 * Handles case-insensitive input
 */
export function normalizeSeverity(severity: string): Severity {
  const normalized = severity.toLowerCase() as Severity;
  if (!SEVERITY_LEVELS.includes(normalized)) {
    throw new Error(`Invalid severity level: ${severity}`);
  }
  return normalized;
}
