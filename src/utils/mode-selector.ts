/**
 * Mode selection utilities for RFC-126 pipeline architecture.
 *
 * Three primary modes:
 * - scan: Scan repository, create issues, register PipelineRun
 * - process: Discover and execute pending work for an existing PipelineRun
 * - full: Run all phases in a single job (scan → validate → mitigate)
 *
 * Legacy aliases kept for backward compatibility:
 * - validate / validate-only → single-issue backend-orchestrated validation
 * - mitigate / fix-only → single-issue backend-orchestrated mitigation
 */

export type ExecutionMode = 'scan' | 'validate' | 'mitigate' | 'full' | 'validate-only' | 'fix-only' | 'process';

const VALID_MODES: ExecutionMode[] = ['scan', 'validate', 'mitigate', 'full', 'validate-only', 'fix-only', 'process'];

export interface ModeRequirements {
  requiresIssue: boolean;
  requiresScanData: boolean;
  requiresValidation: boolean;
}

/**
 * Extract mode from command line arguments
 * Supports --mode <value> and --mode=<value> syntax
 */
export function getModeFromArgs(): string | undefined {
  const args = process.argv.slice(2);

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];

    // Handle --mode=value syntax
    if (arg.startsWith('--mode=')) {
      return arg.substring('--mode='.length);
    }

    // Handle --mode value syntax
    if (arg === '--mode' && i + 1 < args.length) {
      return args[i + 1];
    }
  }

  return undefined;
}

/**
 * Get execution mode with proper precedence:
 * 1. CLI args (highest priority)
 * 2. RSOLV_MODE environment variable
 * 3. Legacy RSOLV_SCAN_MODE (for backward compatibility)
 * 4. Default to 'full' mode
 */
export function getExecutionMode(): ExecutionMode {
  const cliMode = getModeFromArgs();
  if (cliMode) {
    const normalizedCliMode = cliMode.toLowerCase();
    if (validateMode(normalizedCliMode)) {
      return normalizedCliMode as ExecutionMode;
    }
  }

  const envMode = process.env.RSOLV_MODE || process.env.INPUT_MODE;
  if (envMode) {
    const normalizedEnvMode = envMode.toLowerCase();
    if (validateMode(normalizedEnvMode)) {
      return normalizedEnvMode as ExecutionMode;
    }
  }

  const legacyMode = process.env.RSOLV_SCAN_MODE;
  if (legacyMode && legacyMode.toLowerCase() === 'scan') {
    return 'scan';
  }

  return 'full';
}

/**
 * Validate that a mode string is valid
 */
export function validateMode(mode: string): boolean {
  return VALID_MODES.includes(mode as ExecutionMode);
}

/**
 * Get requirements for a specific mode
 */
export function getModeRequirements(mode: ExecutionMode): ModeRequirements {
  switch (mode) {
  case 'scan':
    return { requiresIssue: false, requiresScanData: false, requiresValidation: false };

  case 'validate':
  case 'validate-only':
    return { requiresIssue: true, requiresScanData: false, requiresValidation: false };

  case 'mitigate':
  case 'fix-only':
    return { requiresIssue: true, requiresScanData: false, requiresValidation: true };

  case 'full':
    return { requiresIssue: false, requiresScanData: false, requiresValidation: false };

  case 'process':
    return { requiresIssue: false, requiresScanData: false, requiresValidation: false };

  default:
    throw new Error(`Unknown mode: ${mode}`);
  }
}

/**
 * Get a human-readable description of the mode
 */
export function getModeDescription(mode: ExecutionMode): string {
  switch (mode) {
  case 'scan':
    return 'Scan for vulnerabilities and create issues';
  case 'validate':
  case 'validate-only':
    return 'Validate vulnerabilities with failing tests';
  case 'mitigate':
  case 'fix-only':
    return 'Fix validated vulnerabilities';
  case 'full':
    return 'Run all phases: scan, validate, and mitigate';
  case 'process':
    return 'Process pending issues for a pipeline run (RFC-126)';
  default:
    return 'Unknown mode';
  }
}
