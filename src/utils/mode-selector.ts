/**
 * Mode selection utilities for three-phase architecture
 * Implements RFC-041 mode selection decisions
 */

export type ExecutionMode = 'scan' | 'validate' | 'mitigate' | 'fix' | 'full';

const VALID_MODES: ExecutionMode[] = ['scan', 'validate', 'mitigate', 'fix', 'full'];

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
 * 4. Default to 'fix' mode
 */
export function getExecutionMode(): ExecutionMode {
  // 1. Check CLI args first
  const cliMode = getModeFromArgs();
  if (cliMode && validateMode(cliMode)) {
    return cliMode as ExecutionMode;
  }
  
  // 2. Check RSOLV_MODE env var
  const envMode = process.env.RSOLV_MODE;
  if (envMode && validateMode(envMode)) {
    return envMode as ExecutionMode;
  }
  
  // 3. Check legacy RSOLV_SCAN_MODE for backward compatibility
  const legacyMode = process.env.RSOLV_SCAN_MODE;
  if (legacyMode === 'scan') {
    return 'scan';
  }
  
  // 4. Default to 'fix' mode for backward compatibility
  return 'fix';
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
      return {
        requiresIssue: false,
        requiresScanData: false,
        requiresValidation: false
      };
    
    case 'validate':
      return {
        requiresIssue: true, // Or scan data
        requiresScanData: false, // Either/or with issue
        requiresValidation: false
      };
    
    case 'mitigate':
      return {
        requiresIssue: true,
        requiresScanData: false,
        requiresValidation: true
      };
    
    case 'fix':
      return {
        requiresIssue: true,
        requiresScanData: false,
        requiresValidation: false // Fix mode does its own validation
      };
    
    case 'full':
      return {
        requiresIssue: false, // Full mode does everything
        requiresScanData: false,
        requiresValidation: false
      };
    
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
      return 'Validate vulnerabilities with failing tests';
    case 'mitigate':
      return 'Fix validated vulnerabilities';
    case 'fix':
      return 'Process existing issues (legacy mode)';
    case 'full':
      return 'Run all phases: scan, validate, and mitigate';
    default:
      return 'Unknown mode';
  }
}