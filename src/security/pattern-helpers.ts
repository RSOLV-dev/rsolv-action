/**
 * Helper functions for creating security patterns
 * Promotes code reuse and consistency across pattern definitions
 */

import { SecurityPattern, VulnerabilityType } from './types.js';

/**
 * Common CWE IDs for vulnerability types
 */
export const CWE_IDS = {
  CODE_INJECTION: 'CWE-94',
  INSECURE_DESERIALIZATION: 'CWE-502',
  PROTOTYPE_POLLUTION: 'CWE-1321',
  COMMAND_INJECTION: 'CWE-78',
  SQL_INJECTION: 'CWE-89',
  XSS: 'CWE-79',
  PATH_TRAVERSAL: 'CWE-22',
  LOG_INJECTION: 'CWE-117',
  CRLF_INJECTION: 'CWE-93',
  NOSQL_INJECTION: 'CWE-943',
} as const;

/**
 * Common OWASP categories
 */
export const OWASP_CATEGORIES = {
  INJECTION: 'A03:2021',
  BROKEN_AUTH: 'A07:2021',
  INSECURE_DESIGN: 'A04:2021',
  VULNERABLE_COMPONENTS: 'A06:2021',
  SECURITY_MISCONFIGURATION: 'A05:2021',
  IDENTIFICATION_FAILURES: 'A07:2021',
  SOFTWARE_DATA_INTEGRITY: 'A08:2021',
  LOGGING_MONITORING: 'A09:2021',
  BROKEN_ACCESS_CONTROL: 'A01:2021',
} as const;

interface CodeInjectionPatternConfig {
  id: string;
  name: string;
  language: string;
  patterns: RegExp[];
  description?: string;
  remediation?: string;
}

/**
 * Create a code injection pattern (CWE-94)
 * Used for eval(), exec(), and similar code execution vulnerabilities
 */
export function createCodeInjectionPattern(
  config: CodeInjectionPatternConfig
): SecurityPattern {
  return {
    id: config.id,
    name: config.name,
    type: VulnerabilityType.CODE_INJECTION,
    severity: 'critical',
    description: config.description || `Use of eval() or dynamic code execution with user input`,
    patterns: {
      regex: config.patterns
    },
    languages: [config.language],
    cweId: CWE_IDS.CODE_INJECTION,
    owaspCategory: OWASP_CATEGORIES.INJECTION,
    remediation: config.remediation || 'Avoid eval(), use safe alternatives',
    examples: { vulnerable: '', secure: '' }
  };
}

interface DeserializationPatternConfig {
  id: string;
  name: string;
  language: string;
  patterns: RegExp[];
  description?: string;
  remediation?: string;
}

/**
 * Create an insecure deserialization pattern (CWE-502)
 * Used for pickle.loads(), Marshal.load(), unserialize(), etc.
 */
export function createDeserializationPattern(
  config: DeserializationPatternConfig
): SecurityPattern {
  return {
    id: config.id,
    name: config.name,
    type: VulnerabilityType.INSECURE_DESERIALIZATION,
    severity: 'high',
    description: config.description || 'Unsafe deserialization of untrusted data',
    patterns: {
      regex: config.patterns
    },
    languages: [config.language],
    cweId: CWE_IDS.INSECURE_DESERIALIZATION,
    owaspCategory: OWASP_CATEGORIES.SOFTWARE_DATA_INTEGRITY,
    remediation: config.remediation || 'Use safe serialization formats like JSON',
    examples: { vulnerable: '', secure: '' }
  };
}

interface PrototypePollutionPatternConfig {
  id: string;
  name: string;
  patterns: RegExp[];
  description?: string;
  remediation?: string;
}

/**
 * Create a prototype pollution pattern (CWE-1321)
 * Used for __proto__, constructor.prototype manipulation
 */
export function createPrototypePollutionPattern(
  config: PrototypePollutionPatternConfig
): SecurityPattern {
  return {
    id: config.id,
    name: config.name,
    type: VulnerabilityType.PROTOTYPE_POLLUTION,
    severity: 'high',
    description: config.description || 'Unsafe assignment to object properties that can pollute the prototype chain',
    patterns: {
      regex: config.patterns
    },
    languages: ['javascript', 'typescript'],
    cweId: CWE_IDS.PROTOTYPE_POLLUTION,
    owaspCategory: OWASP_CATEGORIES.SOFTWARE_DATA_INTEGRITY,
    remediation: config.remediation || 'Use Object.create(null), validate keys against whitelist, or use Map',
    examples: { vulnerable: '', secure: '' }
  };
}

/**
 * Type guard to check if a pattern is a code injection pattern
 */
export function isCodeInjectionPattern(pattern: SecurityPattern): boolean {
  return pattern.type === VulnerabilityType.CODE_INJECTION &&
         pattern.cweId === CWE_IDS.CODE_INJECTION;
}

/**
 * Type guard to check if a pattern is a prototype pollution pattern
 */
export function isPrototypePollutionPattern(pattern: SecurityPattern): boolean {
  return pattern.type === VulnerabilityType.PROTOTYPE_POLLUTION &&
         pattern.cweId === CWE_IDS.PROTOTYPE_POLLUTION;
}

/**
 * Type guard to check if a pattern is an insecure deserialization pattern
 */
export function isDeserializationPattern(pattern: SecurityPattern): boolean {
  return pattern.type === VulnerabilityType.INSECURE_DESERIALIZATION &&
         pattern.cweId === CWE_IDS.INSECURE_DESERIALIZATION;
}
