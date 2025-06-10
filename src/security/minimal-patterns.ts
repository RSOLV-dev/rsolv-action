import { SecurityPattern, VulnerabilityType } from './types.js';

/**
 * Minimal fallback patterns for when API is unavailable
 * These are basic, publicly known patterns that don't expose proprietary detection logic
 */
export const minimalFallbackPatterns: SecurityPattern[] = [
  // Basic SQL Injection
  {
    id: 'basic-sql-injection',
    name: 'Basic SQL Injection',
    type: VulnerabilityType.SQL_INJECTION,
    severity: 'high',
    description: 'Potential SQL injection via string concatenation',
    patterns: {
      regex: [
        /["'`].*?(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER).*?["'`]\s*\+/gi,
        /execute\s*\(\s*['"`].*\+/gi
      ]
    },
    languages: ['javascript', 'typescript'],
    frameworks: [],
    cweId: 'CWE-89',
    owaspCategory: 'A03:2021',
    remediation: 'Use parameterized queries or prepared statements',
    testCases: { vulnerable: [], safe: [] }
  },
  
  // Basic XSS
  {
    id: 'basic-xss',
    name: 'Basic Cross-Site Scripting',
    type: VulnerabilityType.XSS,
    severity: 'high',
    description: 'Potential XSS via innerHTML',
    patterns: {
      regex: [
        /innerHTML\s*=\s*[^'"`;]*(?:req\.|request\.)/gi,
        /document\.write\s*\(/gi
      ]
    },
    languages: ['javascript', 'typescript'],
    frameworks: [],
    cweId: 'CWE-79',
    owaspCategory: 'A03:2021',
    remediation: 'Use textContent or proper encoding',
    testCases: { vulnerable: [], safe: [] }
  },
  
  // Basic Command Injection
  {
    id: 'basic-command-injection',
    name: 'Basic Command Injection',
    type: VulnerabilityType.COMMAND_INJECTION,
    severity: 'critical',
    description: 'Potential command injection',
    patterns: {
      regex: [
        /exec\s*\(\s*['"`].*\+/gi,
        /system\s*\(\s*['"`].*\+/gi
      ]
    },
    languages: ['javascript', 'python', 'ruby'],
    frameworks: [],
    cweId: 'CWE-78',
    owaspCategory: 'A03:2021',
    remediation: 'Validate and sanitize all user input',
    testCases: { vulnerable: [], safe: [] }
  }
];

/**
 * Get minimal patterns for a specific language
 * This is intentionally limited to protect IP
 */
export function getMinimalPatternsByLanguage(language: string): SecurityPattern[] {
  const normalizedLang = language.toLowerCase();
  return minimalFallbackPatterns.filter(p => 
    p.languages.includes(normalizedLang) || 
    (normalizedLang === 'typescript' && p.languages.includes('javascript'))
  );
}