import { SecurityPattern, VulnerabilityType } from './types.js';

/**
 * Demo patterns for users without API key (~20 patterns)
 * These are basic, publicly known patterns that demonstrate RSOLV's capabilities
 * Full pattern library (172 patterns) available with API key
 */
export const minimalFallbackPatterns: SecurityPattern[] = [
  // JavaScript/TypeScript patterns
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
  },
  
  // Basic Path Traversal
  {
    id: 'basic-path-traversal',
    name: 'Basic Path Traversal',
    type: VulnerabilityType.PATH_TRAVERSAL,
    severity: 'high',
    description: 'Potential path traversal vulnerability',
    patterns: {
      regex: [
        /readFile\s*\([^)]*\.\.\/[^)]*\)/gi,
        /path\.join\s*\([^)]*req\./gi
      ]
    },
    languages: ['javascript', 'typescript'],
    frameworks: [],
    cweId: 'CWE-22',
    owaspCategory: 'A01:2021',
    remediation: 'Validate and sanitize file paths',
    testCases: { vulnerable: [], safe: [] }
  },
  
  // Python patterns
  {
    id: 'python-eval',
    name: 'Python Eval Usage',
    type: VulnerabilityType.RCE,
    severity: 'critical',
    description: 'Use of eval() with user input',
    patterns: {
      regex: [
        /eval\s*\(/gi,
        /exec\s*\(/gi
      ]
    },
    languages: ['python'],
    frameworks: [],
    cweId: 'CWE-94',
    owaspCategory: 'A03:2021',
    remediation: 'Avoid eval(), use ast.literal_eval() for safe evaluation',
    testCases: { vulnerable: [], safe: [] }
  },
  
  {
    id: 'python-pickle',
    name: 'Insecure Deserialization',
    type: VulnerabilityType.INSECURE_DESERIALIZATION,
    severity: 'high',
    description: 'Use of pickle with untrusted data',
    patterns: {
      regex: [
        /pickle\.loads?\s*\(/gi,
        /cPickle\.loads?\s*\(/gi
      ]
    },
    languages: ['python'],
    frameworks: [],
    cweId: 'CWE-502',
    owaspCategory: 'A08:2021',
    remediation: 'Use JSON or other safe serialization formats',
    testCases: { vulnerable: [], safe: [] }
  },
  
  // Ruby patterns
  {
    id: 'ruby-eval',
    name: 'Ruby Eval Usage',
    type: VulnerabilityType.RCE,
    severity: 'critical',
    description: 'Use of eval with user input',
    patterns: {
      regex: [
        /eval\s*\(/gi,
        /instance_eval\s*\(/gi
      ]
    },
    languages: ['ruby'],
    frameworks: [],
    cweId: 'CWE-94',
    owaspCategory: 'A03:2021',
    remediation: 'Avoid eval, use safe alternatives',
    testCases: { vulnerable: [], safe: [] }
  },
  
  {
    id: 'ruby-yaml',
    name: 'YAML Deserialization',
    type: VulnerabilityType.INSECURE_DESERIALIZATION,
    severity: 'high',
    description: 'Unsafe YAML loading',
    patterns: {
      regex: [
        /YAML\.load\s*\(/gi,
        /Psych\.load\s*\(/gi
      ]
    },
    languages: ['ruby'],
    frameworks: [],
    cweId: 'CWE-502',
    owaspCategory: 'A08:2021',
    remediation: 'Use YAML.safe_load instead',
    testCases: { vulnerable: [], safe: [] }
  },
  
  // Java patterns
  {
    id: 'java-sql-injection',
    name: 'Java SQL Injection',
    type: VulnerabilityType.SQL_INJECTION,
    severity: 'high',
    description: 'SQL injection via string concatenation',
    patterns: {
      regex: [
        /createStatement\s*\(\s*\).*executeQuery\s*\(/gi,
        /"SELECT.*"\s*\+/gi
      ]
    },
    languages: ['java'],
    frameworks: [],
    cweId: 'CWE-89',
    owaspCategory: 'A03:2021',
    remediation: 'Use PreparedStatement with parameters',
    testCases: { vulnerable: [], safe: [] }
  },
  
  {
    id: 'java-xxe',
    name: 'XML External Entity',
    type: VulnerabilityType.XXE,
    severity: 'high',
    description: 'XML parser vulnerable to XXE',
    patterns: {
      regex: [
        /DocumentBuilderFactory\.newInstance\s*\(\s*\)/gi,
        /SAXParserFactory\.newInstance\s*\(\s*\)/gi
      ]
    },
    languages: ['java'],
    frameworks: [],
    cweId: 'CWE-611',
    owaspCategory: 'A05:2021',
    remediation: 'Disable external entities and DTD processing',
    testCases: { vulnerable: [], safe: [] }
  },
  
  // PHP patterns
  {
    id: 'php-eval',
    name: 'PHP Eval Usage',
    type: VulnerabilityType.RCE,
    severity: 'critical',
    description: 'Use of eval() function',
    patterns: {
      regex: [
        /eval\s*\(/gi,
        /assert\s*\(/gi
      ]
    },
    languages: ['php'],
    frameworks: [],
    cweId: 'CWE-94',
    owaspCategory: 'A03:2021',
    remediation: 'Avoid eval(), use safe alternatives',
    testCases: { vulnerable: [], safe: [] }
  },
  
  {
    id: 'php-file-inclusion',
    name: 'File Inclusion',
    type: VulnerabilityType.PATH_TRAVERSAL,
    severity: 'high',
    description: 'Dynamic file inclusion',
    patterns: {
      regex: [
        /include\s*\(\s*\$_(?:GET|POST|REQUEST)/gi,
        /require\s*\(\s*\$_(?:GET|POST|REQUEST)/gi
      ]
    },
    languages: ['php'],
    frameworks: [],
    cweId: 'CWE-98',
    owaspCategory: 'A03:2021',
    remediation: 'Validate and whitelist file paths',
    testCases: { vulnerable: [], safe: [] }
  },
  
  // Elixir patterns
  {
    id: 'elixir-code-eval',
    name: 'Elixir Code Evaluation',
    type: VulnerabilityType.RCE,
    severity: 'critical',
    description: 'Dynamic code evaluation',
    patterns: {
      regex: [
        /Code\.eval_string\s*\(/gi,
        /Code\.eval_quoted\s*\(/gi
      ]
    },
    languages: ['elixir'],
    frameworks: [],
    cweId: 'CWE-94',
    owaspCategory: 'A03:2021',
    remediation: 'Avoid dynamic code evaluation',
    testCases: { vulnerable: [], safe: [] }
  },
  
  {
    id: 'elixir-atom-dos',
    name: 'Atom DoS',
    type: VulnerabilityType.DOS,
    severity: 'medium',
    description: 'Creating atoms from user input',
    patterns: {
      regex: [
        /String\.to_atom\s*\(/gi,
        /binary_to_atom\s*\(/gi
      ]
    },
    languages: ['elixir'],
    frameworks: [],
    cweId: 'CWE-400',
    owaspCategory: 'A06:2021',
    remediation: 'Use String.to_existing_atom instead',
    testCases: { vulnerable: [], safe: [] }
  },
  
  // Cross-language patterns
  {
    id: 'hardcoded-secret',
    name: 'Hardcoded Secret',
    type: VulnerabilityType.HARDCODED_SECRET,
    severity: 'high',
    description: 'Hardcoded password or API key',
    patterns: {
      regex: [
        /password\s*=\s*["'][^"']{8,}["']/gi,
        /api_key\s*=\s*["'][^"']{20,}["']/gi
      ]
    },
    languages: ['javascript', 'typescript', 'python', 'ruby', 'java', 'php', 'elixir'],
    frameworks: [],
    cweId: 'CWE-798',
    owaspCategory: 'A07:2021',
    remediation: 'Use environment variables or secure key management',
    testCases: { vulnerable: [], safe: [] }
  },
  
  {
    id: 'weak-crypto',
    name: 'Weak Cryptography',
    type: VulnerabilityType.WEAK_CRYPTO,
    severity: 'medium',
    description: 'Use of weak cryptographic algorithms',
    patterns: {
      regex: [
        /MD5\s*\(/gi,
        /SHA1\s*\(/gi
      ]
    },
    languages: ['javascript', 'typescript', 'python', 'ruby', 'java', 'php'],
    frameworks: [],
    cweId: 'CWE-327',
    owaspCategory: 'A02:2021',
    remediation: 'Use SHA-256 or stronger algorithms',
    testCases: { vulnerable: [], safe: [] }
  },
  
  {
    id: 'jwt-none-algorithm',
    name: 'JWT None Algorithm',
    type: VulnerabilityType.JWT,
    severity: 'critical',
    description: 'JWT allowing none algorithm',
    patterns: {
      regex: [
        /algorithm\s*:\s*["']none["']/gi,
        /verify\s*:\s*false/gi
      ]
    },
    languages: ['javascript', 'typescript', 'python', 'ruby'],
    frameworks: [],
    cweId: 'CWE-347',
    owaspCategory: 'A02:2021',
    remediation: 'Always verify JWT signatures',
    testCases: { vulnerable: [], safe: [] }
  },
  
  {
    id: 'open-redirect',
    name: 'Open Redirect',
    type: VulnerabilityType.OPEN_REDIRECT,
    severity: 'medium',
    description: 'Unvalidated redirect',
    patterns: {
      regex: [
        /redirect\s*\(\s*req\./gi,
        /location\.href\s*=\s*req\./gi
      ]
    },
    languages: ['javascript', 'typescript'],
    frameworks: [],
    cweId: 'CWE-601',
    owaspCategory: 'A03:2021',
    remediation: 'Validate redirect URLs against whitelist',
    testCases: { vulnerable: [], safe: [] }
  },
  
  {
    id: 'nosql-injection',
    name: 'NoSQL Injection',
    type: VulnerabilityType.NOSQL_INJECTION,
    severity: 'high',
    description: 'MongoDB injection vulnerability',
    patterns: {
      regex: [
        /\$where\s*:/gi,
        /find\s*\(\s*{[^}]*\$ne\s*:/gi
      ]
    },
    languages: ['javascript', 'typescript'],
    frameworks: [],
    cweId: 'CWE-943',
    owaspCategory: 'A03:2021',
    remediation: 'Sanitize user input and use parameterized queries',
    testCases: { vulnerable: [], safe: [] }
  },
  
  {
    id: 'log4j-jndi',
    name: 'Log4j JNDI Injection (CVE-2021-44228)',
    type: VulnerabilityType.CVE,
    severity: 'critical',
    description: 'Log4Shell vulnerability pattern',
    patterns: {
      regex: [
        /\$\{jndi:/gi,
        /logger\.(?:info|warn|error|debug)\s*\([^)]*\$\{/gi
      ]
    },
    languages: ['java'],
    frameworks: [],
    cweId: 'CWE-502',
    owaspCategory: 'A08:2021',
    remediation: 'Update Log4j to version 2.17.0 or later',
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