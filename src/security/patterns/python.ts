import { SecurityPattern, VulnerabilityType } from '../types.js';

/**
 * Python-specific security patterns for vulnerability detection
 */
export const pythonSecurityPatterns: SecurityPattern[] = [
  // SQL Injection patterns
  {
    id: 'python-sql-injection-format',
    type: VulnerabilityType.SQL_INJECTION,
    pattern: /execute\s*\(\s*["`'].*%s.*["`']\s*%\s*\w+/g,
    severity: 'high',
    message: 'SQL injection vulnerability: Using string formatting in SQL queries',
    remediation: 'Use parameterized queries with execute() method parameters',
    cwe: 'CWE-89',
    owasp: 'A03',
    language: 'python'
  },
  {
    id: 'python-sql-injection-fstring',
    type: VulnerabilityType.SQL_INJECTION,
    pattern: /execute\s*\(\s*f["'`].*\{.*\}.*["'`]/g,
    severity: 'high',
    message: 'SQL injection vulnerability: Using f-strings in SQL queries',
    remediation: 'Use parameterized queries instead of f-string formatting',
    cwe: 'CWE-89',
    owasp: 'A03',
    language: 'python'
  },
  {
    id: 'python-sql-injection-concat',
    type: VulnerabilityType.SQL_INJECTION,
    pattern: /execute\s*\(\s*["'`].*["'`]\s*\+\s*\w+/g,
    severity: 'high',
    message: 'SQL injection vulnerability: String concatenation in SQL queries',
    remediation: 'Use parameterized queries with execute() method parameters',
    cwe: 'CWE-89',
    owasp: 'A03',
    language: 'python'
  },

  // Command Injection patterns
  {
    id: 'python-command-injection-os-system',
    type: VulnerabilityType.COMMAND_INJECTION,
    pattern: /os\.system\s*\(\s*.*\+|os\.system\s*\(\s*f["'`].*\{/g,
    severity: 'critical',
    message: 'Command injection vulnerability: Unsanitized input in os.system()',
    remediation: 'Use subprocess.run() with shell=False and validate inputs',
    cwe: 'CWE-78',
    owasp: 'A03',
    language: 'python'
  },
  {
    id: 'python-command-injection-subprocess-shell',
    type: VulnerabilityType.COMMAND_INJECTION,
    pattern: /subprocess\.(run|call|check_call|Popen)\s*\([^)]*shell\s*=\s*True/g,
    severity: 'high',
    message: 'Command injection vulnerability: subprocess with shell=True',
    remediation: 'Use shell=False and pass command as list of arguments',
    cwe: 'CWE-78',
    owasp: 'A03',
    language: 'python'
  },

  // Deserialization vulnerabilities
  {
    id: 'python-unsafe-pickle',
    type: VulnerabilityType.INSECURE_DESERIALIZATION,
    pattern: /pickle\.(loads?|load)\s*\(/g,
    severity: 'critical',
    message: 'Insecure deserialization: pickle.loads() can execute arbitrary code',
    remediation: 'Use json.loads() or implement custom deserialization with validation',
    cwe: 'CWE-502',
    owasp: 'A08',
    language: 'python'
  },
  {
    id: 'python-unsafe-eval',
    type: VulnerabilityType.INSECURE_DESERIALIZATION,
    pattern: /\beval\s*\(/g,
    severity: 'critical',
    message: 'Code injection vulnerability: eval() can execute arbitrary code',
    remediation: 'Use ast.literal_eval() for safe evaluation of literals',
    cwe: 'CWE-95',
    owasp: 'A03',
    language: 'python'
  },

  // Path Traversal
  {
    id: 'python-path-traversal-open',
    type: VulnerabilityType.PATH_TRAVERSAL,
    pattern: /open\s*\(\s*.*\+|open\s*\(\s*f["'`].*\{/g,
    severity: 'medium',
    message: 'Path traversal vulnerability: Unsanitized file paths in open()',
    remediation: 'Validate and sanitize file paths, use os.path.join() safely',
    cwe: 'CWE-22',
    owasp: 'A01',
    language: 'python'
  },

  // Weak cryptography
  {
    id: 'python-weak-hash-md5',
    type: VulnerabilityType.WEAK_CRYPTOGRAPHY,
    pattern: /hashlib\.md5\s*\(/g,
    severity: 'medium',
    message: 'Weak cryptography: MD5 is cryptographically broken',
    remediation: 'Use SHA-256 or SHA-3 for cryptographic hashing',
    cwe: 'CWE-327',
    owasp: 'A02',
    language: 'python'
  },
  {
    id: 'python-weak-hash-sha1',
    type: VulnerabilityType.WEAK_CRYPTOGRAPHY,
    pattern: /hashlib\.sha1\s*\(/g,
    severity: 'medium',
    message: 'Weak cryptography: SHA-1 is deprecated for security purposes',
    remediation: 'Use SHA-256 or SHA-3 for cryptographic hashing',
    cwe: 'CWE-327',
    owasp: 'A02',
    language: 'python'
  },

  // Debug/Development issues
  {
    id: 'python-debug-true',
    type: VulnerabilityType.DEBUG_MODE,
    pattern: /DEBUG\s*=\s*True/g,
    severity: 'medium',
    message: 'Security misconfiguration: Debug mode enabled in production',
    remediation: 'Set DEBUG = False in production environments',
    cwe: 'CWE-489',
    owasp: 'A05',
    language: 'python'
  },

  // YAML deserialization
  {
    id: 'python-unsafe-yaml-load',
    type: VulnerabilityType.INSECURE_DESERIALIZATION,
    pattern: /yaml\.load\s*\([^)]*(?!Loader\s*=\s*yaml\.SafeLoader)/g,
    severity: 'critical',
    message: 'Insecure deserialization: yaml.load() without SafeLoader',
    remediation: 'Use yaml.safe_load() or yaml.load() with SafeLoader',
    cwe: 'CWE-502',
    owasp: 'A08',
    language: 'python'
  }
];