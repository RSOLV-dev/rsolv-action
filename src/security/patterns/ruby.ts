import { SecurityPattern, VulnerabilityType } from '../types.js';

/**
 * Ruby-specific security patterns for vulnerability detection
 */
export const rubySecurityPatterns: SecurityPattern[] = [
  // SQL Injection patterns
  {
    id: 'ruby-sql-injection-string-interpolation',
    type: VulnerabilityType.SQL_INJECTION,
    pattern: /\.(find_by_sql|execute|exec_query)\s*\(\s*["'`].*#\{.*\}/g,
    severity: 'high',
    message: 'SQL injection vulnerability: String interpolation in SQL queries',
    remediation: 'Use parameterized queries with ? placeholders or ActiveRecord methods',
    cwe: 'CWE-89',
    owasp: 'A03',
    language: 'ruby'
  },
  {
    id: 'ruby-sql-injection-where-string',
    type: VulnerabilityType.SQL_INJECTION,
    pattern: /\.where\s*\(\s*["'`].*#\{.*\}/g,
    severity: 'high',
    message: 'SQL injection vulnerability: String interpolation in where clause',
    remediation: 'Use parameterized where clauses: where("name = ?", name)',
    cwe: 'CWE-89',
    owasp: 'A03',
    language: 'ruby'
  },

  // Command Injection patterns
  {
    id: 'ruby-command-injection-system',
    type: VulnerabilityType.COMMAND_INJECTION,
    pattern: /system\s*\(\s*["'`].*#\{.*\}/g,
    severity: 'critical',
    message: 'Command injection vulnerability: String interpolation in system()',
    remediation: 'Use system() with array of arguments or validate input',
    cwe: 'CWE-78',
    owasp: 'A03',
    language: 'ruby'
  },
  {
    id: 'ruby-command-injection-backticks',
    type: VulnerabilityType.COMMAND_INJECTION,
    pattern: /`.*#\{.*\}`/g,
    severity: 'critical',
    message: 'Command injection vulnerability: String interpolation in backticks',
    remediation: 'Use Open3.capture3() or system() with array arguments',
    cwe: 'CWE-78',
    owasp: 'A03',
    language: 'ruby'
  },
  {
    id: 'ruby-command-injection-exec',
    type: VulnerabilityType.COMMAND_INJECTION,
    pattern: /exec\s*\(\s*["'`].*#\{.*\}/g,
    severity: 'critical',
    message: 'Command injection vulnerability: String interpolation in exec()',
    remediation: 'Use exec() with array of arguments or validate input',
    cwe: 'CWE-78',
    owasp: 'A03',
    language: 'ruby'
  },

  // Deserialization vulnerabilities
  {
    id: 'ruby-unsafe-marshal-load',
    type: VulnerabilityType.INSECURE_DESERIALIZATION,
    pattern: /Marshal\.load/g,
    severity: 'critical',
    message: 'Insecure deserialization: Marshal.load can execute arbitrary code',
    remediation: 'Use JSON.parse or implement custom deserialization with validation',
    cwe: 'CWE-502',
    owasp: 'A08',
    language: 'ruby'
  },
  {
    id: 'ruby-unsafe-yaml-load',
    type: VulnerabilityType.INSECURE_DESERIALIZATION,
    pattern: /YAML\.load(?!_file|_stream)/g,
    severity: 'high',
    message: 'Insecure deserialization: YAML.load can execute arbitrary code',
    remediation: 'Use YAML.safe_load for untrusted input',
    cwe: 'CWE-502',
    owasp: 'A08',
    language: 'ruby'
  },
  {
    id: 'ruby-unsafe-eval',
    type: VulnerabilityType.INSECURE_DESERIALIZATION,
    pattern: /\beval\s*\(/g,
    severity: 'critical',
    message: 'Code injection vulnerability: eval() can execute arbitrary code',
    remediation: 'Avoid eval() or use safe evaluation libraries',
    cwe: 'CWE-95',
    owasp: 'A03',
    language: 'ruby'
  },

  // Path Traversal
  {
    id: 'ruby-path-traversal-file-read',
    type: VulnerabilityType.PATH_TRAVERSAL,
    pattern: /File\.(read|open)\s*\(\s*.*#\{.*\}/g,
    severity: 'medium',
    message: 'Path traversal vulnerability: Unsanitized file paths in File operations',
    remediation: 'Validate and sanitize file paths, use File.join() safely',
    cwe: 'CWE-22',
    owasp: 'A01',
    language: 'ruby'
  },

  // Rails-specific vulnerabilities
  {
    id: 'ruby-rails-mass-assignment',
    type: VulnerabilityType.MASS_ASSIGNMENT,
    pattern: /\.(create|update|update_attributes)\s*\(\s*params\[/g,
    severity: 'high',
    message: 'Mass assignment vulnerability: Unfiltered params in model operations',
    remediation: 'Use strong parameters with permit() to whitelist attributes',
    cwe: 'CWE-915',
    owasp: 'A04',
    language: 'ruby'
  },
  {
    id: 'ruby-rails-redirect-to-params',
    type: VulnerabilityType.OPEN_REDIRECT,
    pattern: /redirect_to\s+params\[/g,
    severity: 'medium',
    message: 'Open redirect vulnerability: Unvalidated redirect_to with params',
    remediation: 'Validate redirect URLs against whitelist of allowed domains',
    cwe: 'CWE-601',
    owasp: 'A01',
    language: 'ruby'
  },

  // XSS in ERB templates
  {
    id: 'ruby-erb-raw-output',
    type: VulnerabilityType.XSS,
    pattern: /<%=\s*raw\s+.*%>/g,
    severity: 'medium',
    message: 'XSS vulnerability: Using raw() in ERB templates',
    remediation: 'Use html_safe only for trusted content, or sanitize with sanitize()',
    cwe: 'CWE-79',
    owasp: 'A03',
    language: 'ruby'
  },
  {
    id: 'ruby-erb-html-safe',
    type: VulnerabilityType.XSS,
    pattern: /<%=.*\.html_safe\s*%>/g,
    severity: 'medium',
    message: 'Potential XSS vulnerability: html_safe in ERB template',
    remediation: 'Ensure content is properly escaped before using html_safe',
    cwe: 'CWE-79',
    owasp: 'A03',
    language: 'ruby'
  },

  // Weak cryptography
  {
    id: 'ruby-weak-hash-md5',
    type: VulnerabilityType.WEAK_CRYPTOGRAPHY,
    pattern: /Digest::MD5/g,
    severity: 'medium',
    message: 'Weak cryptography: MD5 is cryptographically broken',
    remediation: 'Use Digest::SHA256 or Digest::SHA3 for cryptographic hashing',
    cwe: 'CWE-327',
    owasp: 'A02',
    language: 'ruby'
  },
  {
    id: 'ruby-weak-hash-sha1',
    type: VulnerabilityType.WEAK_CRYPTOGRAPHY,
    pattern: /Digest::SHA1/g,
    severity: 'medium',
    message: 'Weak cryptography: SHA-1 is deprecated for security purposes',
    remediation: 'Use Digest::SHA256 or Digest::SHA3 for cryptographic hashing',
    cwe: 'CWE-327',
    owasp: 'A02',
    language: 'ruby'
  },

  // Hardcoded secrets
  {
    id: 'ruby-hardcoded-secret-key',
    type: VulnerabilityType.HARDCODED_SECRETS,
    pattern: /secret_key_base\s*=\s*["'`][a-f0-9]{64,}/g,
    severity: 'critical',
    message: 'Hardcoded secret: Rails secret_key_base in source code',
    remediation: 'Use environment variables or Rails credentials for secrets',
    cwe: 'CWE-798',
    owasp: 'A07',
    language: 'ruby'
  }
];