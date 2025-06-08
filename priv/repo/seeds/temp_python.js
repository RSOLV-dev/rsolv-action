
const VulnerabilityType = {
  SQL_INJECTION: 'sql_injection',
  XSS: 'xss',
  COMMAND_INJECTION: 'command_injection',
  PATH_TRAVERSAL: 'path_traversal',
  HARDCODED_SECRET: 'hardcoded_secret',
  WEAK_CRYPTO: 'weak_crypto',
  BROKEN_ACCESS_CONTROL: 'broken_access_control',
  SENSITIVE_DATA_EXPOSURE: 'sensitive_data_exposure',
  XML_EXTERNAL_ENTITIES: 'xxe',
  SECURITY_MISCONFIGURATION: 'security_misconfiguration',
  VULNERABLE_COMPONENTS: 'vulnerable_components',
  BROKEN_AUTHENTICATION: 'broken_authentication',
  INSECURE_DESERIALIZATION: 'insecure_deserialization',
  INSUFFICIENT_LOGGING: 'insufficient_logging',
  UNVALIDATED_REDIRECT: 'open_redirect',
  SSRF: 'ssrf',
  LDAP_INJECTION: 'ldap_injection',
  NOSQL_INJECTION: 'nosql_injection',
  CSRF: 'csrf',
  XXE: 'xxe',
  DESERIALIZATION: 'deserialization',
  RCE: 'rce',
  // Ruby/Rails specific
  MASS_ASSIGNMENT: 'mass_assignment',
  UNSAFE_REFLECTION: 'unsafe_reflection',
  DEBUG_MODE: 'debug_mode',
  WEAK_CRYPTOGRAPHY: 'weak_cryptography',
  // Django specific
  TEMPLATE_INJECTION: 'template_injection',
  ORM_INJECTION: 'orm_injection',
  MIDDLEWARE_BYPASS: 'middleware_bypass'
};
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.pythonSecurityPatterns = void 0;
const types_js_1 = {};
exports.pythonSecurityPatterns = [
    {
        id: 'python-sql-injection-format',
        type: types_js_1.VulnerabilityType.SQL_INJECTION,
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
        type: types_js_1.VulnerabilityType.SQL_INJECTION,
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
        type: types_js_1.VulnerabilityType.SQL_INJECTION,
        pattern: /execute\s*\(\s*["'`].*["'`]\s*\+\s*\w+/g,
        severity: 'high',
        message: 'SQL injection vulnerability: String concatenation in SQL queries',
        remediation: 'Use parameterized queries with execute() method parameters',
        cwe: 'CWE-89',
        owasp: 'A03',
        language: 'python'
    },
    {
        id: 'python-command-injection-os-system',
        type: types_js_1.VulnerabilityType.COMMAND_INJECTION,
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
        type: types_js_1.VulnerabilityType.COMMAND_INJECTION,
        pattern: /subprocess\.(run|call|check_call|Popen)\s*\([^)]*shell\s*=\s*True/g,
        severity: 'high',
        message: 'Command injection vulnerability: subprocess with shell=True',
        remediation: 'Use shell=False and pass command as list of arguments',
        cwe: 'CWE-78',
        owasp: 'A03',
        language: 'python'
    },
    {
        id: 'python-unsafe-pickle',
        type: types_js_1.VulnerabilityType.INSECURE_DESERIALIZATION,
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
        type: types_js_1.VulnerabilityType.INSECURE_DESERIALIZATION,
        pattern: /\beval\s*\(/g,
        severity: 'critical',
        message: 'Code injection vulnerability: eval() can execute arbitrary code',
        remediation: 'Use ast.literal_eval() for safe evaluation of literals',
        cwe: 'CWE-95',
        owasp: 'A03',
        language: 'python'
    },
    {
        id: 'python-path-traversal-open',
        type: types_js_1.VulnerabilityType.PATH_TRAVERSAL,
        pattern: /open\s*\(\s*.*\+|open\s*\(\s*f["'`].*\{/g,
        severity: 'medium',
        message: 'Path traversal vulnerability: Unsanitized file paths in open()',
        remediation: 'Validate and sanitize file paths, use os.path.join() safely',
        cwe: 'CWE-22',
        owasp: 'A01',
        language: 'python'
    },
    {
        id: 'python-weak-hash-md5',
        type: types_js_1.VulnerabilityType.WEAK_CRYPTOGRAPHY,
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
        type: types_js_1.VulnerabilityType.WEAK_CRYPTOGRAPHY,
        pattern: /hashlib\.sha1\s*\(/g,
        severity: 'medium',
        message: 'Weak cryptography: SHA-1 is deprecated for security purposes',
        remediation: 'Use SHA-256 or SHA-3 for cryptographic hashing',
        cwe: 'CWE-327',
        owasp: 'A02',
        language: 'python'
    },
    {
        id: 'python-debug-true',
        type: types_js_1.VulnerabilityType.DEBUG_MODE,
        pattern: /DEBUG\s*=\s*True/g,
        severity: 'medium',
        message: 'Security misconfiguration: Debug mode enabled in production',
        remediation: 'Set DEBUG = False in production environments',
        cwe: 'CWE-489',
        owasp: 'A05',
        language: 'python'
    },
    {
        id: 'python-unsafe-yaml-load',
        type: types_js_1.VulnerabilityType.INSECURE_DESERIALIZATION,
        pattern: /yaml\.load\s*\([^)]*(?!Loader\s*=\s*yaml\.SafeLoader)/g,
        severity: 'critical',
        message: 'Insecure deserialization: yaml.load() without SafeLoader',
        remediation: 'Use yaml.safe_load() or yaml.load() with SafeLoader',
        cwe: 'CWE-502',
        owasp: 'A08',
        language: 'python'
    }
];
