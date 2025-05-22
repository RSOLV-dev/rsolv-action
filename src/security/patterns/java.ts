import { SecurityPattern, VulnerabilityType } from '../types.js';

/**
 * Java-specific security patterns for vulnerability detection
 */
export const javaSecurityPatterns: SecurityPattern[] = [
  // SQL Injection patterns
  {
    id: 'java-sql-injection-statement',
    type: VulnerabilityType.SQL_INJECTION,
    pattern: /Statement\s+\w+\s*=.*\.createStatement\(\)[\s\S]*?\.executeQuery\s*\(\s*.*\+/g,
    severity: 'high',
    message: 'SQL injection vulnerability: String concatenation in executeQuery()',
    remediation: 'Use PreparedStatement with parameterized queries',
    cwe: 'CWE-89',
    owasp: 'A03',
    language: 'java'
  },
  {
    id: 'java-sql-injection-string-format',
    type: VulnerabilityType.SQL_INJECTION,
    pattern: /executeQuery\s*\(\s*String\.format\s*\(/g,
    severity: 'high',
    message: 'SQL injection vulnerability: String.format() in SQL queries',
    remediation: 'Use PreparedStatement with setString(), setInt(), etc.',
    cwe: 'CWE-89',
    owasp: 'A03',
    language: 'java'
  },

  // Deserialization vulnerabilities
  {
    id: 'java-unsafe-deserialization',
    type: VulnerabilityType.INSECURE_DESERIALIZATION,
    pattern: /ObjectInputStream.*\.readObject\s*\(\)/g,
    severity: 'critical',
    message: 'Insecure deserialization: ObjectInputStream.readObject() can execute arbitrary code',
    remediation: 'Implement custom readObject() with validation or use safe serialization libraries',
    cwe: 'CWE-502',
    owasp: 'A08',
    language: 'java'
  },
  {
    id: 'java-xpath-injection',
    type: VulnerabilityType.XPATH_INJECTION,
    pattern: /XPath.*\.compile\s*\(\s*.*\+|XPath.*\.evaluate\s*\(\s*.*\+/g,
    severity: 'high',
    message: 'XPath injection vulnerability: String concatenation in XPath expressions',
    remediation: 'Use parameterized XPath expressions or validate input',
    cwe: 'CWE-643',
    owasp: 'A03',
    language: 'java'
  },

  // Command Injection patterns
  {
    id: 'java-command-injection-runtime-exec',
    type: VulnerabilityType.COMMAND_INJECTION,
    pattern: /Runtime\.getRuntime\(\)\.exec\s*\(\s*.*\+/g,
    severity: 'critical',
    message: 'Command injection vulnerability: String concatenation in Runtime.exec()',
    remediation: 'Use ProcessBuilder with array of arguments and validate input',
    cwe: 'CWE-78',
    owasp: 'A03',
    language: 'java'
  },
  {
    id: 'java-command-injection-processbuilder',
    type: VulnerabilityType.COMMAND_INJECTION,
    pattern: /ProcessBuilder.*\.command\s*\(\s*.*\+/g,
    severity: 'high',
    message: 'Command injection vulnerability: String concatenation in ProcessBuilder.command()',
    remediation: 'Use ProcessBuilder with separate arguments and validate input',
    cwe: 'CWE-78',
    owasp: 'A03',
    language: 'java'
  },

  // Path Traversal
  {
    id: 'java-path-traversal-file',
    type: VulnerabilityType.PATH_TRAVERSAL,
    pattern: /new\s+File\s*\(\s*.*\+/g,
    severity: 'medium',
    message: 'Path traversal vulnerability: Unsanitized file paths in File constructor',
    remediation: 'Validate and sanitize file paths, use Paths.get() with validation',
    cwe: 'CWE-22',
    owasp: 'A01',
    language: 'java'
  },
  {
    id: 'java-path-traversal-fileinputstream',
    type: VulnerabilityType.PATH_TRAVERSAL,
    pattern: /new\s+FileInputStream\s*\(\s*.*\+/g,
    severity: 'medium',
    message: 'Path traversal vulnerability: Unsanitized file paths in FileInputStream',
    remediation: 'Validate file paths and use Files.newInputStream() with proper validation',
    cwe: 'CWE-22',
    owasp: 'A01',
    language: 'java'
  },

  // Weak cryptography
  {
    id: 'java-weak-hash-md5',
    type: VulnerabilityType.WEAK_CRYPTOGRAPHY,
    pattern: /MessageDigest\.getInstance\s*\(\s*["']MD5["']\s*\)/g,
    severity: 'medium',
    message: 'Weak cryptography: MD5 is cryptographically broken',
    remediation: 'Use SHA-256 or SHA-3 for cryptographic hashing',
    cwe: 'CWE-327',
    owasp: 'A02',
    language: 'java'
  },
  {
    id: 'java-weak-hash-sha1',
    type: VulnerabilityType.WEAK_CRYPTOGRAPHY,
    pattern: /MessageDigest\.getInstance\s*\(\s*["']SHA-1["']\s*\)/g,
    severity: 'medium',
    message: 'Weak cryptography: SHA-1 is deprecated for security purposes',
    remediation: 'Use SHA-256 or SHA-3 for cryptographic hashing',
    cwe: 'CWE-327',
    owasp: 'A02',
    language: 'java'
  },
  {
    id: 'java-weak-cipher-des',
    type: VulnerabilityType.WEAK_CRYPTOGRAPHY,
    pattern: /Cipher\.getInstance\s*\(\s*["']DES/g,
    severity: 'high',
    message: 'Weak cryptography: DES encryption is insecure',
    remediation: 'Use AES with appropriate key sizes (AES-256)',
    cwe: 'CWE-327',
    owasp: 'A02',
    language: 'java'
  },

  // XXE vulnerabilities
  {
    id: 'java-xxe-documentbuilder',
    type: VulnerabilityType.XML_EXTERNAL_ENTITIES,
    pattern: /DocumentBuilderFactory.*\.newDocumentBuilder\(\)(?![\s\S]*setFeature.*XMLConstants\.FEATURE_SECURE_PROCESSING)/g,
    severity: 'high',
    message: 'XXE vulnerability: DocumentBuilder without secure processing',
    remediation: 'Enable secure processing and disable external entity processing',
    cwe: 'CWE-611',
    owasp: 'A05',
    language: 'java'
  },
  {
    id: 'java-xxe-saxparser',
    type: VulnerabilityType.XML_EXTERNAL_ENTITIES,
    pattern: /SAXParserFactory.*\.newSAXParser\(\)(?![\s\S]*setFeature.*XMLConstants\.FEATURE_SECURE_PROCESSING)/g,
    severity: 'high',
    message: 'XXE vulnerability: SAXParser without secure processing',
    remediation: 'Enable secure processing and disable external entity processing',
    cwe: 'CWE-611',
    owasp: 'A05',
    language: 'java'
  },

  // LDAP Injection
  {
    id: 'java-ldap-injection',
    type: VulnerabilityType.LDAP_INJECTION,
    pattern: /\.search\s*\(\s*.*\+.*,/g,
    severity: 'high',
    message: 'LDAP injection vulnerability: String concatenation in LDAP search',
    remediation: 'Use parameterized LDAP queries and validate input',
    cwe: 'CWE-90',
    owasp: 'A03',
    language: 'java'
  },

  // Hardcoded credentials
  {
    id: 'java-hardcoded-password',
    type: VulnerabilityType.HARDCODED_SECRETS,
    pattern: /(?:password|pwd|passwd)\s*=\s*["'][^"']{6,}["']/gi,
    severity: 'high',
    message: 'Hardcoded credentials: Password in source code',
    remediation: 'Use environment variables or secure configuration management',
    cwe: 'CWE-798',
    owasp: 'A07',
    language: 'java'
  },

  // Insecure random
  {
    id: 'java-weak-random',
    type: VulnerabilityType.WEAK_CRYPTOGRAPHY,
    pattern: /new\s+Random\s*\(\)|Math\.random\s*\(\)/g,
    severity: 'medium',
    message: 'Weak randomness: java.util.Random is not cryptographically secure',
    remediation: 'Use SecureRandom for security-sensitive random values',
    cwe: 'CWE-338',
    owasp: 'A02',
    language: 'java'
  },

  // SSL/TLS issues
  {
    id: 'java-trust-all-certs',
    type: VulnerabilityType.INSECURE_TRANSPORT,
    pattern: /TrustManager.*\{\s*public\s+void\s+checkClientTrusted.*\{\s*\}/g,
    severity: 'critical',
    message: 'Insecure transport: TrustManager that accepts all certificates',
    remediation: 'Implement proper certificate validation',
    cwe: 'CWE-295',
    owasp: 'A07',
    language: 'java'
  }
];