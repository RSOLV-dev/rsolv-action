import { SecurityPattern, VulnerabilityType } from './types.js';
import { pythonSecurityPatterns } from './patterns/python.js';
import { rubySecurityPatterns } from './patterns/ruby.js';
import { javaSecurityPatterns } from './patterns/java.js';

export class PatternRegistry {
  private patterns: Map<VulnerabilityType, SecurityPattern[]> = new Map();

  constructor() {
    this.initializePatterns();
  }

  private initializePatterns(): void {
    this.patterns.set(VulnerabilityType.SQL_INJECTION, [
      {
        id: 'sql-injection-concat',
        type: VulnerabilityType.SQL_INJECTION,
        name: 'SQL Injection via String Concatenation',
        description: 'Detects SQL injection vulnerabilities from string concatenation',
        patterns: {
          regex: [
            /["'`].*?(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER).*?["'`]\s*\+\s*\w+/gi,
            /query.*?=.*?["'`].*?(WHERE|SET|VALUES).*?["'`]\s*\+/gi
          ]
        },
        severity: 'high',
        cweId: 'CWE-89',
        owaspCategory: 'A03:2021 - Injection',
        languages: ['javascript', 'typescript'],
        remediation: 'Use parameterized queries or prepared statements',
        examples: {
          vulnerable: 'const query = "SELECT * FROM users WHERE id = " + userId;',
          secure: 'const query = "SELECT * FROM users WHERE id = ?"; db.query(query, [userId]);'
        }
      },
      {
        id: 'sql-injection-template',
        type: VulnerabilityType.SQL_INJECTION,
        name: 'SQL Injection via Template Literals',
        description: 'Detects SQL injection vulnerabilities from template literal interpolation',
        patterns: {
          regex: [
            /`.*?(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER).*?\$\{[^}]+\}.*?`/gi
          ]
        },
        severity: 'high',
        cweId: 'CWE-89',
        owaspCategory: 'A03:2021 - Injection',
        languages: ['javascript', 'typescript'],
        remediation: 'Use parameterized queries instead of template literals for SQL',
        examples: {
          vulnerable: 'const query = `SELECT * FROM users WHERE name = \'${userName}\';',
          secure: 'const query = "SELECT * FROM users WHERE name = ?"; db.query(query, [userName]);'
        }
      }
    ]);

    this.patterns.set(VulnerabilityType.XSS, [
      {
        id: 'xss-inner-html',
        type: VulnerabilityType.XSS,
        name: 'XSS via innerHTML Assignment',
        description: 'Detects XSS vulnerabilities from innerHTML assignments',
        patterns: {
          regex: [
            /\.innerHTML\s*=\s*[^;]+(?!\.replace|\.escape|\.sanitize)/gi
          ]
        },
        severity: 'high',
        cweId: 'CWE-79',
        owaspCategory: 'A03:2021 - Injection',
        languages: ['javascript', 'typescript'],
        remediation: 'Use textContent or sanitize input before setting innerHTML',
        examples: {
          vulnerable: 'element.innerHTML = userInput;',
          secure: 'element.textContent = userInput; // or use DOMPurify.sanitize(userInput)'
        }
      },
      {
        id: 'xss-document-write',
        type: VulnerabilityType.XSS,
        name: 'XSS via document.write',
        description: 'Detects XSS vulnerabilities from document.write calls',
        patterns: {
          regex: [
            /document\.write\s*\([^)]*\w+[^)]*\)/gi,
            /\$\([^)]+\)\.html\s*\([^)]*\w+[^)]*\)/gi
          ]
        },
        severity: 'high',
        cweId: 'CWE-79',
        owaspCategory: 'A03:2021 - Injection',
        languages: ['javascript', 'typescript'],
        remediation: 'Avoid document.write and use safe DOM manipulation methods',
        examples: {
          vulnerable: 'document.write(userContent);',
          secure: 'const div = document.createElement("div"); div.textContent = userContent;'
        }
      }
    ]);

    // A01:2021 - Broken Access Control
    this.patterns.set(VulnerabilityType.BROKEN_ACCESS_CONTROL, [
      {
        id: 'broken-access-control-no-auth',
        type: VulnerabilityType.BROKEN_ACCESS_CONTROL,
        name: 'Missing Authentication Check',
        description: 'Detects endpoints without proper authentication checks',
        patterns: {
          regex: [
            /app\.(get|post|put|delete|patch)\s*\([^,]+,\s*(?!.*auth|.*login|.*verify|.*token)[^)]*\)/gi,
            /router\.(get|post|put|delete|patch)\s*\([^,]+,\s*(?!.*auth|.*login|.*verify|.*token)[^)]*\)/gi
          ]
        },
        severity: 'high',
        cweId: 'CWE-862',
        owaspCategory: 'A01:2021 - Broken Access Control',
        languages: ['javascript', 'typescript'],
        remediation: 'Add proper authentication middleware to protect endpoints',
        examples: {
          vulnerable: 'app.get("/admin/users", (req, res) => { /* handler */ });',
          secure: 'app.get("/admin/users", authenticateUser, (req, res) => { /* handler */ });'
        }
      }
    ]);

    // A02:2021 - Cryptographic Failures 
    this.patterns.set(VulnerabilityType.SENSITIVE_DATA_EXPOSURE, [
      {
        id: 'sensitive-data-plain-text',
        type: VulnerabilityType.SENSITIVE_DATA_EXPOSURE,
        name: 'Plain Text Sensitive Data',
        description: 'Detects storage of sensitive data in plain text',
        patterns: {
          regex: [
            /(password|secret|key|token)\s*[:=]\s*["'][^"']*["']/gi,
            /console\.log\([^)]*(?:password|secret|key|token|ssn|credit)/gi
          ]
        },
        severity: 'high',
        cweId: 'CWE-312',
        owaspCategory: 'A02:2021 - Cryptographic Failures',
        languages: ['javascript', 'typescript'],
        remediation: 'Encrypt sensitive data and avoid logging sensitive information',
        examples: {
          vulnerable: 'const password = "plaintext123";',
          secure: 'const password = await bcrypt.hash(plaintext, 10);'
        }
      }
    ]);

    // A04:2021 - Insecure Design (XML External Entities)
    this.patterns.set(VulnerabilityType.XML_EXTERNAL_ENTITIES, [
      {
        id: 'xxe-xml-parser',
        type: VulnerabilityType.XML_EXTERNAL_ENTITIES,
        name: 'XML External Entity Processing',
        description: 'Detects XML parsers that may process external entities',
        patterns: {
          regex: [
            /new\s+DOMParser\(\)/gi,
            /xml2js\.parseString/gi,
            /libxmljs\.parseXml/gi
          ]
        },
        severity: 'medium',
        cweId: 'CWE-611',
        owaspCategory: 'A04:2021 - Insecure Design',
        languages: ['javascript', 'typescript'],
        remediation: 'Disable XML external entity processing in parsers',
        examples: {
          vulnerable: 'const doc = new DOMParser().parseFromString(xmlData, "text/xml");',
          secure: 'const parser = new DOMParser(); parser.parseFromString(xmlData, "text/xml"); // with XXE disabled'
        }
      }
    ]);

    // A05:2021 - Security Misconfiguration
    this.patterns.set(VulnerabilityType.SECURITY_MISCONFIGURATION, [
      {
        id: 'security-misconfiguration-cors',
        type: VulnerabilityType.SECURITY_MISCONFIGURATION,
        name: 'Overly Permissive CORS',
        description: 'Detects CORS configurations that allow all origins',
        patterns: {
          regex: [
            /Access-Control-Allow-Origin.*\*|cors\(\)\.allowAll/gi,
            /cors\(\s*\{\s*origin:\s*true/gi
          ]
        },
        severity: 'medium',
        cweId: 'CWE-346',
        owaspCategory: 'A05:2021 - Security Misconfiguration',
        languages: ['javascript', 'typescript'],
        remediation: 'Configure CORS to allow only specific trusted origins',
        examples: {
          vulnerable: 'app.use(cors());',
          secure: 'app.use(cors({ origin: "https://trusted-domain.com" }));'
        }
      }
    ]);

    // A06:2021 - Vulnerable and Outdated Components
    this.patterns.set(VulnerabilityType.VULNERABLE_COMPONENTS, [
      {
        id: 'vulnerable-components-eval',
        type: VulnerabilityType.VULNERABLE_COMPONENTS,
        name: 'Use of Dangerous Functions',
        description: 'Detects use of dangerous functions like eval()',
        patterns: {
          regex: [
            /\beval\s*\(/gi,
            /new\s+Function\s*\(/gi,
            /setTimeout\s*\(\s*["'][^"']*["']/gi
          ]
        },
        severity: 'high',
        cweId: 'CWE-78',
        owaspCategory: 'A06:2021 - Vulnerable and Outdated Components',
        languages: ['javascript', 'typescript'],
        remediation: 'Avoid using eval() and similar dangerous functions',
        examples: {
          vulnerable: 'eval(userInput);',
          secure: 'JSON.parse(userInput); // Use safe parsing instead'
        }
      }
    ]);

    // A07:2021 - Identification and Authentication Failures
    this.patterns.set(VulnerabilityType.BROKEN_AUTHENTICATION, [
      {
        id: 'broken-authentication-weak-session',
        type: VulnerabilityType.BROKEN_AUTHENTICATION,
        name: 'Weak Session Management',
        description: 'Detects weak session management practices',
        patterns: {
          regex: [
            /session\s*\.\s*cookie\s*\.\s*secure\s*=\s*false/gi,
            /session\s*\.\s*cookie\s*\.\s*httpOnly\s*=\s*false/gi
          ]
        },
        severity: 'medium',
        cweId: 'CWE-384',
        owaspCategory: 'A07:2021 - Identification and Authentication Failures',
        languages: ['javascript', 'typescript'],
        remediation: 'Use secure session configuration with httpOnly and secure flags',
        examples: {
          vulnerable: 'session.cookie.secure = false;',
          secure: 'session.cookie.secure = true; session.cookie.httpOnly = true;'
        }
      }
    ]);

    // A08:2021 - Software and Data Integrity Failures (Insecure Deserialization)
    this.patterns.set(VulnerabilityType.INSECURE_DESERIALIZATION, [
      {
        id: 'insecure-deserialization-untrusted',
        type: VulnerabilityType.INSECURE_DESERIALIZATION,
        name: 'Untrusted Deserialization',
        description: 'Detects deserialization of untrusted data',
        patterns: {
          regex: [
            /JSON\.parse\s*\(\s*(?!.*validate|.*sanitize)[^)]*req\./gi,
            /serialize\.unserialize\s*\(/gi,
            /pickle\.loads\s*\(/gi
          ]
        },
        severity: 'high',
        cweId: 'CWE-502',
        owaspCategory: 'A08:2021 - Software and Data Integrity Failures',
        languages: ['javascript', 'typescript'],
        remediation: 'Validate and sanitize data before deserialization',
        examples: {
          vulnerable: 'const data = JSON.parse(req.body);',
          secure: 'const data = JSON.parse(validateInput(req.body));'
        }
      }
    ]);

    // A09:2021 - Security Logging and Monitoring Failures
    this.patterns.set(VulnerabilityType.INSUFFICIENT_LOGGING, [
      {
        id: 'insufficient-logging-missing-security',
        type: VulnerabilityType.INSUFFICIENT_LOGGING,
        name: 'Missing Security Event Logging',
        description: 'Detects missing logging for security-relevant events',
        patterns: {
          regex: [
            /catch\s*\([^)]*\)\s*\{\s*\}/gi,
            /\.catch\s*\(\s*\)\s*;/gi
          ]
        },
        severity: 'low',
        cweId: 'CWE-778',
        owaspCategory: 'A09:2021 - Security Logging and Monitoring Failures',
        languages: ['javascript', 'typescript'],
        remediation: 'Add comprehensive logging for security events and errors',
        examples: {
          vulnerable: 'try { riskyOperation(); } catch (e) { }',
          secure: 'try { riskyOperation(); } catch (e) { logger.error("Security event", e); }'
        }
      }
    ]);

    // Add multi-language patterns
    this.addMultiLanguagePatterns();
  }

  private addMultiLanguagePatterns(): void {
    // Add Python patterns
    for (const pattern of pythonSecurityPatterns) {
      const existingPatterns = this.patterns.get(pattern.type) || [];
      existingPatterns.push(this.convertToSecurityPattern(pattern));
      this.patterns.set(pattern.type, existingPatterns);
    }

    // Add Ruby patterns  
    for (const pattern of rubySecurityPatterns) {
      const existingPatterns = this.patterns.get(pattern.type) || [];
      existingPatterns.push(this.convertToSecurityPattern(pattern));
      this.patterns.set(pattern.type, existingPatterns);
    }

    // Add Java patterns
    for (const pattern of javaSecurityPatterns) {
      const existingPatterns = this.patterns.get(pattern.type) || [];
      existingPatterns.push(this.convertToSecurityPattern(pattern));
      this.patterns.set(pattern.type, existingPatterns);
    }
  }

  private convertToSecurityPattern(pattern: any): SecurityPattern {
    return {
      id: pattern.id,
      type: pattern.type,
      name: pattern.message,
      description: pattern.message,
      patterns: {
        regex: [pattern.pattern]
      },
      severity: pattern.severity,
      cweId: pattern.cwe,
      owaspCategory: pattern.owasp,
      languages: [pattern.language],
      remediation: pattern.remediation,
      examples: {
        vulnerable: 'See pattern documentation',
        secure: pattern.remediation
      }
    };
  }

  getPatterns(type: VulnerabilityType): SecurityPattern[] {
    return this.patterns.get(type) || [];
  }

  getAllPatterns(): SecurityPattern[] {
    const allPatterns: SecurityPattern[] = [];
    for (const patterns of this.patterns.values()) {
      allPatterns.push(...patterns);
    }
    return allPatterns;
  }

  getPatternsByLanguage(language: string): SecurityPattern[] {
    return this.getAllPatterns().filter(pattern => 
      pattern.languages.includes(language)
    );
  }

  isSafeUsage(line: string, type: VulnerabilityType): boolean {
    switch (type) {
      case VulnerabilityType.SQL_INJECTION:
        return /\?\s*["'`,\];]|prepare|bind|param/i.test(line);
      case VulnerabilityType.XSS:
        return /textContent|innerText|\.text\(/.test(line);
      case VulnerabilityType.BROKEN_ACCESS_CONTROL:
        return /auth|login|verify|token|middleware/i.test(line);
      case VulnerabilityType.SENSITIVE_DATA_EXPOSURE:
        return /encrypt|hash|bcrypt|crypto|validate/i.test(line);
      case VulnerabilityType.XML_EXTERNAL_ENTITIES:
        return /disableExternalEntities|noResolve|safe/i.test(line);
      case VulnerabilityType.SECURITY_MISCONFIGURATION:
        return /origin:\s*["'][^*"']/i.test(line);
      case VulnerabilityType.VULNERABLE_COMPONENTS:
        return /JSON\.parse|safe|validate/i.test(line);
      case VulnerabilityType.BROKEN_AUTHENTICATION:
        return /secure:\s*true|httpOnly:\s*true/i.test(line);
      case VulnerabilityType.INSECURE_DESERIALIZATION:
        return /validate|sanitize|schema/i.test(line);
      case VulnerabilityType.INSUFFICIENT_LOGGING:
        return /log|error|warn|info|debug/i.test(line);
      default:
        return false;
    }
  }
}