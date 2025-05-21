import { SecurityPattern, VulnerabilityType } from './types.js';

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
      default:
        return false;
    }
  }
}