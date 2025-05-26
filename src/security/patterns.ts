import { SecurityPattern, VulnerabilityType } from './types.js';
import { pythonSecurityPatterns } from './patterns/python.js';
import { rubySecurityPatterns } from './patterns/ruby.js';
import { javaSecurityPatterns } from './patterns/java.js';
import { allJavaScriptPatterns } from './patterns/javascript.js';

export class PatternRegistry {
  private patterns: Map<VulnerabilityType, SecurityPattern[]> = new Map();

  constructor() {
    this.initializePatterns();
  }

  private initializePatterns(): void {
    // Initialize patterns map with empty arrays for each vulnerability type
    Object.values(VulnerabilityType).forEach(type => {
      this.patterns.set(type, []);
    });

    // Add JavaScript/TypeScript patterns
    this.addJavaScriptPatterns();

    // Add multi-language patterns
    this.addMultiLanguagePatterns();
  }

  private addJavaScriptPatterns(): void {
    // Add all enhanced JavaScript/TypeScript patterns
    for (const pattern of allJavaScriptPatterns) {
      const existingPatterns = this.patterns.get(pattern.type) || [];
      existingPatterns.push(pattern);
      this.patterns.set(pattern.type, existingPatterns);
    }
  }

  private addMultiLanguagePatterns(): void {
    // Add Python patterns
    for (const pattern of pythonSecurityPatterns) {
      const existingPatterns = this.patterns.get(pattern.type) || [];
      existingPatterns.push(this.convertToSecurityPattern(pattern));
      this.patterns.set(pattern.type, existingPatterns);
    }
    
    // Add Ruby patterns (enhanced version with full OWASP coverage)
    for (const pattern of rubySecurityPatterns) {
      const existingPatterns = this.patterns.get(pattern.type) || [];
      existingPatterns.push(pattern); // Already in correct format
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