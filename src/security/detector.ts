import { Vulnerability, VulnerabilityType, SecurityScanResult } from './types.js';
import { PatternRegistry } from './patterns.js';

export class SecurityDetector {
  private registry: PatternRegistry;

  constructor() {
    this.registry = new PatternRegistry();
  }

  detect(code: string, language: string): Vulnerability[] {
    const vulnerabilities: Vulnerability[] = [];
    const lines = code.split('\n');
    const seen = new Set<string>(); // Track line + type combinations

    const patterns = this.registry.getPatternsByLanguage(language);

    for (const pattern of patterns) {
      if (pattern.patterns.regex) {
        for (const regex of pattern.patterns.regex) {
          let match;
          regex.lastIndex = 0; // Reset regex state
          
          while ((match = regex.exec(code)) !== null) {
            const lineNumber = this.getLineNumber(code, match.index);
            const line = lines[lineNumber - 1]?.trim() || '';
            
            // Skip if this looks like a safe usage
            if (this.registry.isSafeUsage(line, pattern.type)) {
              continue;
            }

            // Deduplicate by line + type
            const key = `${lineNumber}:${pattern.type}`;
            if (seen.has(key)) {
              continue;
            }
            seen.add(key);

            vulnerabilities.push({
              type: pattern.type,
              severity: pattern.severity,
              line: lineNumber,
              message: `${pattern.name}: ${pattern.description}`,
              description: pattern.description,
              confidence: this.getConfidence(line, pattern.type),
              cweId: pattern.cweId,
              owaspCategory: pattern.owaspCategory,
              remediation: pattern.remediation
            });
          }
        }
      }
    }

    return vulnerabilities;
  }

  private getLineNumber(code: string, index: number): number {
    return code.substring(0, index).split('\n').length;
  }

  private getConfidence(line: string, type: VulnerabilityType): number {
    // Basic confidence scoring based on pattern specificity
    switch (type) {
    case VulnerabilityType.SQL_INJECTION:
      if (line.includes('SELECT') || line.includes('INSERT')) return 90;
      return 75;
    case VulnerabilityType.XSS:
      if (line.includes('innerHTML')) return 85;
      return 70;
    default:
      return 60;
    }
  }

  createSummary(vulnerabilities: Vulnerability[]): SecurityScanResult {
    const summary = {
      total: vulnerabilities.length,
      byType: {} as Record<VulnerabilityType, number>,
      bySeverity: {} as Record<string, number>
    };

    for (const vuln of vulnerabilities) {
      summary.byType[vuln.type] = (summary.byType[vuln.type] || 0) + 1;
      summary.bySeverity[vuln.severity] = (summary.bySeverity[vuln.severity] || 0) + 1;
    }

    return {
      vulnerabilities,
      summary,
      metadata: {
        language: 'mixed',
        linesScanned: 0,
        scanDuration: 0,
        timestamp: new Date().toISOString()
      }
    };
  }
}