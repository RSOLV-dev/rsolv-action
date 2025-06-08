import { Vulnerability, VulnerabilityType, SecurityScanResult } from './types.js';
import { TieredPatternSource, SecurityPattern, CustomerConfig, defaultPatternSource } from './tiered-pattern-source.js';
import { logger } from '../utils/logger.js';

export class SecurityDetector {
  private patternSource: TieredPatternSource;
  private customerConfig?: CustomerConfig;

  constructor(patternSource?: TieredPatternSource, customerConfig?: CustomerConfig) {
    this.patternSource = patternSource || defaultPatternSource;
    this.customerConfig = customerConfig;
  }

  async detect(code: string, language: string): Promise<Vulnerability[]> {
    const vulnerabilities: Vulnerability[] = [];
    const lines = code.split('\n');
    const seen = new Set<string>(); // Track line + type combinations

    try {
      const patterns = await this.patternSource.getPatternsByLanguage(language, this.customerConfig);

      for (const pattern of patterns) {
        if (pattern.patterns.regex) {
          for (const regexStr of pattern.patterns.regex) {
            try {
              const regex = new RegExp(regexStr, 'gi');
              let match;
              
              while ((match = regex.exec(code)) !== null) {
                const lineNumber = this.getLineNumber(code, match.index);
                const line = lines[lineNumber - 1]?.trim() || '';
                
                // Skip if this looks like a safe usage
                if (this.isSafeUsage(line, pattern.safeUsage)) {
                  continue;
                }

                // Deduplicate by line + type
                const key = `${lineNumber}:${pattern.type}`;
                if (seen.has(key)) {
                  continue;
                }
                seen.add(key);

                vulnerabilities.push({
                  type: pattern.type as VulnerabilityType,
                  severity: pattern.severity,
                  line: lineNumber,
                  message: `${pattern.name}: ${pattern.description}`,
                  description: pattern.description,
                  confidence: this.getConfidenceScore(line, pattern.type, pattern.confidence),
                  cweId: pattern.cweId || '',
                  owaspCategory: pattern.owaspCategory || '',
                  remediation: pattern.remediation
                });
              }
            } catch (regexError) {
              logger.warn(`Invalid regex pattern: ${regexStr}, skipping`);
            }
          }
        }
      }
    } catch (error) {
      logger.error(`Pattern detection failed: ${error}`);
    }

    return vulnerabilities;
  }

  private getLineNumber(code: string, index: number): number {
    return code.substring(0, index).split('\n').length;
  }

  private getConfidenceScore(line: string, type: string, patternConfidence: string): number {
    // Convert pattern confidence to numeric score
    let baseScore = 60;
    switch (patternConfidence) {
      case 'high': baseScore = 85; break;
      case 'medium': baseScore = 70; break;
      case 'low': baseScore = 50; break;
    }

    // Adjust based on line content specificity
    if (type.includes('sql') && (line.includes('SELECT') || line.includes('INSERT'))) {
      baseScore += 10;
    }
    if (type.includes('xss') && line.includes('innerHTML')) {
      baseScore += 10;
    }

    return Math.min(baseScore, 95);
  }

  private isSafeUsage(line: string, safeUsagePatterns: string[]): boolean {
    for (const safePattern of safeUsagePatterns) {
      try {
        const regex = new RegExp(safePattern, 'i');
        if (regex.test(line)) {
          return true;
        }
      } catch (error) {
        logger.warn(`Invalid safe usage pattern: ${safePattern}`);
      }
    }
    return false;
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