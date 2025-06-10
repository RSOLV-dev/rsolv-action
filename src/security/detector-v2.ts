import { Vulnerability, VulnerabilityType, SecurityScanResult } from './types.js';
import { PatternSource, createPatternSource } from './pattern-source.js';
import { logger } from '../utils/logger.js';

/**
 * Enhanced SecurityDetector that uses PatternSource for dynamic pattern loading
 * Implements RFC-008 pattern serving architecture
 */
export class SecurityDetectorV2 {
  private patternSource: PatternSource;
  private cachedPatterns: Map<string, any[]> = new Map();

  constructor(patternSource?: PatternSource) {
    this.patternSource = patternSource || createPatternSource();
  }

  async detect(code: string, language: string): Promise<Vulnerability[]> {
    const vulnerabilities: Vulnerability[] = [];
    const lines = code.split('\n');
    const seen = new Set<string>(); // Track line + type combinations

    try {
      // Get patterns from source (API or local)
      const patterns = await this.patternSource.getPatternsByLanguage(language);
      logger.info(`SecurityDetectorV2: Analyzing ${language} code with ${patterns.length} patterns`);

      for (const pattern of patterns) {
        if (pattern.patterns.regex) {
          for (const regex of pattern.patterns.regex) {
            let match;
            regex.lastIndex = 0; // Reset regex state
            
            while ((match = regex.exec(code)) !== null) {
              const lineNumber = this.getLineNumber(code, match.index);
              const line = lines[lineNumber - 1]?.trim() || '';
              
              // Skip if this looks like a safe usage
              if (this.isSafeUsage(line, pattern.type)) {
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

              // Exit after first match for non-global regex
              if (!regex.global) {
                break;
              }
            }
          }
        }
      }
    } catch (error) {
      logger.error('Error detecting vulnerabilities:', error);
      // In case of error, return empty array rather than throwing
      // This allows the analysis to continue with other checks
    }

    return vulnerabilities;
  }

  async scanDirectory(directory: string): Promise<SecurityScanResult> {
    logger.info(`SecurityDetectorV2: Starting directory scan of ${directory}`);
    const results: SecurityScanResult = {
      vulnerabilities: [],
      fileCount: 0,
      totalIssues: 0,
      criticalCount: 0,
      highCount: 0,
      mediumCount: 0,
      lowCount: 0,
      byType: new Map(),
      byFile: new Map()
    };

    // TODO: Implement directory scanning logic
    // This would use file system APIs to scan the directory
    // and call detect() on each file

    return results;
  }

  private getLineNumber(code: string, index: number): number {
    return code.substring(0, index).split('\n').length;
  }

  private isSafeUsage(line: string, type: VulnerabilityType): boolean {
    // Common safe patterns to reduce false positives
    const safePatterns: Record<string, RegExp[]> = {
      [VulnerabilityType.SQL_INJECTION]: [
        /\?.+\?/,  // Parameterized query
        /\$\d+/,   // Positional parameters
        /:\w+/,    // Named parameters
        /prepare\s*\(/i,
        /setParameter/i,
        /bindParam/i
      ],
      [VulnerabilityType.XSS]: [
        /escape/i,
        /sanitize/i,
        /encode/i,
        /textContent/,
        /innerText/,
        /createTextNode/
      ],
      [VulnerabilityType.COMMAND_INJECTION]: [
        /escapeshellarg/i,
        /escapeshellcmd/i,
        /quote/i
      ]
    };

    const patterns = safePatterns[type] || [];
    return patterns.some(pattern => pattern.test(line));
  }

  private getConfidence(line: string, type: VulnerabilityType): 'high' | 'medium' | 'low' {
    // Patterns that indicate definite vulnerabilities
    const highConfidencePatterns: Record<string, RegExp[]> = {
      [VulnerabilityType.SQL_INJECTION]: [
        /\+\s*req\./,
        /\+\s*request\./,
        /\$\{.*req\./,
        /`.*\$\{.*req\./
      ],
      [VulnerabilityType.XSS]: [
        /innerHTML\s*=\s*[^'"]*req\./,
        /document\.write\s*\([^)]*req\./,
        /\$\([^)]+\)\.html\s*\([^)]*req\./
      ]
    };

    const patterns = highConfidencePatterns[type] || [];
    if (patterns.some(pattern => pattern.test(line))) {
      return 'high';
    }

    // Check for common safe patterns
    if (this.isSafeUsage(line, type)) {
      return 'low';
    }

    return 'medium';
  }
}

// Export a default instance for backward compatibility
export const securityDetector = new SecurityDetectorV2();