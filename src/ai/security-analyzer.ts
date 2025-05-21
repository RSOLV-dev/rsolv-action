import { IssueContext, ActionConfig, AnalysisData, IssueType } from '../types/index.js';
import { logger } from '../utils/logger.js';
import { SecurityDetector, Vulnerability, VulnerabilityType } from '../security/index.js';

export interface SecurityAnalysisResult {
  hasSecurityIssues: boolean;
  vulnerabilities: Vulnerability[];
  riskLevel: 'low' | 'medium' | 'high' | 'critical';
  recommendations: string[];
  affectedFiles: string[];
}

/**
 * Enhanced analyzer that combines AI analysis with security vulnerability detection
 */
export class SecurityAwareAnalyzer {
  private securityDetector: SecurityDetector;

  constructor() {
    this.securityDetector = new SecurityDetector();
  }

  /**
   * Analyze an issue with both AI and security scanning
   */
  async analyzeWithSecurity(
    issue: IssueContext,
    config: ActionConfig,
    codebaseFiles?: Map<string, string>
  ): Promise<AnalysisData & { securityAnalysis?: SecurityAnalysisResult }> {
    logger.info(`Analyzing issue #${issue.number} with security-aware analysis`);

    // Perform standard AI analysis first
    const standardAnalysis = await this.performStandardAnalysis(issue, config);

    // If we have code files, perform security analysis
    let securityAnalysis: SecurityAnalysisResult | undefined;
    if (codebaseFiles && codebaseFiles.size > 0) {
      securityAnalysis = await this.performSecurityAnalysis(codebaseFiles, issue);
      
      // Enhance standard analysis with security findings
      if (securityAnalysis.hasSecurityIssues) {
        standardAnalysis.issueType = 'security';
        standardAnalysis.estimatedComplexity = this.adjustComplexityForSecurity(
          standardAnalysis.estimatedComplexity,
          securityAnalysis.riskLevel
        );
      }
    }

    return {
      ...standardAnalysis,
      securityAnalysis
    };
  }

  /**
   * Perform security analysis on codebase files
   */
  private async performSecurityAnalysis(
    codebaseFiles: Map<string, string>,
    issue: IssueContext
  ): Promise<SecurityAnalysisResult> {
    logger.info('Performing security analysis on codebase files');

    const allVulnerabilities: Vulnerability[] = [];
    const affectedFiles: string[] = [];

    for (const [filePath, content] of codebaseFiles.entries()) {
      // Determine language from file extension
      const language = this.getLanguageFromPath(filePath);
      if (!language) continue;

      const vulnerabilities = this.securityDetector.detect(content, language);
      
      if (vulnerabilities.length > 0) {
        allVulnerabilities.push(...vulnerabilities);
        affectedFiles.push(filePath);
        logger.info(`Found ${vulnerabilities.length} vulnerabilities in ${filePath}`);
      }
    }

    // Calculate risk level
    const riskLevel = this.calculateRiskLevel(allVulnerabilities);

    // Generate recommendations
    const recommendations = this.generateSecurityRecommendations(allVulnerabilities);

    return {
      hasSecurityIssues: allVulnerabilities.length > 0,
      vulnerabilities: allVulnerabilities,
      riskLevel,
      recommendations,
      affectedFiles
    };
  }

  /**
   * Determine programming language from file path
   */
  private getLanguageFromPath(filePath: string): string | null {
    const extension = filePath.split('.').pop()?.toLowerCase();
    
    switch (extension) {
      case 'js':
      case 'jsx':
        return 'javascript';
      case 'ts':
      case 'tsx':
        return 'typescript';
      case 'py':
        return 'python';
      case 'rb':
        return 'ruby';
      case 'php':
        return 'php';
      case 'java':
        return 'java';
      case 'cs':
        return 'csharp';
      case 'go':
        return 'go';
      case 'rs':
        return 'rust';
      default:
        return null;
    }
  }

  /**
   * Calculate overall risk level from vulnerabilities
   */
  private calculateRiskLevel(vulnerabilities: Vulnerability[]): 'low' | 'medium' | 'high' | 'critical' {
    if (vulnerabilities.length === 0) return 'low';

    const criticalCount = vulnerabilities.filter(v => v.severity === 'critical').length;
    const highCount = vulnerabilities.filter(v => v.severity === 'high').length;
    const mediumCount = vulnerabilities.filter(v => v.severity === 'medium').length;

    if (criticalCount > 0) return 'critical';
    if (highCount >= 3) return 'critical';
    if (highCount >= 1) return 'high';
    if (mediumCount >= 3) return 'high';
    if (mediumCount >= 1) return 'medium';
    
    return 'low';
  }

  /**
   * Generate security recommendations based on found vulnerabilities
   */
  private generateSecurityRecommendations(vulnerabilities: Vulnerability[]): string[] {
    const recommendations = new Set<string>();

    for (const vuln of vulnerabilities) {
      if (vuln.remediation) {
        recommendations.add(vuln.remediation);
      }

      // Add general recommendations based on vulnerability type
      switch (vuln.type) {
        case VulnerabilityType.SQL_INJECTION:
          recommendations.add('Implement parameterized queries throughout the codebase');
          recommendations.add('Add input validation and sanitization');
          break;
        case VulnerabilityType.XSS:
          recommendations.add('Use secure DOM manipulation methods (textContent, not innerHTML)');
          recommendations.add('Implement Content Security Policy (CSP)');
          break;
        default:
          recommendations.add('Review security best practices for this vulnerability type');
      }
    }

    return Array.from(recommendations);
  }

  /**
   * Adjust complexity based on security risk level
   */
  private adjustComplexityForSecurity(
    baseComplexity: 'simple' | 'medium' | 'complex',
    riskLevel: 'low' | 'medium' | 'high' | 'critical'
  ): 'simple' | 'medium' | 'complex' {
    if (riskLevel === 'critical') return 'complex';
    if (riskLevel === 'high' && baseComplexity === 'simple') return 'medium';
    if (riskLevel === 'high' && baseComplexity === 'medium') return 'complex';
    
    return baseComplexity;
  }

  /**
   * Placeholder for standard analysis - in real implementation, this would call the existing analyzer
   */
  private async performStandardAnalysis(
    issue: IssueContext,
    config: ActionConfig
  ): Promise<AnalysisData> {
    // This is a simplified version - in real implementation, 
    // we would import and call the existing analyzeIssue function
    return {
      issueType: this.determineIssueType(issue),
      filesToModify: [],
      estimatedComplexity: 'medium',
      requiredContext: [],
      suggestedApproach: 'Analyze and fix the reported issue',
      confidenceScore: 0.7
    };
  }

  /**
   * Determine the issue type from the issue context
   */
  private determineIssueType(issue: IssueContext): IssueType {
    const title = issue.title.toLowerCase();
    const body = issue.body.toLowerCase();
    const combined = `${title} ${body}`;
    
    // Security check first
    if (combined.includes('secur') || combined.includes('vulnerab') || 
        combined.includes('hack') || combined.includes('attack') ||
        combined.includes('xss') || combined.includes('sql injection')) {
      return 'security';
    }
    
    // Check for other issue types
    if (combined.includes('fix') || combined.includes('bug')) {
      return 'bug';
    } else if (combined.includes('add') || combined.includes('feature')) {
      return 'feature';
    } else if (combined.includes('refactor')) {
      return 'refactoring';
    } else if (combined.includes('performance')) {
      return 'performance';
    }
    
    return 'other';
  }
}