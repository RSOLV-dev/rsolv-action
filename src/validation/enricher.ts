/**
 * ValidationEnricher - Enriches scan-created issues with detailed vulnerability information
 * Implements RFC-043 enhanced validation phase
 */

import { logger } from '../utils/logger.js';
import { IssueContext } from '../types/index.js';
import { execSync } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import { updateIssue, addLabels } from '../github/api.js';

export interface DetailedVulnerability {
  file: string;
  startLine: number;
  endLine: number;
  column?: number;
  codeSnippet: string;
  pattern: string;
  confidence: 'high' | 'medium' | 'low';
  astValidation: boolean;
  proofOfConcept?: string;
  suggestedFix?: string;
  cweId?: string;
  owasp?: string;
}

export interface ValidationResult {
  issueNumber: number;
  originalIssue: IssueContext;
  validationTimestamp: Date;
  vulnerabilities: DetailedVulnerability[];
  enriched: boolean;
  labelAdded: boolean;
}

export class ValidationEnricher {
  private githubToken: string;
  private rsolvApiKey?: string;

  constructor(githubToken: string, rsolvApiKey?: string) {
    this.githubToken = githubToken;
    this.rsolvApiKey = rsolvApiKey;
  }

  /**
   * Enrich an issue with detailed validation information
   */
  async enrichIssue(issue: IssueContext): Promise<ValidationResult> {
    logger.info(`[VALIDATE] Enriching issue #${issue.number} with detailed validation`);

    try {
      // Step 1: Parse issue body to extract file references
      const fileReferences = this.parseIssueForFiles(issue);
      logger.info(`[VALIDATE] Found ${fileReferences.length} file references in issue`);

      // Step 2: Analyze each file for specific vulnerabilities
      const vulnerabilities: DetailedVulnerability[] = [];
      
      for (const filePath of fileReferences) {
        const fileVulns = await this.analyzeFile(filePath, issue);
        vulnerabilities.push(...fileVulns);
      }

      logger.info(`[VALIDATE] Found ${vulnerabilities.length} specific vulnerabilities`);

      // Step 3: Update issue body with validation results
      const updatedBody = this.generateEnrichedIssueBody(issue, vulnerabilities);
      
      await updateIssue(
        issue.repository.owner,
        issue.repository.name,
        issue.number,
        { body: updatedBody }
      );

      // Step 4: Add validated label
      await addLabels(
        issue.repository.owner,
        issue.repository.name,
        issue.number,
        ['rsolv:validated']
      );

      logger.info(`[VALIDATE] Successfully enriched issue #${issue.number}`);

      return {
        issueNumber: issue.number,
        originalIssue: issue,
        validationTimestamp: new Date(),
        vulnerabilities,
        enriched: true,
        labelAdded: true
      };

    } catch (error) {
      logger.error(`[VALIDATE] Failed to enrich issue #${issue.number}:`, error);
      throw error;
    }
  }

  /**
   * Parse issue body to extract file references
   */
  private parseIssueForFiles(issue: IssueContext): string[] {
    const files: string[] = [];
    const body = issue.body || '';
    
    // Pattern 1: Look for markdown file references like `file.js`
    const codeBlockPattern = /`([^`]+\.(js|ts|jsx|tsx|py|rb|java|go|php|cs))`/g;
    let match;
    while ((match = codeBlockPattern.exec(body)) !== null) {
      if (!files.includes(match[1])) {
        files.push(match[1]);
      }
    }

    // Pattern 2: Look for file paths in "Affected Files" section
    const affectedFilesPattern = /\*\*Affected Files\*\*:?\s*\n([\s\S]*?)(?:\n\n|\n\*\*|$)/;
    const affectedMatch = body.match(affectedFilesPattern);
    if (affectedMatch) {
      const fileList = affectedMatch[1];
      const fileLines = fileList.split('\n');
      for (const line of fileLines) {
        // Extract file path from bullet points or plain lines
        const fileMatch = line.match(/[-*]\s*(.+\.(js|ts|jsx|tsx|py|rb|java|go|php|cs))/);
        if (fileMatch && !files.includes(fileMatch[1].trim())) {
          files.push(fileMatch[1].trim());
        }
      }
    }

    // Pattern 3: Look for file paths in code blocks
    const codeBlocksPattern = /```[\s\S]*?```/g;
    const codeBlocks = body.match(codeBlocksPattern) || [];
    for (const block of codeBlocks) {
      // Look for file paths in comments like // File: path/to/file.js
      const fileCommentPattern = /(?:\/\/|#|\/\*)\s*(?:File|file|FILE):\s*(.+\.(js|ts|jsx|tsx|py|rb|java|go|php|cs))/g;
      let fileMatch;
      while ((fileMatch = fileCommentPattern.exec(block)) !== null) {
        if (!files.includes(fileMatch[1].trim())) {
          files.push(fileMatch[1].trim());
        }
      }
      
      // Pattern 4: Look for file paths in plain comments (without File: prefix)
      // Matches: // app/routes/profile.js or # lib/auth.py or /* src/main.java */
      const supportedExtensions = 'js|ts|jsx|tsx|py|rb|java|go|php|cs';
      const plainCommentPattern = new RegExp(
        `(?:^|\\n)\\s*(?:\\/\\/|#|\\/\\*)\\s*([a-zA-Z0-9_\\-\\.\\/]+\\.(${supportedExtensions}))\\s*(?:\\*\\/)?`,
        'gm'
      );
      let plainMatch;
      while ((plainMatch = plainCommentPattern.exec(block)) !== null) {
        const filePath = plainMatch[1].trim();
        // Ensure it looks like a valid file path (contains at least one /)
        if (filePath.includes('/') && !files.includes(filePath)) {
          files.push(filePath);
        }
      }
    }

    return files;
  }

  /**
   * Analyze a file for specific vulnerabilities
   */
  private async analyzeFile(filePath: string, issue: IssueContext): Promise<DetailedVulnerability[]> {
    const vulnerabilities: DetailedVulnerability[] = [];
    
    // Check if file exists
    const fullPath = path.resolve(process.cwd(), filePath);
    if (!fs.existsSync(fullPath)) {
      logger.warn(`[VALIDATE] File not found: ${filePath}`);
      return vulnerabilities;
    }

    // Read file content
    const content = fs.readFileSync(fullPath, 'utf8');
    const lines = content.split('\n');

    // Extract vulnerability type from issue title
    const vulnType = this.extractVulnerabilityType(issue);
    
    // Run AST validation if available
    let astResults: any = null;
    if (this.rsolvApiKey) {
      astResults = await this.runASTValidation(filePath, content, vulnType);
    }

    // Pattern-based detection based on vulnerability type
    const patterns = this.getPatterns(vulnType);
    
    for (const pattern of patterns) {
      const regex = pattern.regex;
      let match;
      
      while ((match = regex.exec(content)) !== null) {
        const lineNumber = content.substring(0, match.index).split('\n').length;
        const startLine = lineNumber;
        const endLine = lineNumber + match[0].split('\n').length - 1;
        
        // Extract code snippet with context
        const contextStart = Math.max(0, startLine - 3);
        const contextEnd = Math.min(lines.length - 1, endLine + 2);
        const codeSnippet = lines.slice(contextStart, contextEnd + 1).join('\n');
        
        // Check if AST validation confirms this
        // The validation API returns { validated: [...] } with isValid flag
        const astValidated = astResults?.validated?.some((v: any) => 
          v.isValid === true
        ) || false;
        
        vulnerabilities.push({
          file: filePath,
          startLine,
          endLine,
          column: match.index - content.lastIndexOf('\n', match.index) - 1,
          codeSnippet,
          pattern: pattern.name,
          confidence: astValidated ? 'high' : pattern.confidence as 'high' | 'medium' | 'low',
          astValidation: astValidated,
          suggestedFix: pattern.suggestedFix,
          cweId: pattern.cweId,
          owasp: pattern.owasp
        });
      }
    }

    return vulnerabilities;
  }

  /**
   * Extract vulnerability type from issue
   */
  private extractVulnerabilityType(issue: IssueContext): string {
    const title = issue.title.toLowerCase();
    
    if (title.includes('sql injection')) return 'sql-injection';
    if (title.includes('xss') || title.includes('cross-site scripting')) return 'xss';
    if (title.includes('command injection')) return 'command-injection';
    if (title.includes('path traversal')) return 'path-traversal';
    if (title.includes('nosql injection')) return 'nosql-injection';
    if (title.includes('xxe') || title.includes('xml external entity')) return 'xxe';
    if (title.includes('ssrf') || title.includes('server-side request forgery')) return 'ssrf';
    if (title.includes('javascript injection') || title.includes('eval')) return 'ssjs-injection';
    
    return 'generic';
  }

  /**
   * Get detection patterns for vulnerability type
   */
  private getPatterns(vulnType: string): Array<{
    name: string;
    regex: RegExp;
    confidence: string;
    suggestedFix?: string;
    cweId?: string;
    owasp?: string;
  }> {
    const patterns: Record<string, any[]> = {
      'sql-injection': [
        {
          name: 'String concatenation in SQL query',
          regex: /(?:query|execute|prepare|SELECT|INSERT|UPDATE|DELETE).*["'`].*\+.*["'`]/gi,
          confidence: 'high',
          suggestedFix: 'Use parameterized queries',
          cweId: 'CWE-89',
          owasp: 'A03:2021'
        },
        {
          name: 'Template literal in SQL query',
          regex: /(?:query|execute|prepare)\s*\(`[^`]*\$\{[^}]+\}[^`]*`\)/g,
          confidence: 'high',
          suggestedFix: 'Use parameterized queries',
          cweId: 'CWE-89',
          owasp: 'A03:2021'
        }
      ],
      'xss': [
        {
          name: 'Direct HTML injection',
          regex: /innerHTML\s*=\s*[^;]+user|req\.|params|query/g,
          confidence: 'high',
          suggestedFix: 'Use textContent or escape HTML',
          cweId: 'CWE-79',
          owasp: 'A03:2021'
        },
        {
          name: 'Unescaped template rendering',
          regex: /\{\{\{[^}]+\}\}\}/g,
          confidence: 'medium',
          suggestedFix: 'Use escaped template syntax',
          cweId: 'CWE-79',
          owasp: 'A03:2021'
        }
      ],
      'command-injection': [
        {
          name: 'exec with user input',
          regex: /(?:exec|spawn|execFile)\s*\([^)]*(?:req\.|params|query|body)/g,
          confidence: 'high',
          suggestedFix: 'Validate and sanitize input',
          cweId: 'CWE-78',
          owasp: 'A03:2021'
        }
      ],
      'nosql-injection': [
        {
          name: 'MongoDB $where operator',
          regex: /\$where.*(?:req\.|params|query|body)/g,
          confidence: 'high',
          suggestedFix: 'Avoid $where, use standard queries',
          cweId: 'CWE-943',
          owasp: 'A03:2021'
        },
        {
          name: 'Direct object injection',
          regex: /find\s*\(\s*(?:req\.body|req\.query|req\.params)/g,
          confidence: 'medium',
          suggestedFix: 'Validate input structure',
          cweId: 'CWE-943',
          owasp: 'A03:2021'
        }
      ],
      'ssjs-injection': [
        {
          name: 'eval() with user input',
          regex: /eval\s*\(\s*(?:req\.|request\.|params|query|body)/gi,
          confidence: 'high',
          suggestedFix: 'Use parseInt/parseFloat or JSON.parse instead of eval',
          cweId: 'CWE-94',
          owasp: 'A03:2021'
        },
        {
          name: 'Function constructor with user input',
          regex: /new\s+Function\s*\([^)]*(?:req\.|params|query|body)/gi,
          confidence: 'high',
          suggestedFix: 'Avoid dynamic code generation',
          cweId: 'CWE-94',
          owasp: 'A03:2021'
        }
      ],
      'generic': [
        {
          name: 'Potential security issue',
          regex: /(?:eval|Function)\s*\(/g,
          confidence: 'low',
          suggestedFix: 'Review for security implications',
          cweId: 'CWE-94'
        }
      ]
    };

    return patterns[vulnType] || patterns['generic'];
  }

  /**
   * Run AST validation using RSOLV API
   */
  private async runASTValidation(filePath: string, content: string, vulnType: string): Promise<any> {
    if (!this.rsolvApiKey) {
      return null;
    }

    try {
      // Call RSOLV API for vulnerability validation
      const response = await fetch(`${process.env.RSOLV_API_URL || 'https://api.rsolv.dev'}/api/v1/vulnerabilities/validate`, {
        method: 'POST',
        headers: {
          'x-api-key': this.rsolvApiKey,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          vulnerabilities: [{
            id: `temp-${Date.now()}`,
            patternId: vulnType,
            filePath: filePath,
            line: 1,
            code: content.split('\n')[0],
            severity: 'high'
          }],
          files: {
            [filePath]: content
          }
        })
      });

      if (!response.ok) {
        logger.warn(`[VALIDATE] AST validation failed for ${filePath}: ${response.statusText}`);
        return null;
      }

      return await response.json();
    } catch (error) {
      logger.warn(`[VALIDATE] AST validation error for ${filePath}:`, error);
      return null;
    }
  }

  /**
   * Generate enriched issue body with validation results
   */
  private generateEnrichedIssueBody(issue: IssueContext, vulnerabilities: DetailedVulnerability[]): string {
    let body = issue.body || '';
    
    // Remove any existing validation results section
    const validationSectionPattern = /## Validation Results[\s\S]*?(?=##|$)/;
    body = body.replace(validationSectionPattern, '');
    
    // Add new validation results
    body += '\n\n## Validation Results\n\n';
    body += `**Validated at**: ${new Date().toISOString()}\n`;
    body += `**Specific vulnerabilities found**: ${vulnerabilities.length}\n\n`;
    
    if (vulnerabilities.length === 0) {
      body += '⚠️ **No specific vulnerabilities detected** - This may be a false positive.\n';
    } else {
      body += '### Detailed Findings\n\n';
      
      for (let i = 0; i < vulnerabilities.length; i++) {
        const vuln = vulnerabilities[i];
        body += `#### Vulnerability ${i + 1}\n\n`;
        body += `**File**: \`${vuln.file}\`\n`;
        body += `**Lines**: ${vuln.startLine}-${vuln.endLine}\n`;
        body += `**Confidence**: ${vuln.confidence}\n`;
        body += `**AST Validated**: ${vuln.astValidation ? '✅' : '❌'}\n`;
        
        if (vuln.cweId) {
          body += `**CWE**: ${vuln.cweId}\n`;
        }
        if (vuln.owasp) {
          body += `**OWASP**: ${vuln.owasp}\n`;
        }
        
        body += '\n**Code**:\n';
        body += '```' + this.getLanguageFromFile(vuln.file) + '\n';
        body += vuln.codeSnippet + '\n';
        body += '```\n\n';
        
        if (vuln.suggestedFix) {
          body += `**Suggested Fix**: ${vuln.suggestedFix}\n\n`;
        }
      }
    }
    
    body += '### Next Steps\n\n';
    if (vulnerabilities.length > 0) {
      body += '1. Review the detailed findings above\n';
      body += '2. Add `rsolv:automate` label to trigger automated fix\n';
      body += '3. Or manually fix based on the suggestions provided\n';
    } else {
      body += '1. Review the issue for false positives\n';
      body += '2. Consider closing if no real vulnerability exists\n';
      body += '3. Or provide more specific information about the vulnerability\n';
    }
    
    return body;
  }

  /**
   * Get language identifier from file extension
   */
  private getLanguageFromFile(filePath: string): string {
    const ext = path.extname(filePath).toLowerCase();
    const langMap: Record<string, string> = {
      '.js': 'javascript',
      '.jsx': 'javascript',
      '.ts': 'typescript',
      '.tsx': 'typescript',
      '.py': 'python',
      '.rb': 'ruby',
      '.java': 'java',
      '.go': 'go',
      '.php': 'php',
      '.cs': 'csharp'
    };
    return langMap[ext] || '';
  }
}