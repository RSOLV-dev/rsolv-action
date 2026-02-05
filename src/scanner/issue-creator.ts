import { getGitHubClient } from '../github/api.js';
import { logger } from '../utils/logger.js';
import type {
  VulnerabilityGroup,
  CreatedIssue,
  ScanConfig,
  GitHubIssue,
  ExistingIssueResult,
  IssueCreationResult,
  IssueLabel
} from './types.js';

/**
 * Map of vulnerability types to human-readable names
 * Supports both underscore and hyphen formats for compatibility
 */
const VULNERABILITY_TYPE_NAMES: Record<string, string> = {
  'sql_injection': 'SQL Injection',
  'sql-injection': 'SQL Injection',
  'xss': 'Cross-Site Scripting (XSS)',
  'command_injection': 'Command Injection',
  'command-injection': 'Command Injection',
  'path_traversal': 'Path Traversal',
  'path-traversal': 'Path Traversal',
  'weak_cryptography': 'Weak Cryptography',
  'weak-crypto': 'Weak Cryptography',
  'hardcoded_secrets': 'Hardcoded Secrets',
  'hardcoded_secret': 'Hardcoded Secrets',
  'hardcoded-secret': 'Hardcoded Secrets',
  'insecure-random': 'Insecure Random Number Generation',
  'open_redirect': 'Open Redirect',
  'open-redirect': 'Open Redirect',
  'xml_external_entities': 'XML External Entity (XXE)',
  'xxe': 'XML External Entity (XXE)',
  'server_side_request_forgery': 'Server-Side Request Forgery (SSRF)',
  'ssrf': 'Server-Side Request Forgery (SSRF)',
  'nosql_injection': 'NoSQL Injection',
  'nosql-injection': 'NoSQL Injection',
  'ldap_injection': 'LDAP Injection',
  'ldap-injection': 'LDAP Injection',
  'xpath_injection': 'XPath Injection',
  'xpath-injection': 'XPath Injection',
  'weak-hash': 'Weak Hashing Algorithm',
  'insecure_deserialization': 'Insecure Deserialization',
  'insecure-deserialization': 'Insecure Deserialization',
  'prototype_pollution': 'Prototype Pollution',
  'prototype-pollution': 'Prototype Pollution',
  'code_injection': 'Code Injection',
  'code-injection': 'Code Injection',
  'template_injection': 'Server-Side Template Injection (SSTI)',
  'template-injection': 'Server-Side Template Injection (SSTI)',
  'insecure_jwt': 'Insecure JWT Configuration',
  'debug_mode': 'Debug Mode Enabled',
  'broken_access_control': 'Broken Access Control',
  'broken_authentication': 'Broken Authentication',
  'security_misconfiguration': 'Security Misconfiguration',
  'sensitive_data_exposure': 'Sensitive Data Exposure',
  'mass_assignment': 'Mass Assignment',
  'log_injection': 'Log Injection',
  'information_disclosure': 'Information Disclosure',
  'improper_input_validation': 'Improper Input Validation',
  'cross_site_request_forgery': 'Cross-Site Request Forgery (CSRF)',
  'csrf': 'Cross-Site Request Forgery (CSRF)',
  'denial_of_service': 'Denial of Service',
};

/**
 * Get human-readable name for a vulnerability type
 */
function getVulnerabilityTypeName(type: string): string {
  return VULNERABILITY_TYPE_NAMES[type] || type.replace(/[_-]/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
}

export class IssueCreator {
  private github: ReturnType<typeof getGitHubClient>;

  constructor() {
    this.github = getGitHubClient();
  }

  /**
   * Extract label names from GitHub issue labels
   */
  private extractLabelNames(labels: IssueLabel[]): string[] {
    return labels.map(label =>
      typeof label === 'string' ? label : label.name || ''
    );
  }

  /**
   * Check if issue should be skipped based on its labels
   * Returns skip reason or null if issue should be processed
   */
  private checkSkipStatus(labels: string[]): 'skip:validated' | 'skip:false-positive' | 'skip:dismissed' | null {
    if (labels.includes('rsolv:validated')) {
      return 'skip:validated';
    }
    if (labels.includes('rsolv:false-positive')) {
      return 'skip:false-positive';
    }
    if (labels.includes('rsolv:wont-fix') || labels.includes('rsolv:accepted-risk') || labels.includes('rsolv:deferred')) {
      return 'skip:dismissed';
    }
    return null;
  }

  async createIssuesFromGroups(
    groups: VulnerabilityGroup[],
    config: ScanConfig
  ): Promise<IssueCreationResult> {
    const createdIssues: CreatedIssue[] = [];
    let skippedValidated = 0;
    let skippedFalsePositive = 0;
    let skippedDismissed = 0;

    if (!config.createIssues) {
      logger.info('Issue creation disabled, skipping');
      return {issues: createdIssues, skippedValidated, skippedFalsePositive, skippedDismissed};
    }

    // Separate vendor and application vulnerability groups
    const vendorGroups = groups.filter(g => g.isVendor);
    const appGroups = groups.filter(g => !g.isVendor);

    logger.info(`Found ${appGroups.length} application vulnerability groups and ${vendorGroups.length} vendor vulnerability groups`);

    // Only create issues for application vulnerabilities by default
    // Vendor vulnerabilities should be handled differently (library updates, not patches)
    const groupsToCreateIssues = appGroups;

    // Apply max_issues limit if specified
    const maxIssues = config.maxIssues;
    const groupsToProcess = maxIssues ? groupsToCreateIssues.slice(0, maxIssues) : groupsToCreateIssues;

    logger.info(`Processing ${groupsToProcess.length} application vulnerability groups` +
                (maxIssues ? ` (limited by max_issues: ${maxIssues})` : ''));

    if (maxIssues && groupsToCreateIssues.length > maxIssues) {
      logger.info(`Note: ${groupsToCreateIssues.length - maxIssues} vulnerability groups will be skipped due to max_issues limit`);
    }

    // Log vendor vulnerabilities that won't be processed
    if (vendorGroups.length > 0) {
      logger.info(`Skipping ${vendorGroups.length} vendor vulnerability groups (require library updates, not code patches)`);
      for (const vendorGroup of vendorGroups) {
        logger.info(`  - ${vendorGroup.type} in ${vendorGroup.files.length} vendor files (${vendorGroup.count} instances)`);
      }
    }

    for (const group of groupsToProcess) {
      try {
        // Check for existing issue with duplicate detection enabled
        const existingIssue = await this.findExistingIssue(group, config);

        if (existingIssue === 'skip:validated') {
          skippedValidated++;
          continue;
        }

        if (existingIssue === 'skip:false-positive') {
          skippedFalsePositive++;
          continue;
        }

        if (existingIssue === 'skip:dismissed') {
          skippedDismissed++;
          continue;
        }

        if (existingIssue) {
          logger.info(`Found existing issue #${existingIssue.number} for ${group.type} vulnerabilities`);
          const updatedIssue = await this.updateExistingIssue(existingIssue, group, config);
          createdIssues.push(updatedIssue);
        } else {
          const issue = await this.createIssueForGroup(group, config);
          createdIssues.push(issue);
          logger.info(`Created new issue #${issue.number} for ${group.type} vulnerabilities`);
        }
      } catch (error) {
        logger.error(`Failed to process issue for ${group.type}:`, error);
      }
    }

    return {issues: createdIssues, skippedValidated, skippedFalsePositive, skippedDismissed};
  }

  private async findExistingIssue(
    group: VulnerabilityGroup,
    config: ScanConfig
  ): Promise<ExistingIssueResult> {
    try {
      // In test mode with fresh issues flag, always create new issues
      if (process.env.RSOLV_TESTING_MODE === 'true' && process.env.RSOLV_FORCE_FRESH_ISSUES === 'true') {
        logger.info('Test mode: Force fresh issues enabled, skipping existing issue check');
        return null;
      }

      // Search for open issues with the vulnerability type label
      const typeLabel = `rsolv:vuln-${group.type}`;
      const { data: issues } = await this.github.issues.listForRepo({
        owner: config.repository.owner,
        repo: config.repository.name,
        labels: typeLabel,
        state: 'open'
      });

      if (issues.length === 0) {
        return null;
      }

      const existingIssue = issues[0] as GitHubIssue;
      const labelNames = this.extractLabelNames(existingIssue.labels);
      const skipStatus = this.checkSkipStatus(labelNames);

      if (skipStatus) {
        const reasonMap: Record<string, string> = {
          'skip:validated': 'validated',
          'skip:false-positive': 'false positive',
          'skip:dismissed': 'dismissed (wont-fix/accepted-risk/deferred)',
        };
        const reason = reasonMap[skipStatus] || skipStatus;
        logger.info(`Skipping ${reason} issue #${existingIssue.number} for ${group.type}`);
        return skipStatus;
      }

      // Only rsolv:detected - safe to update
      return existingIssue;
    } catch (error) {
      logger.warn(`Failed to check for existing issues: ${error}`);
      return null;
    }
  }

  private async updateExistingIssue(
    existingIssue: GitHubIssue,
    group: VulnerabilityGroup,
    config: ScanConfig
  ): Promise<CreatedIssue> {
    const title = this.generateIssueTitle(group);
    const body = this.generateIssueBody(group, config);

    // Update the issue with new information
    await this.github.issues.update({
      owner: config.repository.owner,
      repo: config.repository.name,
      issue_number: existingIssue.number,
      title,
      body
    });

    // Ensure rsolv:detected label is present for phase handoff
    // (existing issues from earlier runs may lack this label)
    const labelNames = this.extractLabelNames(existingIssue.labels || []);
    if (!labelNames.includes('rsolv:detected')) {
      await this.github.issues.addLabels({
        owner: config.repository.owner,
        repo: config.repository.name,
        issue_number: existingIssue.number,
        labels: ['rsolv:detected']
      });
    }

    // Add a comment showing the delta
    const comment = this.generateUpdateComment(group, existingIssue);
    await this.github.issues.createComment({
      owner: config.repository.owner,
      repo: config.repository.name,
      issue_number: existingIssue.number,
      body: comment
    });

    return {
      number: existingIssue.number,
      title,
      url: existingIssue.html_url,
      vulnerabilityType: group.type,
      fileCount: group.files.length
    };
  }

  private generateUpdateComment(group: VulnerabilityGroup, _existingIssue: GitHubIssue): string {
    const timestamp = new Date().toISOString();
    const fileText = group.files.length === 1 ? 'file' : 'files';

    return [
      `## 📊 Scan Update - ${timestamp}`,
      '',
      `**Updated vulnerability count**: ${group.count} instances in ${group.files.length} ${fileText}`,
      '',
      'This issue has been updated with the latest scan results.',
      'The vulnerability details above reflect the current state of the codebase.'
    ].join('\n');
  }

  private async createIssueForGroup(
    group: VulnerabilityGroup,
    config: ScanConfig
  ): Promise<CreatedIssue> {
    const title = this.generateIssueTitle(group);
    const body = this.generateIssueBody(group, config);

    // Build labels array - add type-specific label for duplicate detection
    const labels = [
      'rsolv:detected',
      `rsolv:vuln-${group.type}`,  // Type-specific label for duplicate detection
      'security',
      group.severity,
      'automated-scan'
    ];

    // Add rsolv:automate label if in demo mode or auto-fix is enabled
    if (process.env.RSOLV_DEMO_MODE === 'true' || process.env.RSOLV_AUTO_FIX === 'true') {
      labels.push('rsolv:automate');
      labels.push('demo');
    }

    const { data: issue } = await this.github.issues.create({
      owner: config.repository.owner,
      repo: config.repository.name,
      title,
      body,
      labels
    });

    return {
      number: issue.number,
      title: issue.title,
      url: issue.html_url,
      vulnerabilityType: group.type,
      fileCount: group.files.length
    };
  }

  private generateIssueTitle(group: VulnerabilityGroup): string {
    const vulnType = group.type || 'security-vulnerability';
    const readableType = getVulnerabilityTypeName(vulnType);
    const fileCount = group.files.length;
    const fileText = fileCount === 1 ? 'file' : 'files';

    return `🔒 ${readableType} vulnerabilities found in ${fileCount} ${fileText}`;
  }

  private generateIssueBody(group: VulnerabilityGroup, config: ScanConfig): string {
    const sections: string[] = [];

    // Header
    sections.push('## Security Vulnerability Report');
    sections.push('');
    const vulnType = group.type || 'security-vulnerability';
    const readableType = getVulnerabilityTypeName(vulnType);
    sections.push(`**Type**: ${readableType}`);
    sections.push(`**Severity**: ${group.severity.toUpperCase()}`);
    sections.push(`**Total Instances**: ${group.count}`);
    sections.push(`**Affected Files**: ${group.files.length}`);
    sections.push('');

    // Security Classification (from first vulnerability — all share same type)
    const representative = group.vulnerabilities[0];
    if (representative) {
      const classificationLines: string[] = [];
      if (representative.cweId) {
        const cweNum = representative.cweId.replace(/^CWE-/, '');
        classificationLines.push(`- **CWE**: [${representative.cweId}](https://cwe.mitre.org/data/definitions/${cweNum}.html)`);
      }
      if (representative.owaspCategory) {
        classificationLines.push(`- **OWASP**: ${representative.owaspCategory}`);
      }
      if (representative.confidence !== undefined) {
        classificationLines.push(`- **Confidence**: ${representative.confidence}%`);
      }
      if (classificationLines.length > 0) {
        sections.push('### Security Classification');
        sections.push(...classificationLines);
        sections.push('');
      }
    }

    // Description
    sections.push('### Description');
    sections.push(this.getVulnerabilityDescription(vulnType));
    sections.push('');
    
    // Affected Files
    sections.push('### Affected Files');
    sections.push('');
    
    // Group vulnerabilities by file
    const fileGroups = new Map<string, typeof group.vulnerabilities>();
    for (const vuln of group.vulnerabilities) {
      if (!vuln.filePath) continue;
      
      if (!fileGroups.has(vuln.filePath)) {
        fileGroups.set(vuln.filePath, []);
      }
      fileGroups.get(vuln.filePath)!.push(vuln);
    }
    
    // List each file and its vulnerabilities
    for (const [filePath, vulns] of fileGroups) {
      sections.push(`#### \`${filePath}\``);
      sections.push('');
      
      for (const vuln of vulns.slice(0, 3)) { // Show max 3 examples per file
        sections.push(`- **Line ${vuln.line}**: ${vuln.description}`);
        if (vuln.snippet) {
          sections.push('  ```' + this.detectLanguageFromPath(filePath));
          sections.push('  ' + vuln.snippet.trim());
          sections.push('  ```');
        }
      }
      
      if (vulns.length > 3) {
        sections.push(`- ... and ${vulns.length - 3} more instances`);
      }
      sections.push('');
    }
    
    // Recommendation
    sections.push('### Recommendation');
    sections.push(this.getVulnerabilityRecommendation(vulnType));
    sections.push('');
    
    // Footer
    sections.push('---');
    sections.push('*This issue was automatically generated by RSOLV security scanner*');
    sections.push(`*Repository: ${config.repository.owner}/${config.repository.name}*`);
    sections.push(`*Branch: ${config.repository.defaultBranch}*`);
    sections.push(`*Scan Date: ${new Date().toISOString()}*`);
    sections.push('');
    sections.push('*To dismiss this finding, add one of these labels:*');
    sections.push('*`rsolv:false-positive` · `rsolv:wont-fix` · `rsolv:accepted-risk` · `rsolv:deferred`*');
    
    return sections.join('\n');
  }

  private getVulnerabilityDescription(type: string): string {
    const descriptions: Record<string, string> = {
      'sql_injection': 'SQL injection vulnerabilities occur when user input is directly concatenated into SQL queries without proper sanitization or parameterization. This can allow attackers to execute arbitrary SQL commands.',
      'sql-injection': 'SQL injection vulnerabilities occur when user input is directly concatenated into SQL queries without proper sanitization or parameterization. This can allow attackers to execute arbitrary SQL commands.',
      'xss': 'Cross-Site Scripting (XSS) vulnerabilities occur when user input is rendered in HTML without proper escaping. This can allow attackers to inject malicious scripts that execute in other users\' browsers.',
      'command_injection': 'Command injection vulnerabilities occur when user input is passed directly to system commands. This can allow attackers to execute arbitrary system commands on the server.',
      'command-injection': 'Command injection vulnerabilities occur when user input is passed directly to system commands. This can allow attackers to execute arbitrary system commands on the server.',
      'path_traversal': 'Path traversal vulnerabilities occur when user input is used to construct file paths without proper validation. This can allow attackers to access files outside the intended directory.',
      'path-traversal': 'Path traversal vulnerabilities occur when user input is used to construct file paths without proper validation. This can allow attackers to access files outside the intended directory.',
      'weak_cryptography': 'Weak cryptography vulnerabilities occur when outdated or insecure cryptographic algorithms are used. This can make encrypted data vulnerable to decryption by attackers.',
      'weak-crypto': 'Weak cryptography vulnerabilities occur when outdated or insecure cryptographic algorithms are used. This can make encrypted data vulnerable to decryption by attackers.',
      'hardcoded_secrets': 'Hardcoded secrets in source code can be exposed if the code is leaked or accessed by unauthorized parties. This includes API keys, passwords, and other sensitive credentials.',
      'hardcoded-secret': 'Hardcoded secrets in source code can be exposed if the code is leaked or accessed by unauthorized parties. This includes API keys, passwords, and other sensitive credentials.',
      'insecure-random': 'Using insecure random number generators for security-critical operations can make systems predictable and vulnerable to attacks.',
      'open_redirect': 'Open redirect vulnerabilities occur when user input is used to construct redirect URLs without validation. This can be used in phishing attacks.',
      'open-redirect': 'Open redirect vulnerabilities occur when user input is used to construct redirect URLs without validation. This can be used in phishing attacks.',
      'xml_external_entities': 'XML External Entity (XXE) vulnerabilities occur when XML parsers process external entity references. This can lead to file disclosure, SSRF, or denial of service.',
      'xxe': 'XML External Entity (XXE) vulnerabilities occur when XML parsers process external entity references. This can lead to file disclosure, SSRF, or denial of service.',
      'server_side_request_forgery': 'Server-Side Request Forgery (SSRF) vulnerabilities occur when user input is used to make HTTP requests from the server. This can allow access to internal resources.',
      'ssrf': 'Server-Side Request Forgery (SSRF) vulnerabilities occur when user input is used to make HTTP requests from the server. This can allow access to internal resources.',
      'nosql_injection': 'NoSQL injection vulnerabilities occur when user input is used in NoSQL queries without proper sanitization. This can allow attackers to manipulate queries and access unauthorized data.',
      'nosql-injection': 'NoSQL injection vulnerabilities occur when user input is used in NoSQL queries without proper sanitization. This can allow attackers to manipulate queries and access unauthorized data.',
      'ldap_injection': 'LDAP injection vulnerabilities occur when user input is used in LDAP queries without proper escaping. This can allow attackers to modify LDAP queries and bypass authentication.',
      'ldap-injection': 'LDAP injection vulnerabilities occur when user input is used in LDAP queries without proper escaping. This can allow attackers to modify LDAP queries and bypass authentication.',
      'xpath_injection': 'XPath injection vulnerabilities occur when user input is used in XPath queries without proper sanitization. This can allow attackers to extract sensitive data from XML documents.',
      'xpath-injection': 'XPath injection vulnerabilities occur when user input is used in XPath queries without proper sanitization. This can allow attackers to extract sensitive data from XML documents.',
      'weak-hash': 'Weak hashing algorithms like MD5 or SHA1 are vulnerable to collision attacks and should not be used for security-critical operations.',
      'insecure_deserialization': 'Insecure deserialization vulnerabilities occur when untrusted data is deserialized without proper validation. This can lead to remote code execution.',
      'insecure-deserialization': 'Insecure deserialization vulnerabilities occur when untrusted data is deserialized without proper validation. This can lead to remote code execution.',
      'prototype_pollution': 'Prototype pollution vulnerabilities occur when an attacker can modify an object\'s prototype, allowing them to inject properties that are inherited by all objects. This can lead to denial of service, property injection, or in some cases remote code execution by polluting the prototype chain.',
      'prototype-pollution': 'Prototype pollution vulnerabilities occur when an attacker can modify an object\'s prototype, allowing them to inject properties that are inherited by all objects. This can lead to denial of service, property injection, or in some cases remote code execution by polluting the prototype chain.',
      'code_injection': 'Code injection vulnerabilities occur when user input is passed to functions that execute code dynamically, such as eval(). This can allow attackers to execute arbitrary code in the application context.',
      'code-injection': 'Code injection vulnerabilities occur when user input is passed to functions that execute code dynamically, such as eval(). This can allow attackers to execute arbitrary code in the application context.'
    };

    return descriptions[type] || 'This type of vulnerability can compromise the security of your application.';
  }

  private getVulnerabilityRecommendation(type: string): string {
    const recommendations: Record<string, string> = {
      'sql_injection': 'Use parameterized queries or prepared statements instead of string concatenation. Never trust user input and always validate and sanitize it before use in SQL queries.',
      'sql-injection': 'Use parameterized queries or prepared statements instead of string concatenation. Never trust user input and always validate and sanitize it before use in SQL queries.',
      'xss': 'Always escape user input before rendering it in HTML. Use context-appropriate escaping functions and consider using a templating engine that provides automatic escaping.',
      'command_injection': 'Avoid executing system commands with user input. If necessary, use a whitelist of allowed values and escape shell metacharacters. Consider using language-specific APIs instead of shell commands.',
      'command-injection': 'Avoid executing system commands with user input. If necessary, use a whitelist of allowed values and escape shell metacharacters. Consider using language-specific APIs instead of shell commands.',
      'path_traversal': 'Validate and sanitize file paths. Use a whitelist of allowed directories and files. Resolve paths to their canonical form and ensure they stay within allowed boundaries.',
      'path-traversal': 'Validate and sanitize file paths. Use a whitelist of allowed directories and files. Resolve paths to their canonical form and ensure they stay within allowed boundaries.',
      'weak_cryptography': 'Replace weak cryptographic algorithms with strong, modern alternatives. Use AES for encryption, SHA-256 or better for hashing, and ensure proper key management.',
      'weak-crypto': 'Replace weak cryptographic algorithms with strong, modern alternatives. Use AES for encryption, SHA-256 or better for hashing, and ensure proper key management.',
      'hardcoded_secrets': 'Remove hardcoded secrets from source code. Use environment variables, secure key management systems, or configuration files that are not committed to version control.',
      'hardcoded-secret': 'Remove hardcoded secrets from source code. Use environment variables, secure key management systems, or configuration files that are not committed to version control.',
      'insecure-random': 'Use cryptographically secure random number generators (CSPRNGs) for security-critical operations. Most languages provide secure alternatives to standard random functions.',
      'open_redirect': 'Validate redirect URLs against a whitelist of allowed domains. Avoid using user input directly in redirect locations.',
      'open-redirect': 'Validate redirect URLs against a whitelist of allowed domains. Avoid using user input directly in redirect locations.',
      'xml_external_entities': 'Disable XML external entity processing in XML parsers. Configure parsers to not resolve external entities or DTDs.',
      'xxe': 'Disable XML external entity processing in XML parsers. Configure parsers to not resolve external entities or DTDs.',
      'server_side_request_forgery': 'Validate and whitelist URLs before making requests. Implement network segmentation to limit access to internal resources.',
      'ssrf': 'Validate and whitelist URLs before making requests. Implement network segmentation to limit access to internal resources.',
      'nosql_injection': 'Sanitize and validate user input before using it in NoSQL queries. Use parameterized queries where available and avoid string concatenation.',
      'nosql-injection': 'Sanitize and validate user input before using it in NoSQL queries. Use parameterized queries where available and avoid string concatenation.',
      'ldap_injection': 'Escape special LDAP characters in user input. Use parameterized LDAP queries and validate input against expected patterns.',
      'ldap-injection': 'Escape special LDAP characters in user input. Use parameterized LDAP queries and validate input against expected patterns.',
      'xpath_injection': 'Use parameterized XPath queries or escape user input properly. Validate input against expected patterns and avoid dynamic query construction.',
      'xpath-injection': 'Use parameterized XPath queries or escape user input properly. Validate input against expected patterns and avoid dynamic query construction.',
      'weak-hash': 'Replace MD5 and SHA1 with SHA-256 or better for security operations. For password hashing, use bcrypt, scrypt, or Argon2.',
      'insecure_deserialization': 'Avoid deserializing untrusted data. If necessary, use safe serialization formats like JSON and validate the structure before processing.',
      'insecure-deserialization': 'Avoid deserializing untrusted data. If necessary, use safe serialization formats like JSON and validate the structure before processing.',
      'prototype_pollution': 'Use Object.create(null) to create objects without a prototype, validate object keys against a whitelist before assignment, use Map instead of plain objects for dynamic key-value storage, or freeze prototypes with Object.freeze(Object.prototype).',
      'prototype-pollution': 'Use Object.create(null) to create objects without a prototype, validate object keys against a whitelist before assignment, use Map instead of plain objects for dynamic key-value storage, or freeze prototypes with Object.freeze(Object.prototype).',
      'code_injection': 'Avoid using eval() and similar dynamic code execution functions. Use safe alternatives like JSON.parse() for data parsing. If dynamic code execution is absolutely necessary, use sandboxed environments and strict input validation.',
      'code-injection': 'Avoid using eval() and similar dynamic code execution functions. Use safe alternatives like JSON.parse() for data parsing. If dynamic code execution is absolutely necessary, use sandboxed environments and strict input validation.'
    };

    return recommendations[type] || 'Review and fix the identified vulnerabilities according to security best practices.';
  }

  private detectLanguageFromPath(path: string): string {
    const ext = path.substring(path.lastIndexOf('.'));
    const langMap: Record<string, string> = {
      '.js': 'javascript',
      '.jsx': 'javascript',
      '.ts': 'typescript',
      '.tsx': 'typescript',
      '.py': 'python',
      '.rb': 'ruby',
      '.java': 'java',
      '.php': 'php',
      '.ex': 'elixir',
      '.exs': 'elixir'
    };
    
    return langMap[ext] || '';
  }
}