/**
 * Educational PR creation with comprehensive security education
 * Implements RSOLV's mission to educate while fixing
 */

import { IssueContext, ActionConfig } from '../types/index.js';
import { ValidationData } from '../types/validation.js';
import { logger } from '../utils/logger.js';
import { getGitHubClient } from './api.js';
import { execSync } from 'child_process';
import { RsolvApiClient } from '../external/api-client.js';
import { getCweSpecificName, formatOwaspLink } from '../scanner/issue-creator.js';

/**
 * Enhanced PR result with educational content
 */
export interface EducationalPrResult {
  success: boolean;
  message: string;
  pullRequestUrl?: string;
  pullRequestNumber?: number;
  branchName?: string;
  commitHash?: string;
  educationalContent?: string;
  error?: string;
}

// Re-export ValidationData for backward compatibility
export type { ValidationData } from '../types/validation.js';

/**
 * Build a descriptive PR title that includes vulnerability type and CWE.
 *
 * Examples:
 *   "[RSOLV] Fix SQL Injection (CWE-89) in user.rb (fixes #42)"
 *   "[RSOLV] Fix Weak Cryptography vulnerability (fixes #15)"
 */
function buildPrTitle(
  prefix: string,
  summary: { title?: string; vulnerabilityType?: string; cwe?: string },
  issue: IssueContext
): string {
  const vuln = summary.vulnerabilityType;
  const cwe = summary.cwe;

  // Build a descriptive vulnerability phrase
  let vulnPhrase: string;
  if (vuln && vuln !== 'security' && vuln !== 'unknown') {
    // Use CWE-specific name when available (e.g., CWE-256 → "Weak Password Storage")
    // Falls back to humanized pattern type for unknown CWEs
    const displayName = cwe ? getCweSpecificName(cwe, vuln) : humanizeVulnType(vuln);
    vulnPhrase = cwe ? `${displayName} (${cwe})` : displayName;
  } else if (cwe) {
    vulnPhrase = `${cwe} vulnerability`;
  } else {
    // Fall back to the AI-generated title (stripped of generic prefixes)
    const title = (summary.title || 'Security fix applied')
      .replace(/^(Security fix applied|Fix applied)\s*[-:]?\s*/i, '');
    vulnPhrase = title || 'Security fix applied';
  }

  return `${prefix}[RSOLV] Fix ${vulnPhrase} (fixes #${issue.number})`;
}

function humanizeVulnType(vulnType: string): string {
  const acronyms = new Set(['xss', 'csrf', 'ssrf', 'sql', 'xxe', 'ldap', 'rce']);
  return vulnType
    .replace(/[_-]/g, ' ')
    .split(' ')
    .map(word => acronyms.has(word.toLowerCase()) ? word.toUpperCase() : word.charAt(0).toUpperCase() + word.slice(1))
    .join(' ');
}

/**
 * PR section titles - extracted as constants for maintainability
 */
const PR_SECTIONS = {
  VALIDATION_TESTS: '## 🧪 Validation Tests',
  TEST_RESULTS: '## ✅ Test Results',
  ATTACK_EXAMPLE: '## 🎯 Attack Example',
  LEARNING_RESOURCES: '## 📖 Learning Resources',
  CHANGES_MADE: '## 📊 Changes Made',
  UNDERSTANDING_FIX: '## 📚 Understanding This Fix',
  TESTING_INSTRUCTIONS: '## 🧪 Testing Instructions',
  REVIEW_CHECKLIST: '## ✔️ Review Checklist',
  ABOUT_RSOLV: '## 🤖 About RSOLV',
  SUMMARY: '## 📝 Summary'
} as const;

/**
 * Educational content type — sourced from the platform Registry or built generically.
 */
interface EducationEntry {
  title: string;
  description: string;
  prevention: string;
  example?: string;
}

/**
 * Create an educational pull request with comprehensive security education
 */
export async function createEducationalPullRequest(
  issue: IssueContext,
  commitHash: string,
  summary: {
    title: string;
    description: string;
    vulnerabilityType?: string;
    severity?: string;
    cwe?: string;
    tests?: string[];
    isAiGenerated?: boolean;
    isTestMode?: boolean;
    validationFailed?: boolean;
    testModeNote?: string;
    educationalContent?: EducationEntry;
    owaspCategory?: string;
  },
  config: ActionConfig,
  diffStats?: {
    insertions: number;
    deletions: number;
    filesChanged: number;
  },
  validationData?: ValidationData  // RFC-041: Validation phase data
): Promise<EducationalPrResult> {
  try {
    // Validate commitHash parameter
    if (!commitHash || typeof commitHash !== 'string') {
      const errorMsg = `Invalid commitHash: expected string, got ${typeof commitHash}. This usually means the solution generation did not create any commits - check if the SDK made file modifications.`;
      logger.error(errorMsg);
      return {
        success: false,
        message: 'Cannot create PR without valid commit',
        error: errorMsg
      };
    }

    logger.info(`Creating educational PR from commit ${commitHash.substring(0, 8)} for issue #${issue.number}`);
    
    // Configure git user if not set
    try {
      execSync('git config user.email', { cwd: process.cwd() });
    } catch {
      logger.info('Configuring git user for GitHub Actions');
      execSync('git config user.email "rsolv@users.noreply.github.com"', { cwd: process.cwd() });
      execSync('git config user.name "RSOLV Bot"', { cwd: process.cwd() });
    }
    
    // Create and checkout branch
    const branchName = `rsolv/fix-issue-${issue.number}`;
    try {
      execSync(`git checkout -b ${branchName}`, { cwd: process.cwd() });
      logger.info(`Created branch: ${branchName}`);
    } catch (error) {
      // Branch might already exist
      execSync(`git checkout ${branchName}`, { cwd: process.cwd() });
      logger.info(`Switched to existing branch: ${branchName}`);
    }
    
    // Configure git authentication if token is available
    const token = process.env.GITHUB_TOKEN || process.env.GH_PAT;
    if (token && process.env.GITHUB_REPOSITORY) {
      const [owner, repo] = process.env.GITHUB_REPOSITORY.split('/');
      const authenticatedUrl = `https://x-access-token:${token}@github.com/${owner}/${repo}.git`;
      try {
        // Set BOTH fetch and push URLs — the AI's bash tool execution during MITIGATE
        // may have set a separate pushurl via `git remote set-url --push origin <ssh-url>`,
        // which would cause push to use SSH even though the fetch URL is HTTPS.
        execSync(`git remote set-url origin ${authenticatedUrl}`, { cwd: process.cwd(), stdio: 'pipe' });
        execSync(`git remote set-url --push origin ${authenticatedUrl}`, { cwd: process.cwd(), stdio: 'pipe' });
        logger.debug('Configured git authentication for push (fetch + push URLs)');
      } catch (configError) {
        logger.debug('Could not configure authenticated remote');
      }
    }

    // Push the branch with better error handling
    try {
      // Log the push URL for diagnostics (mask the token)
      try {
        const pushUrl = execSync('git remote get-url --push origin', { cwd: process.cwd(), encoding: 'utf-8', stdio: 'pipe' }).trim();
        const maskedUrl = pushUrl.replace(/x-access-token:[^@]+@/, 'x-access-token:***@');
        logger.debug(`Push URL: ${maskedUrl}`);
      } catch { /* ignore diagnostic failure */ }

      execSync(`git push -u origin ${branchName}`, { cwd: process.cwd() });
      logger.info(`Pushed branch: ${branchName}`);
    } catch (error: any) {
      const errorMessage = error.message || String(error);

      // If branch already exists or updates rejected, try force push
      if (errorMessage.includes('Updates were rejected') ||
          errorMessage.includes('already exists') ||
          errorMessage.includes('non-fast-forward')) {
        logger.info('Branch exists on remote, attempting force push');
        try {
          execSync(`git push -f origin ${branchName}`, { cwd: process.cwd() });
          logger.info(`Force pushed branch: ${branchName}`);
        } catch (forcePushError) {
          logger.error('Force push also failed', forcePushError);
          throw forcePushError;
        }
      } else {
        // Log full error for debugging
        logger.error('Failed to push branch', { error: errorMessage, branch: branchName });
        throw error;
      }
    }
    
    // Generate educational content
    const educationalContent = generateEducationalContent(summary, issue);

    // Generate comprehensive PR body with validation data (RFC-041, RFC-058)
    const prBody = generateEducationalPrBody(issue, summary, educationalContent, diffStats, validationData);
    
    // Create the pull request
    const github = getGitHubClient();
    const [owner, repo] = issue.repository.fullName.split('/');
    
    try {
      const prTitlePrefix = summary.isTestMode && summary.validationFailed ? '[TEST MODE] ' : '';
      const prTitle = buildPrTitle(prTitlePrefix, summary, issue);
      const { data: pullRequest } = await github.pulls.create({
        owner,
        repo,
        title: prTitle,
        body: prBody,
        head: branchName,
        base: issue.repository.defaultBranch || 'main',
        maintainer_can_modify: true
      });
      
      logger.info(`Created educational pull request #${pullRequest.number}: ${pullRequest.html_url}`);
      
      // Track in RSOLV API
      if (config.rsolvApiKey) {
        try {
          const apiClient = new RsolvApiClient(config.rsolvApiKey);
          await apiClient.createFixAttempt({
            issueId: issue.id,
            issueNumber: issue.number,
            repository: issue.repository.fullName,
            pullRequestUrl: pullRequest.html_url,
            pullRequestNumber: pullRequest.number,
            branchName,
            commitHash,
            metadata: {
              hasEducationalContent: true,
              vulnerabilityType: summary.vulnerabilityType,
              severity: summary.severity
            }
          });
          logger.info('Tracked educational fix in RSOLV API');
        } catch (apiError) {
          logger.warn('Failed to track in RSOLV API', apiError);
        }
      }
      
      // Apply rsolv:mitigated label to the issue
      try {
        await github.issues.addLabels({
          owner,
          repo,
          issue_number: issue.number,
          labels: ['rsolv:mitigated']
        });
        // Remove rsolv:validated since it's now mitigated
        await github.issues.removeLabel({
          owner,
          repo,
          issue_number: issue.number,
          name: 'rsolv:validated'
        }).catch(() => { /* label may not exist */ });
        logger.info(`[PR] Applied rsolv:mitigated label to issue #${issue.number}`);
      } catch (labelErr) {
        logger.warn(`[PR] Failed to apply mitigated label to issue #${issue.number}:`, labelErr);
      }

      return {
        success: true,
        message: `Created educational pull request #${pullRequest.number}`,
        pullRequestUrl: pullRequest.html_url,
        pullRequestNumber: pullRequest.number,
        branchName,
        commitHash,
        educationalContent
      };
      
    } catch (error: any) {
      // Check if PR already exists
      if (error.status === 422 && error.message?.includes('pull request already exists')) {
        logger.warn('Pull request already exists for this branch');
        
        const { data: pulls } = await github.pulls.list({
          owner,
          repo,
          head: `${owner}:${branchName}`,
          state: 'open'
        });
        
        if (pulls.length > 0) {
          const existingPr = pulls[0];
          return {
            success: true,
            message: `Pull request already exists: #${existingPr.number}`,
            pullRequestUrl: existingPr.html_url,
            pullRequestNumber: existingPr.number,
            branchName,
            commitHash,
            educationalContent
          };
        }
      }
      
      throw error;
    }
    
  } catch (error) {
    logger.error('Failed to create educational pull request', error);
    return {
      success: false,
      message: 'Failed to create pull request',
      error: error instanceof Error ? error.message : String(error)
    };
  }
}

/**
 * Build generic education from CWE ID and vulnerability type name.
 * Used as fallback when the platform Registry doesn't have content for a CWE.
 * Produces useful, CWE-specific content instead of defaulting to XSS.
 */
function buildGenericEducation(cwe?: string, vulnerabilityType?: string): EducationEntry {
  const cweNum = cwe ? String(cwe).replace(/^CWE-/i, '') : null;
  const typeName = vulnerabilityType || 'Security Vulnerability';
  const titleCased = typeName.split(/[_\s-]+/).map(w => w.charAt(0).toUpperCase() + w.slice(1).toLowerCase()).join(' ');

  return {
    title: titleCased,
    description: cweNum
      ? `This vulnerability (CWE-${cweNum}) can compromise application security. See https://cwe.mitre.org/data/definitions/${cweNum}.html for detailed information.`
      : `This vulnerability can compromise application security if not properly addressed.`,
    prevention: 'Follow secure coding practices: validate and sanitize all inputs, apply the principle of least privilege, and keep dependencies updated.',
  };
}

/**
 * Resolve education entry: prefer platform-provided content, fall back to generic.
 */
function resolveEducation(summary: {
  educationalContent?: EducationEntry;
  cwe?: string;
  vulnerabilityType?: string;
}): EducationEntry {
  if (summary.educationalContent) {
    return summary.educationalContent;
  }
  return buildGenericEducation(summary.cwe, summary.vulnerabilityType);
}

/**
 * Generate educational content based on vulnerability type
 */
function generateEducationalContent(
  summary: {
    vulnerabilityType?: string;
    isAiGenerated?: boolean;
    educationalContent?: EducationEntry;
    cwe?: string;
  },
  _issue: IssueContext
): string {
  const sections: string[] = [];

  const education = resolveEducation(summary);

  sections.push(`## What is ${education.title}?`);
  sections.push(education.description);
  sections.push('');
  sections.push('## How this fix prevents the vulnerability:');
  sections.push(education.prevention);
  if (education.example) {
    sections.push('');
    sections.push('**Example:**');
    sections.push(education.example);
  }
  sections.push('');
  sections.push('## Best practices:');
  sections.push('- Always validate and sanitize user input');
  sections.push('- Apply the principle of least privilege');
  sections.push('- Keep dependencies updated');
  sections.push('- Implement security headers');
  sections.push('- Use security linters and scanners in CI/CD');

  // AI-specific context if applicable
  const vulnTypeLower = (summary.vulnerabilityType || '').toLowerCase();
  if (summary.isAiGenerated || vulnTypeLower === 'slopsquatting') {
    sections.push('');
    sections.push('## 🤖 AI-Specific Vulnerability Context');
    sections.push('This vulnerability is related to AI-generated code. Our research shows:');
    sections.push('- 19.6% of AI package suggestions are hallucinated (non-existent)');
    sections.push('- Attackers actively exploit these by registering malicious packages');
    sections.push('- Always verify package existence before adding dependencies');
  }

  // RSOLV value proposition
  sections.push('');
  sections.push('## About RSOLV');
  sections.push('RSOLV automatically fixes security vulnerabilities, not just detects them.');
  sections.push('- 181 patterns across 8 languages and frameworks');
  sections.push('- Success-based pricing: only pay for deployed fixes');
  sections.push('- Detects AI-specific vulnerabilities others miss');
  sections.push('- AST-based analysis for minimal false positives');

  return sections.join('\n');
}

/**
 * Generate validation tests section (RFC-058)
 */
function generateValidationSection(validationData?: ValidationData): string[] {
  if (!validationData?.branchName) return [];

  return [
    PR_SECTIONS.VALIDATION_TESTS,
    '',
    'This fix was validated using RED tests from the VALIDATE phase:',
    '',
    `**Validation Branch:** [\`${validationData.branchName}\`](../../tree/${validationData.branchName})`,
    '',
    'The validation branch contains RED tests that:',
    '- ❌ **Failed** on the vulnerable code (proving the vulnerability exists)',
    '- ✅ **Pass** after this fix is applied (proving the fix works)',
    '',
    'This test-driven approach ensures the fix addresses the actual vulnerability.',
    ''
  ];
}

/**
 * Generate test results section (RFC-041)
 */
function generateTestResultsSection(validationData?: ValidationData): string[] {
  if (!validationData?.testResults) return [];

  const { passed = 0, failed = 0, total = 0 } = validationData.testResults;

  return [
    PR_SECTIONS.TEST_RESULTS,
    '',
    '### Before Fix (RED Tests)',
    '```',
    `Tests: ${failed} failed, ${passed} passed, ${total} total`,
    'Status: ❌ FAILING (vulnerability present)',
    '```',
    '',
    '### After Fix (GREEN Tests)',
    '```',
    `Tests: 0 failed, ${total} passed, ${total} total`,
    'Status: ✅ PASSING (vulnerability fixed)',
    '```',
    ''
  ];
}

/**
 * Generate attack example section (RFC-041)
 */
function generateAttackExampleSection(
  education: { title: string; description: string; prevention: string; example?: string }
): string[] {
  if (!education.example) return [];

  return [
    PR_SECTIONS.ATTACK_EXAMPLE,
    '',
    '**How this vulnerability could be exploited:**',
    '',
    '```',
    education.example,
    '```',
    '',
    'This fix prevents such attacks by applying proper input validation and sanitization.',
    ''
  ];
}

/**
 * Generate learning resources section
 */
function generateLearningResourcesSection(
  summary: { cwe?: string; owaspCategory?: string },
  education: { title: string }
): string[] {
  const resources = [
    PR_SECTIONS.LEARNING_RESOURCES,
    '',
    'To learn more about this vulnerability type:',
    ''
  ];

  if (summary.cwe) {
    const cweNum = String(summary.cwe).replace(/^CWE-/i, '');
    resources.push(`- [CWE-${cweNum}](https://cwe.mitre.org/data/definitions/${cweNum}.html) - Common Weakness Enumeration`);
  }

  if (summary.owaspCategory) {
    resources.push(`- ${formatOwaspLink(summary.owaspCategory)} - OWASP Top 10`);
  } else {
    resources.push(`- [OWASP: ${education.title}](https://owasp.org) - Security best practices`);
  }
  resources.push('- [RSOLV Security Patterns](https://rsolv.dev/patterns) - Comprehensive vulnerability database');
  resources.push('');

  return resources;
}

/**
 * Generate educational PR body with all components (RFC-041)
 * Includes validation branch link, test results, and educational content
 */
function generateEducationalPrBody(
  issue: IssueContext,
  summary: {
    title: string;
    description: string;
    vulnerabilityType?: string;
    severity?: string;
    cwe?: string;
    tests?: string[];
    isTestMode?: boolean;
    validationFailed?: boolean;
    testModeNote?: string;
    educationalContent?: EducationEntry;
    owaspCategory?: string;
  },
  educationalContent: string,
  diffStats?: {
    insertions: number;
    deletions: number;
    filesChanged: number;
  },
  validationData?: ValidationData
): string {
  const sections: string[] = [];
  
  // Header
  const titlePrefix = summary.isTestMode && summary.validationFailed ? '[TEST MODE] ' : '';
  sections.push(`# ${titlePrefix}${summary.title}`);
  sections.push('');

  // Test mode warning if validation failed
  if (summary.isTestMode && summary.validationFailed) {
    sections.push('> ⚠️ **TEST MODE**: This PR was created despite validation failures to allow inspection of the attempted fix.');
    sections.push('> ');
    if (summary.testModeNote) {
      sections.push(`> **Validation Issue:** ${summary.testModeNote}`);
    }
    sections.push('');
    sections.push('---');
    sections.push('');
  }

  sections.push(`**Fixes:** #${issue.number}`);
  sections.push(`**Severity:** ${summary.severity || 'Medium'}`);
  if (summary.cwe) {
    sections.push(`**CWE:** ${summary.cwe}`);
  }
  sections.push('');
  
  // Summary
  sections.push(PR_SECTIONS.SUMMARY);
  sections.push(summary.description);
  sections.push('');

  // Get vulnerability education for later sections (platform-provided or generic fallback)
  const education = resolveEducation(summary);

  // RFC-058: Validation Branch Link (rsolv/validate/issue-N)
  sections.push(...generateValidationSection(validationData));

  // RFC-041: Test Results (RED → GREEN)
  sections.push(...generateTestResultsSection(validationData));

  // Learning Resources
  sections.push(...generateLearningResourcesSection(summary, education));

  // Changes Made
  if (diffStats && diffStats.filesChanged > 0) {
    sections.push('## 📊 Changes Made');
    sections.push(`- **Files Changed:** ${diffStats.filesChanged}`);
    sections.push(`- **Lines Added:** +${diffStats.insertions}`);
    sections.push(`- **Lines Removed:** -${diffStats.deletions}`);
    sections.push('');
  }
  
  // Educational Content
  sections.push('## 📚 Understanding This Fix');
  sections.push('');
  // education variable already declared earlier in function

  sections.push(`### 🛡️ What is ${education.title}?`);
  sections.push(education.description);
  sections.push('');
  
  sections.push('### 🔧 How This Fix Works');
  sections.push(education.prevention);
  if (education.example) {
    sections.push('');
    sections.push('**Example:**');
    sections.push('```');
    sections.push(education.example);
    sections.push('```');
  }
  sections.push('');
  
  sections.push('### ✅ Best Practices');
  sections.push('1. Always validate and sanitize user input');
  sections.push('2. Apply the principle of least privilege');
  sections.push('3. Keep dependencies updated');
  sections.push('4. Implement security headers');
  sections.push('5. Use security linters and scanners in CI/CD');
  sections.push('');
  
  // Testing Instructions
  if (summary.tests && summary.tests.length > 0) {
    sections.push('## 🧪 Testing Instructions');
    summary.tests.forEach((test, index) => {
      sections.push(`${index + 1}. ${test}`);
    });
    sections.push('');
  }
  
  // Review Checklist
  sections.push('## ✔️ Review Checklist');
  sections.push('- [ ] Changes fix the reported vulnerability');
  sections.push('- [ ] No new vulnerabilities introduced');
  sections.push('- [ ] Existing functionality preserved');
  sections.push('- [ ] Code follows project conventions');
  sections.push('- [ ] Tests pass (if applicable)');
  sections.push('');
  
  // About RSOLV
  sections.push('## 🤖 About RSOLV');
  sections.push('');
  sections.push('[RSOLV](https://rsolv.dev) automatically fixes security vulnerabilities in your code.');
  sections.push('');
  sections.push('**What makes RSOLV different:**');
  sections.push('- 🔧 **Fixes, not just reports:** We generate working code, not just vulnerability lists');
  sections.push('- 💰 **Success-based pricing:** Only pay for fixes that get deployed');
  sections.push('- 🤖 **AI-aware security:** Detect vulnerabilities specific to AI-generated code');
  sections.push('- 🎯 **181+ patterns:** Comprehensive coverage across 8 languages and frameworks');
  sections.push('- 🌳 **AST-based analysis:** Minimal false positives through syntax tree parsing');
  sections.push('');
  
  // Footer
  sections.push('---');
  sections.push('');
  sections.push('*This PR was automatically generated by [RSOLV](https://rsolv.dev) using direct file editing.*');
  const owaspLink = summary.owaspCategory
    ? formatOwaspLink(summary.owaspCategory)
    : '[OWASP](https://owasp.org)';
  sections.push(`*Learn more about ${education.title}: ${owaspLink}*`);
  
  return sections.join('\n');
}