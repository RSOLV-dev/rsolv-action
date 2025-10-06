/**
 * Mitigation Mode Implementation
 * RFC-041: Generate fixes for validated vulnerabilities
 * RFC-058: Support validation branch checkout for test-aware fix generation
 * RFC-060: Use PhaseDataClient API instead of local file reads
 */

import { IssueContext, ActionConfig } from '../types/index.js';
import { logger } from '../utils/logger.js';
import { execSync } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import { PhaseDataClient } from './phase-data-client/index.js';

export class MitigationMode {
  private config: ActionConfig;
  private repoPath: string;
  private phaseClient: PhaseDataClient;
  private commitSha: string;

  constructor(config: ActionConfig, repoPath?: string, phaseClient?: PhaseDataClient) {
    this.config = config;
    this.repoPath = repoPath || process.cwd();

    // RFC-060: Use PhaseDataClient for validation metadata retrieval
    this.phaseClient = phaseClient || new PhaseDataClient(
      config.apiKey,
      process.env.RSOLV_API_URL
    );

    // Get current commit SHA for phase data retrieval
    this.commitSha = this.getCurrentCommitSha();
  }

  /**
   * Get current commit SHA
   */
  private getCurrentCommitSha(): string {
    try {
      return execSync('git rev-parse HEAD', {
        cwd: this.repoPath,
        encoding: 'utf8'
      }).trim();
    } catch (error) {
      logger.warn(`Could not get current commit SHA: ${error}`);
      return 'unknown';
    }
  }

  /**
   * RFC-058/RFC-060: Checkout validation branch for mitigation phase
   * Uses PhaseDataClient API instead of local file reads
   */
  async checkoutValidationBranch(issue: IssueContext): Promise<boolean> {
    try {
      // RFC-060: Retrieve validation results from PhaseDataClient API
      const phaseData = await this.phaseClient.retrievePhaseResults(
        this.config.repo,
        issue.number,
        this.commitSha
      );

      if (!phaseData?.validate) {
        logger.info('No validation results found in API, staying on current branch');
        return false;
      }

      // Extract validation data for this issue
      const issueKey = `issue-${issue.number}`;
      const validationData = phaseData.validate[issueKey];

      if (!validationData) {
        logger.info(`No validation data found for ${issueKey}, staying on current branch`);
        return false;
      }

      // Check if validation produced a branch
      const branchName = validationData.branchName;
      if (!branchName) {
        logger.info('No validation branch found in API metadata, staying on current branch');
        return false;
      }

      try {
        // First try to fetch the branch from remote
        try {
          execSync(`git fetch origin ${branchName}`, { cwd: this.repoPath });
          logger.info(`Fetched validation branch from remote: ${branchName}`);
        } catch (fetchError) {
          logger.warn(`Could not fetch validation branch from remote: ${fetchError}`);
        }

        // Try to checkout the branch (local or remote)
        try {
          // First try local branch
          execSync(`git checkout ${branchName}`, { cwd: this.repoPath });
          logger.info(`Checked out local validation branch: ${branchName}`);
          return true;
        } catch {
          // If local doesn't exist, try remote
          try {
            execSync(`git checkout -b ${branchName} origin/${branchName}`, { cwd: this.repoPath });
            logger.info(`Checked out remote validation branch: origin/${branchName}`);
            return true;
          } catch (remoteError) {
            logger.warn(`Failed to checkout validation branch from remote: ${remoteError}`);
            return false;
          }
        }
      } catch (error) {
        logger.warn(`Failed to checkout validation branch: ${error}`);
        return false;
      }
    } catch (error) {
      logger.error(`Error checking out validation branch for issue #${issue.number}:`, error);
      return false;
    }
  }

  /**
   * RFC-058/RFC-060: Get validation tests from PhaseDataClient
   * Returns test content from validation metadata instead of reading local files
   */
  async getValidationTests(issue: IssueContext): Promise<Array<{path: string, content: string}>> {
    try {
      // RFC-060: Retrieve validation results from PhaseDataClient API
      const phaseData = await this.phaseClient.retrievePhaseResults(
        this.config.repo,
        issue.number,
        this.commitSha
      );

      if (!phaseData?.validate) {
        logger.info('No validation results found in API');
        return [];
      }

      // Extract validation data for this issue
      const issueKey = `issue-${issue.number}`;
      const validationData = phaseData.validate[issueKey];

      if (!validationData?.testResults?.generatedTests) {
        logger.info('No generated tests found in validation metadata');
        return [];
      }

      // Extract RED test content from validation metadata
      const tests = [];
      const generatedTests = validationData.testResults.generatedTests;

      if (generatedTests.red) {
        tests.push({
          path: `.rsolv/tests/validation-${issue.number}-red.test.js`,
          content: generatedTests.red.testCode || ''
        });
      }

      if (generatedTests.green) {
        tests.push({
          path: `.rsolv/tests/validation-${issue.number}-green.test.js`,
          content: generatedTests.green.testCode || ''
        });
      }

      if (generatedTests.refactor) {
        tests.push({
          path: `.rsolv/tests/validation-${issue.number}-refactor.test.js`,
          content: generatedTests.refactor.testCode || ''
        });
      }

      logger.info(`Retrieved ${tests.length} validation tests from API metadata`);
      return tests;

    } catch (error) {
      logger.warn(`Could not retrieve validation tests from API: ${error}`);
      return [];
    }
  }

  /**
   * RFC-058/RFC-060: Generate test-aware mitigation with enhanced Claude Code prompt
   * Uses PhaseDataClient API for test retrieval
   */
  async generateTestAwareFix(issue: IssueContext): Promise<any> {
    try {
      // Step 1: Checkout validation branch
      const branchCheckedOut = await this.checkoutValidationBranch(issue);

      // Step 2: Get validation tests from API (no file reading needed)
      const testContents = await this.getValidationTests(issue);

      // Step 3: Generate enhanced prompt with test context
      const enhancedPrompt = this.buildTestAwarePrompt(issue, testContents);

      logger.info(`Generated test-aware mitigation prompt for issue #${issue.number}`);
      logger.info(`- Validation branch: ${branchCheckedOut ? 'checked out' : 'not available'}`);
      logger.info(`- Test files found: ${testContents.length}`);

      return {
        branchCheckedOut,
        testFilesFound: testContents.length,
        enhancedPrompt,
        testContents
      };

    } catch (error) {
      logger.error(`Test-aware fix generation failed for issue #${issue.number}:`, error);
      throw error;
    }
  }

  /**
   * RFC-058: Build enhanced Claude Code prompt with test specifications
   */
  private buildTestAwarePrompt(issue: IssueContext, testContents: Array<{path: string, content: string}>): string {
    const basePrompt = `
Fix the security vulnerability described in issue #${issue.number}: "${issue.title}"

Issue Description:
${issue.body}
`;

    if (testContents.length === 0) {
      logger.info('No validation tests found, using standard prompt');
      return basePrompt;
    }

    const testSection = `
VALIDATION TESTS AVAILABLE:
The following tests define the expected behavior and vulnerability patterns.
These tests currently FAIL on the vulnerable code and should PASS after your fix:

${testContents.map(test => `
File: ${test.path}
\`\`\`javascript
${test.content}
\`\`\`
`).join('\n')}

REQUIREMENTS:
1. Your fix must make these tests pass
2. Preserve all existing behavioral contracts tested
3. Make minimal, incremental changes
4. You can run these tests locally to validate your fix using: npm test

`;

    return basePrompt + testSection;
  }

  /**
   * RFC-058: Get current git branch for PR creation
   */
  getCurrentBranch(): string {
    try {
      return execSync('git branch --show-current', {
        cwd: this.repoPath,
        encoding: 'utf8'
      }).trim();
    } catch (error) {
      logger.warn(`Could not get current branch: ${error}`);
      return 'main';
    }
  }

  /**
   * RFC-058: Create PR from validation branch with tests + fixes
   */
  async createPRFromValidationBranch(issue: IssueContext): Promise<any> {
    try {
      const currentBranch = this.getCurrentBranch();

      // Ensure we're on a validation branch
      if (!currentBranch.startsWith('rsolv/validate/')) {
        logger.warn(`Not on validation branch (${currentBranch}), cannot create PR with tests`);
        return { success: false, reason: 'Not on validation branch' };
      }

      // Check if there are any changes to commit (after fix generation)
      const status = execSync('git status --porcelain', {
        cwd: this.repoPath,
        encoding: 'utf8'
      });

      if (status.trim()) {
        // Commit the fix
        execSync('git add .', { cwd: this.repoPath });
        execSync(`git commit -m "Fix vulnerability for issue #${issue.number}\n\n✅ Generated with RSOLV three-phase workflow\n🧪 Includes validation tests from ${currentBranch}"`, {
          cwd: this.repoPath
        });
        logger.info(`Committed fix to validation branch: ${currentBranch}`);
      }

      // Create PR (using GitHub CLI if available)
      const prTitle = `🔒 Fix security vulnerability: ${issue.title}`;
      const prBody = `
## Security Fix for Issue #${issue.number}

**Vulnerability**: ${issue.title}

### 📋 Changes Made
- Fixed security vulnerability identified in issue #${issue.number}
- Generated using RSOLV three-phase workflow (Scan → Validate → Mitigate)

### 🧪 Validation Tests Included
This PR includes validation tests that:
- ✅ Prove the vulnerability existed (red tests)
- ✅ Verify the fix resolves the issue (green tests)
- ✅ Prevent regression

### 🔧 Test-Aware Fix Generation
The fix was generated using AI with access to validation tests, ensuring:
- Behavioral contracts are preserved
- Minimal, focused changes
- Test-driven approach

**Branch**: \`${currentBranch}\`
**Issue**: #${issue.number}

---
🤖 Generated with [RSOLV](https://rsolv.app) - AI-powered vulnerability remediation
      `.trim();

      logger.info(`Creating PR from validation branch: ${currentBranch}`);
      logger.info(`PR Title: ${prTitle}`);

      return {
        success: true,
        branch: currentBranch,
        title: prTitle,
        body: prBody,
        hasTests: true,
        message: `PR ready to be created from validation branch ${currentBranch}`
      };

    } catch (error) {
      logger.error(`Failed to create PR from validation branch:`, error);
      return { success: false, error: error instanceof Error ? error.message : String(error) };
    }
  }
}