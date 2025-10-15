/**
 * Mitigation Mode Implementation
 * RFC-041: Generate fixes for validated vulnerabilities
 * RFC-058: Support validation branch checkout for test-aware fix generation
 * RFC-060: Use PhaseDataClient for validation metadata (no local file reads)
 */

import { IssueContext, ActionConfig } from '../types/index.js';
import { logger } from '../utils/logger.js';
import { vendorFilterUtils } from './vendor-utils.js';
import { execSync, exec } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import { PhaseDataClient } from './phase-data-client/index.js';
import { TestRunner } from '../services/test-runner.js';
import { buildTestAwarePrompt as buildPromptFromTemplate, getTrustScoreExplanation } from '../prompts/test-aware-mitigation.js';

export class MitigationMode {
  private config: ActionConfig;
  private repoPath: string;
  private phaseDataClient?: PhaseDataClient;

  constructor(config: ActionConfig, repoPath?: string, phaseDataClient?: PhaseDataClient) {
    this.config = config;
    this.repoPath = repoPath || process.cwd();
    this.phaseDataClient = phaseDataClient;

    // Apply environment variables from config
    if (config.environmentVariables && typeof config.environmentVariables === 'object') {
      Object.entries(config.environmentVariables).forEach(([key, value]) => {
        if (typeof value === 'string') {
          process.env[key] = value;
          logger.debug(`Applied environment variable: ${key}`);
        }
      });
    }
  }

  /**
   * RFC-060: Get current git commit SHA
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
   * RFC-060: Retrieve validation branch name
   *
   * Explicit modes:
   * - WITH PhaseDataClient: API-only (production) - returns undefined if API fails
   * - WITHOUT PhaseDataClient: Local file only (testing) - reads .rsolv/validation/
   *
   * No silent fallback between modes - fail fast in production
   */
  private async getValidationBranchName(issue: IssueContext): Promise<string | undefined> {
    return this.phaseDataClient
      ? this.getFromApi(issue)
      : this.getFromLocalFile(issue);
  }

  private async getFromApi(issue: IssueContext): Promise<string | undefined> {
    try {
      const repo = `${issue.repository.owner}/${issue.repository.name}`;
      const phaseData = await this.phaseDataClient!.retrievePhaseResults(
        repo,
        issue.number,
        this.getCurrentCommitSha()
      );

      const branchName = phaseData?.validate?.[`issue-${issue.number}`]?.branchName;
      if (branchName) {
        logger.info(`Found validation branch via API: ${branchName}`);
      }
      return branchName;
    } catch (error) {
      logger.error(`API retrieval failed (production mode): ${error}`);
      return undefined;
    }
  }

  private getFromLocalFile(issue: IssueContext): string | undefined {
    try {
      const filePath = path.join(this.repoPath, '.rsolv', 'validation', `issue-${issue.number}.json`);
      if (!fs.existsSync(filePath)) return undefined;

      const data = JSON.parse(fs.readFileSync(filePath, 'utf8'));
      if (data.branchName) {
        logger.info(`Found validation branch in local file (testing mode): ${data.branchName}`);
      }
      return data.branchName;
    } catch (error) {
      logger.warn(`Local file read failed (testing mode): ${error}`);
      return undefined;
    }
  }

  /**
   * RFC-058/RFC-060: Checkout validation branch for mitigation phase
   * Uses API (production) or local files (testing) based on PhaseDataClient presence
   *
   * IMPORTANT: This method should NEVER create a branch. It only checks out existing branches.
   * Per RFC-060, validation branches are created by ValidationMode, not MitigationMode.
   */
  async checkoutValidationBranch(issue: IssueContext): Promise<boolean> {
    // Save current branch so we can restore it if checkout fails
    const originalBranch = this.getCurrentBranch();

    try {
      const branchName = await this.getValidationBranchName(issue);

      if (!branchName) {
        logger.info('No validation branch found, staying on current branch');
        return false;
      }

      // Check if branch exists locally
      const localBranchExists = this.doesLocalBranchExist(branchName);

      // Fetch the branch from remote (best effort)
      try {
        execSync(`git fetch origin ${branchName}`, { cwd: this.repoPath, stdio: 'pipe' });
        logger.info(`Fetched validation branch from remote: ${branchName}`);
      } catch (fetchError) {
        logger.debug(`Could not fetch validation branch from remote: ${fetchError}`);
      }

      // Check if branch exists on remote after fetch
      const remoteBranchExists = this.doesRemoteBranchExist(branchName);

      // If branch doesn't exist locally or remotely, return false without changing branches
      if (!localBranchExists && !remoteBranchExists) {
        logger.info(`Validation branch ${branchName} does not exist locally or remotely, staying on current branch`);
        return false;
      }

      // Try to checkout local branch first
      if (localBranchExists) {
        try {
          execSync(`git checkout ${branchName}`, { cwd: this.repoPath, stdio: 'pipe' });
          logger.info(`Checked out local validation branch: ${branchName}`);
          return true;
        } catch (checkoutError) {
          logger.warn(`Failed to checkout local branch ${branchName}: ${checkoutError}`);
          // Restore original branch
          try {
            execSync(`git checkout ${originalBranch}`, { cwd: this.repoPath, stdio: 'pipe' });
          } catch {
            // Ignore restoration errors
          }
        }
      }

      // If local checkout failed or branch not local, try remote
      if (remoteBranchExists) {
        try {
          execSync(`git checkout -b ${branchName} origin/${branchName}`, { cwd: this.repoPath, stdio: 'pipe' });
          logger.info(`Checked out remote validation branch: origin/${branchName}`);
          return true;
        } catch (remoteError) {
          logger.warn(`Failed to checkout validation branch from remote: ${remoteError}`);
          // Restore original branch
          try {
            execSync(`git checkout ${originalBranch}`, { cwd: this.repoPath, stdio: 'pipe' });
          } catch {
            // Ignore restoration errors
          }
          return false;
        }
      }

      return false;
    } catch (error) {
      logger.error(`Error checking out validation branch for issue #${issue.number}:`, error);
      // Restore original branch on any error
      try {
        execSync(`git checkout ${originalBranch}`, { cwd: this.repoPath, stdio: 'pipe' });
      } catch {
        // Ignore restoration errors
      }
      return false;
    }
  }

  /**
   * Check if a branch exists locally
   */
  private doesLocalBranchExist(branchName: string): boolean {
    try {
      const branches = execSync('git branch --list', { cwd: this.repoPath, encoding: 'utf8' })
        .split('\n')
        .map(b => b.trim().replace(/^\*\s+/, ''));
      return branches.includes(branchName);
    } catch (error) {
      logger.debug(`Error checking local branches: ${error}`);
      return false;
    }
  }

  /**
   * Check if a branch exists on remote
   */
  private doesRemoteBranchExist(branchName: string): boolean {
    try {
      const remoteBranches = execSync('git branch -r', { cwd: this.repoPath, encoding: 'utf8', stdio: 'pipe' })
        .split('\n')
        .map(b => b.trim().replace(/^origin\//, ''));
      return remoteBranches.includes(branchName);
    } catch (error) {
      logger.debug(`Error checking remote branches: ${error}`);
      return false;
    }
  }

  /**
   * RFC-058: Get validation tests from current branch
   */
  async getValidationTests(issue: IssueContext): Promise<string[]> {
    const testDir = path.join(this.repoPath, '.rsolv', 'tests');

    if (!fs.existsSync(testDir)) {
      return [];
    }

    // Return all test files in the validation branch
    try {
      return fs.readdirSync(testDir)
        .filter(file => file.endsWith('.test.js'))
        .map(file => path.join(testDir, file));
    } catch (error) {
      logger.warn(`Could not read test directory: ${error}`);
      return [];
    }
  }

  /**
   * RFC-058: Generate test-aware mitigation with enhanced Claude Code prompt
   */
  async generateTestAwareFix(issue: IssueContext): Promise<any> {
    try {
      // Step 0: Check if this is a vendor file vulnerability
      const vendorCheckResult = vendorFilterUtils.checkVendorStatusFromValidation(this.repoPath, issue.number);
      if (vendorCheckResult.isVendor) {
        return {
          skipReason: 'vendor_file',
          message: 'Cannot patch vendor library - update required',
          vendorFiles: vendorCheckResult.files,
          branchCheckedOut: false,
          testFilesFound: 0,
          enhancedPrompt: undefined
        };
      }

      // Step 1: Checkout validation branch
      const branchCheckedOut = await this.checkoutValidationBranch(issue);

      // Step 2: Get validation tests
      const testFiles = await this.getValidationTests(issue);

      // Step 3: Read test content
      const testContents = testFiles.map(file => {
        try {
          return {
            path: file,
            content: fs.readFileSync(file, 'utf-8')
          };
        } catch (error) {
          logger.warn(`Could not read test file ${file}:`, error);
          return null;
        }
      }).filter(Boolean);

      // Step 4: Generate enhanced prompt with test context
      const enhancedPrompt = this.buildLegacyTestAwarePrompt(issue, testContents as Array<{path: string, content: string}>);

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
   * RFC-060 Phase 3.2: Prepare test context from validation branch
   */
  async prepareTestContext(issueId: string): Promise<{testContent: string, testPath: string, branchName: string}> {
    if (!this.phaseDataClient) {
      throw new Error('PhaseDataClient not configured for test-aware mitigation');
    }

    // Get test info from Phase Data Client
    const testInfo = await this.phaseDataClient.getPhaseTestInfo(issueId);

    // Checkout validation branch
    logger.info(`Checking out validation branch: ${testInfo.branchName}`);
    await new Promise<void>((resolve, reject) => {
      exec(`git checkout ${testInfo.branchName}`, (error: any) => {
        if (error) {
          reject(error);
        } else {
          resolve();
        }
      });
    });

    // Read test file from git
    const testContent = fs.readFileSync(testInfo.testPath, 'utf-8');

    return {
      testContent,
      testPath: testInfo.testPath,
      branchName: testInfo.branchName
    };
  }

  /**
   * RFC-060 Phase 3.2: Build test-aware prompt with RED test content
   */
  async buildTestAwarePrompt(issueId: string, basePrompt: string): Promise<string> {
    const context = await this.prepareTestContext(issueId);

    // Use the template function from prompts module
    return buildPromptFromTemplate(
      {
        issueId,
        title: '', // Will be in basePrompt
        description: ''
      },
      {
        testPath: context.testPath,
        testContent: context.testContent
      },
      basePrompt
    );
  }

  /**
   * RFC-060 Phase 3.2: Run test before applying fix
   */
  async runPreFixTest(issueId: string): Promise<{passed: boolean, output: string}> {
    return this.runTestForIssue(issueId);
  }

  /**
   * RFC-060 Phase 3.2: Run test after applying fix
   */
  async runPostFixTest(issueId: string): Promise<{passed: boolean, output: string}> {
    return this.runTestForIssue(issueId);
  }

  /**
   * Shared test execution logic
   */
  private async runTestForIssue(issueId: string): Promise<{passed: boolean, output: string}> {
    if (!this.phaseDataClient) {
      throw new Error('PhaseDataClient not configured');
    }

    const testInfo = await this.phaseDataClient.getPhaseTestInfo(issueId);
    const testRunner = new TestRunner();

    return await testRunner.runTest(testInfo.command);
  }

  /**
   * RFC-060 Phase 3.2: Save test results to PhaseDataClient
   */
  async saveTestResults(results: any): Promise<void> {
    if (!this.phaseDataClient) {
      throw new Error('PhaseDataClient not configured');
    }

    await this.phaseDataClient.saveTestResults(results);
  }

  /**
   * RFC-060 Phase 3.2: Calculate trust score based on test results
   */
  async calculateTrustScore(preTestPassed: boolean, postTestPassed: boolean): Promise<number> {
    // Trust score calculation logic:
    // - Both fail = 0 (fix didn't work)
    // - Before fail, after pass = 100 (perfect fix)
    // - Before pass, after pass = 50 (test issue or false positive)
    // - Before pass, after fail = 0 (broke something)

    if (!preTestPassed && postTestPassed) {
      return 100; // Perfect fix
    } else if (preTestPassed && postTestPassed) {
      return 50; // Test might have been passing already (false positive)
    } else {
      return 0; // Fix didn't work or broke something
    }
  }

  /**
   * RFC-060 Phase 3.2: Run test with error handling
   */
  async runTestSafely(issueId: string): Promise<{passed: boolean, output?: string, error?: string}> {
    try {
      return await this.runTestForIssue(issueId);
    } catch (error: any) {
      return {
        passed: false,
        error: error.message
      };
    }
  }

  /**
   * RFC-058: Build enhanced Claude Code prompt with test specifications (legacy)
   */
  private buildLegacyTestAwarePrompt(issue: IssueContext, testContents: Array<{path: string, content: string}>): string {
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