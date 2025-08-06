/**
 * Phase Executor - Decomposes existing fix mode into reusable phases
 * RFC-041: Three-Phase Architecture
 * 
 * This module extracts and refactors functionality from git-based-processor.ts
 * to enable independent execution of validation and mitigation phases
 */

import { IssueContext, ActionConfig } from '../types/index.js';
import { logger } from '../utils/logger.js';
import { ValidationResult, MitigationResult } from './types.js';
import { analyzeIssue } from '../ai/analyzer.js';
import { TestGeneratingSecurityAnalyzer, AnalysisWithTestsResult } from '../ai/test-generating-security-analyzer.js';
import { GitBasedTestValidator } from '../ai/git-based-test-validator.js';
import { GitBasedClaudeCodeAdapter } from '../ai/adapters/claude-code-git.js';
import { createEducationalPullRequest } from '../github/pr-git-educational.js';
import { AIConfig, IssueAnalysis } from '../ai/types.js';
import { getMaxIterations, checkGitStatus } from '../ai/git-based-processor.js';
import * as fs from 'fs';
import * as path from 'path';
import { execSync } from 'child_process';

export class PhaseExecutor {
  private config: ActionConfig;
  
  constructor(config: ActionConfig) {
    this.config = config;
  }
  
  /**
   * Phase 1: Analyze Issue (shared by validation and mitigation)
   * Extracted from processIssueWithGit Step 2
   */
  async analyzePhase(issue: IssueContext): Promise<any> {
    logger.info(`[PHASE: ANALYZE] Analyzing issue #${issue.number}`);
    
    // Ensure clean git state
    const gitStatus = checkGitStatus();
    if (!gitStatus.clean) {
      throw new Error(`Repository has uncommitted changes: ${gitStatus.modifiedFiles.join(', ')}`);
    }
    
    const analysisData = await analyzeIssue(issue, this.config);
    
    if (!analysisData || !analysisData.canBeFixed) {
      throw new Error(`Issue cannot be automatically fixed: ${analysisData?.cannotFixReason || 'Unknown reason'}`);
    }
    
    return analysisData;
  }
  
  /**
   * Phase 2: Generate Tests (validation phase)
   * Extracted from processIssueWithGit Step 2.5
   */
  async generateTestsPhase(
    issue: IssueContext, 
    analysisData: any
  ): Promise<AnalysisWithTestsResult | undefined> {
    logger.info(`[PHASE: TEST GENERATION] Generating tests for issue #${issue.number}`);
    
    if (!this.config.enableSecurityAnalysis) {
      logger.info('Security analysis disabled, skipping test generation');
      return undefined;
    }
    
    // Build AI config (same as original)
    const aiConfig: AIConfig = {
      provider: 'anthropic',
      apiKey: this.config.aiProvider.apiKey,
      model: this.config.aiProvider.model,
      temperature: 0.2,
      maxTokens: this.config.aiProvider.maxTokens,
      useVendedCredentials: this.config.aiProvider.useVendedCredentials
    };
    
    const testAnalyzer = new TestGeneratingSecurityAnalyzer(aiConfig);
    
    // Get codebase files (same logic as original)
    const codebaseFiles = await this.populateCodebaseFiles(analysisData);
    
    return await testAnalyzer.analyzeWithTestGeneration(
      issue,
      this.config,
      codebaseFiles
    );
  }
  
  /**
   * Phase 3: Validate Vulnerability (validation mode)
   * New phase that stops after proving vulnerability exists
   */
  async validatePhase(
    issue: IssueContext,
    testResults?: AnalysisWithTestsResult
  ): Promise<ValidationResult> {
    logger.info(`[PHASE: VALIDATE] Validating vulnerability for issue #${issue.number}`);
    
    if (!testResults || !testResults.generatedTests) {
      return {
        issueId: issue.number,
        validated: false,
        falsePositiveReason: 'No tests available for validation',
        timestamp: new Date().toISOString(),
        commitHash: this.getCurrentCommitHash()
      };
    }
    
    // Run tests on current (vulnerable) code
    const validator = new GitBasedTestValidator();
    const validationResult = await validator.validateTests(
      testResults.generatedTests.testSuite,
      process.cwd()
    );
    
    // Tests should FAIL to prove vulnerability exists
    if (validationResult.passed) {
      // Tests passed = no vulnerability
      logger.info('❌ Tests passed on vulnerable code - false positive detected');
      return {
        issueId: issue.number,
        validated: false,
        falsePositiveReason: 'Tests passed on allegedly vulnerable code',
        testResults: validationResult,
        timestamp: new Date().toISOString(),
        commitHash: this.getCurrentCommitHash()
      };
    }
    
    // Tests failed = vulnerability confirmed
    logger.info('✅ Vulnerability confirmed - tests failed as expected');
    
    // Store validation data for mitigation phase
    await this.storePhaseData('validation', issue.number, {
      validated: true,
      testResults: testResults,
      validationResult: validationResult
    });
    
    return {
      issueId: issue.number,
      validated: true,
      redTests: testResults.generatedTests.testSuite,
      testResults: validationResult,
      timestamp: new Date().toISOString(),
      commitHash: this.getCurrentCommitHash()
    };
  }
  
  /**
   * Phase 4: Mitigate Vulnerability (mitigation mode)
   * Extracted from processIssueWithGit Steps 3-5
   */
  async mitigatePhase(
    issue: IssueContext,
    analysisData: any,
    testResults?: AnalysisWithTestsResult,
    validationData?: ValidationResult
  ): Promise<MitigationResult> {
    logger.info(`[PHASE: MITIGATE] Fixing vulnerability for issue #${issue.number}`);
    
    // Load validation data if not provided
    if (!validationData) {
      validationData = await this.loadPhaseData('validation', issue.number) as ValidationResult;
    }
    
    // Setup AI config (same as original)
    const aiConfig: AIConfig = {
      provider: 'anthropic',
      apiKey: this.config.aiProvider.apiKey,
      model: this.config.aiProvider.model,
      temperature: 0.1,
      maxTokens: this.config.aiProvider.maxTokens,
      useVendedCredentials: this.config.aiProvider.useVendedCredentials,
      claudeCodeConfig: {
        verboseLogging: true,
        timeout: 600000,
        executablePath: process.env.CLAUDE_CODE_PATH,
        useStructuredPhases: this.config.useStructuredPhases
      }
    };
    
    // Get credential manager if needed
    let credentialManager;
    if (this.config.aiProvider.useVendedCredentials && this.config.rsolvApiKey) {
      const { CredentialManagerSingleton } = await import('../credentials/singleton.js');
      credentialManager = await CredentialManagerSingleton.getInstance(this.config.rsolvApiKey);
    }
    
    // Execute fix with validation loop (same as original)
    let solution;
    let iteration = 0;
    const maxIterations = getMaxIterations(issue, this.config);
    let currentIssue = issue;
    
    while (iteration < maxIterations) {
      logger.info(`Fixing vulnerability (attempt ${iteration + 1}/${maxIterations})`);
      
      const adapter = new GitBasedClaudeCodeAdapter(aiConfig, process.cwd(), credentialManager);
      
      // Convert analysis to expected format
      const issueAnalysis: IssueAnalysis = this.convertAnalysisData(analysisData);
      
      solution = await adapter.generateSolutionWithGit(
        currentIssue,
        issueAnalysis,
        testResults,
        iteration > 0 ? { current: iteration + 1, max: maxIterations } : undefined
      );
      
      if (!solution.success) {
        logger.warn(`Fix attempt ${iteration + 1} failed: ${solution.message}`);
        iteration++;
        continue;
      }
      
      // Validate fix if tests are available
      if (this.config.fixValidation?.enabled !== false && testResults?.generatedTests) {
        logger.info('Validating fix with tests...');
        const validator = new GitBasedTestValidator();
        const validation = await validator.validateTests(
          testResults.generatedTests.testSuite,
          process.cwd()
        );
        
        if (validation.passed) {
          logger.info('✅ Fix validated successfully!');
          break;
        } else {
          logger.warn(`Fix validation failed: ${validation.message}`);
          if (iteration < maxIterations - 1) {
            // Enhance context for next iteration
            currentIssue = this.enhanceIssueWithTestFailure(
              issue,
              validation,
              testResults,
              iteration,
              maxIterations
            );
          }
        }
      } else {
        // No validation, assume success
        break;
      }
      
      iteration++;
    }
    
    if (!solution || !solution.success) {
      return {
        issueId: issue.number,
        success: false,
        reason: `Failed after ${iteration} attempts`,
        timestamp: new Date().toISOString()
      };
    }
    
    // Create PR (same as original)
    if (this.config.createPR !== false) {
      const pr = await createEducationalPullRequest(
        issue,
        solution,
        this.config,
        analysisData
      );
      
      return {
        issueId: issue.number,
        success: true,
        prUrl: pr.html_url,
        fixCommit: solution.commitHash,
        timestamp: new Date().toISOString()
      };
    }
    
    return {
      issueId: issue.number,
      success: true,
      fixCommit: solution.commitHash,
      timestamp: new Date().toISOString()
    };
  }
  
  /**
   * Combined fix mode (legacy - validation + mitigation)
   * This is the original processIssueWithGit behavior
   */
  async fixPhase(issue: IssueContext): Promise<MitigationResult> {
    // Step 1: Analyze
    const analysisData = await this.analyzePhase(issue);
    
    // Step 2: Generate tests
    const testResults = await this.generateTestsPhase(issue, analysisData);
    
    // Step 3: Validate (but don't stop if false positive)
    const validation = await this.validatePhase(issue, testResults);
    
    if (!validation.validated) {
      logger.warn('Vulnerability not validated, but continuing with fix attempt');
    }
    
    // Step 4: Mitigate
    return await this.mitigatePhase(issue, analysisData, testResults, validation);
  }
  
  // Helper methods
  
  private async populateCodebaseFiles(analysisData: any): Promise<Map<string, string>> {
    const codebaseFiles = new Map<string, string>();
    
    if (analysisData.filesToModify && analysisData.filesToModify.length > 0) {
      for (const filePath of analysisData.filesToModify) {
        try {
          const fullPath = path.resolve(process.cwd(), filePath);
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
    
    // Fallback to vulnerable file scanner if no files found
    if (codebaseFiles.size === 0) {
      logger.info('No specific files found, scanning for vulnerable patterns...');
      const { getVulnerableFiles } = await import('../ai/vulnerable-file-scanner.js');
      const vulnerableFiles = await getVulnerableFiles(process.cwd());
      vulnerableFiles.forEach((content, path) => codebaseFiles.set(path, content));
    }
    
    return codebaseFiles;
  }
  
  private convertAnalysisData(analysisData: any): IssueAnalysis {
    return {
      summary: `${analysisData.issueType} issue analysis`,
      complexity: analysisData.estimatedComplexity === 'simple' ? 'low' : 
                 analysisData.estimatedComplexity === 'complex' ? 'high' : 'medium',
      estimatedTime: 60,
      potentialFixes: [analysisData.suggestedApproach],
      affectedFiles: analysisData.filesToModify || [],
      dependencies: [],
      risks: [],
      needsHumanReview: false
    };
  }
  
  private enhanceIssueWithTestFailure(
    issue: IssueContext,
    validation: any,
    testResults: any,
    iteration: number,
    maxIterations: number
  ): IssueContext {
    // Add test failure context to issue body
    const enhancedBody = `${issue.body}

## Fix Validation Attempt ${iteration + 1}/${maxIterations}

The previous fix attempt failed validation. The test failures indicate:
${validation.message || 'Tests did not pass'}

Please ensure the fix addresses these test failures.`;
    
    return {
      ...issue,
      body: enhancedBody
    };
  }
  
  private async storePhaseData(phase: string, issueId: number, data: any): Promise<void> {
    const storageDir = path.join(process.cwd(), '.rsolv', 'phases', phase);
    fs.mkdirSync(storageDir, { recursive: true });
    
    const filePath = path.join(storageDir, `issue-${issueId}.json`);
    fs.writeFileSync(filePath, JSON.stringify({
      ...data,
      timestamp: new Date().toISOString(),
      commitHash: this.getCurrentCommitHash()
    }, null, 2));
    
    logger.debug(`Stored ${phase} data for issue #${issueId}`);
  }
  
  private async loadPhaseData(phase: string, issueId: number): Promise<any> {
    const filePath = path.join(process.cwd(), '.rsolv', 'phases', phase, `issue-${issueId}.json`);
    
    if (!fs.existsSync(filePath)) {
      return null;
    }
    
    return JSON.parse(fs.readFileSync(filePath, 'utf8'));
  }
  
  private getCurrentCommitHash(): string {
    try {
      return execSync('git rev-parse HEAD', { encoding: 'utf8' }).trim();
    } catch {
      return 'unknown';
    }
  }
}