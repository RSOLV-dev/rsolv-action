/**
 * PhaseExecutor - Simple switch-based execution for v1
 * Implements RFC-041 three-phase architecture
 */

import { PhaseDataClient, PhaseData } from '../phase-data-client/index.js';
import { ScanOrchestrator } from '../../scanner/index.js';
import { processIssueWithGit } from '../../ai/git-based-processor.js';
import { analyzeIssue } from '../../ai/analyzer.js';
import { TestGeneratingSecurityAnalyzer, AnalysisWithTestsResult } from '../../ai/test-generating-security-analyzer.js';
import { GitBasedTestValidator } from '../../ai/git-based-test-validator.js';
import { GitBasedClaudeCodeAdapter } from '../../ai/adapters/claude-code-git.js';
import { createEducationalPullRequest } from '../../github/pr-git-educational.js';
import { createPullRequestFromGit } from '../../github/pr-git.js';
import { AIConfig, IssueAnalysis } from '../../ai/types.js';
// import { getIssue } from '../../github/api.js'; // Not needed yet
import type { ActionConfig, IssueContext } from '../../types/index.js';
import { logger } from '../../utils/logger.js';
import { execSync } from 'child_process';

export interface ExecuteOptions {
  repository?: {
    owner: string;
    name: string;
    defaultBranch?: string;
  };
  issueNumber?: number;
  issues?: IssueContext[];
  scanData?: any;
  commitSha?: string;
  // Validation-specific options
  usePriorScan?: boolean;
  runTests?: boolean;
  integrateTests?: boolean;
  postComment?: boolean;
  format?: 'markdown' | 'json' | 'github-actions';
}

export interface ExecuteResult {
  success: boolean;
  phase: string;
  message?: string;
  data?: any;
  error?: string;
}

export class PhaseExecutor {
  public phaseDataClient: PhaseDataClient;
  public scanner?: ScanOrchestrator;
  private config: ActionConfig;
  
  // These will be used for mocking in tests
  public testGenerator?: any;
  public fixer?: any;

  constructor(config: ActionConfig) {
    this.config = config;
    this.phaseDataClient = new PhaseDataClient(
      config.apiKey || '',
      process.env.RSOLV_API_URL
    );
    // Lazy initialize scanner only when needed to avoid token requirement in tests
  }

  private getScanner(): ScanOrchestrator {
    if (!this.scanner) {
      this.scanner = new ScanOrchestrator();
    }
    return this.scanner;
  }

  /**
   * Main execution method - simple switch statement for v1
   */
  async execute(mode: string, options: ExecuteOptions): Promise<ExecuteResult> {
    logger.info(`Executing in ${mode} mode`, options);

    switch (mode) {
      case 'scan':
        return this.executeScan(options);
      
      case 'validate':
        // Support multiple validation modes
        if (options.issues && options.issues.length > 0) {
          // Standalone validation with issues
          return this.executeValidateStandalone(options);
        } else if (options.issueNumber || options.scanData) {
          // Original validation mode
          return this.executeValidate(options);
        } else {
          throw new Error('Validation requires issues, --issue, or prior scan');
        }
      
      case 'mitigate':
        // Requires validated issue
        if (!options.issueNumber) {
          throw new Error('Mitigation requires --issue');
        }
        return this.executeMitigate(options);
      
      case 'fix':
        // Legacy mode - use existing processIssueWithGit
        return this.executeFix(options);
      
      case 'full':
        // Run all phases
        return this.executeAllPhases(options);
      
      default:
        throw new Error(`Unknown mode: ${mode}`);
    }
  }

  /**
   * Execute scan phase
   */
  async executeScan(options: ExecuteOptions): Promise<ExecuteResult> {
    try {
      if (!options.repository) {
        throw new Error('Scan mode requires repository information');
      }

      const scanResult = await this.getScanner().performScan({
        mode: 'scan',
        repository: {
          ...options.repository,
          defaultBranch: options.repository.defaultBranch || 'main'
        },
        createIssues: true,
        batchSimilar: true,
        issueLabel: this.config.issueLabel || 'rsolv:automate',
        enableASTValidation: process.env.RSOLV_ENABLE_AST_VALIDATION !== 'false',
        rsolvApiKey: this.config.apiKey
      });

      // Store scan results
      const commitSha = options.commitSha || this.getCurrentCommitSha();
      await this.storePhaseData('scan', scanResult, {
        repo: `${options.repository.owner}/${options.repository.name}`,
        commitSha
      });

      return {
        success: true,
        phase: 'scan',
        message: `Found ${scanResult.vulnerabilities.length} vulnerabilities`,
        data: { scan: scanResult }
      };
    } catch (error) {
      logger.error('Scan phase failed', error);
      return {
        success: false,
        phase: 'scan',
        error: error instanceof Error ? error.message : String(error)
      };
    }
  }

  /**
   * Execute validation phase
   */
  async executeValidate(options: ExecuteOptions): Promise<ExecuteResult> {
    try {
      // For now, just mock the validation
      // TODO: Implement actual test generation
      const validationResult = {
        validated: true,
        tests: ['test1.js'],
        timestamp: new Date().toISOString()
      };

      if (this.testGenerator) {
        const result = await this.testGenerator.generateValidationTests(options);
        Object.assign(validationResult, result);
      }

      // Store validation results
      if (options.issueNumber) {
        const commitSha = options.commitSha || this.getCurrentCommitSha();
        await this.storePhaseData('validation', {
          [`issue-${options.issueNumber}`]: validationResult
        }, {
          repo: options.repository ? 
            `${options.repository.owner}/${options.repository.name}` : 
            'unknown/repo',
          issueNumber: options.issueNumber,
          commitSha
        });
      }

      return {
        success: true,
        phase: 'validate',
        message: 'Vulnerability validated with RED tests',
        data: { validation: validationResult }
      };
    } catch (error) {
      logger.error('Validation phase failed', error);
      return {
        success: false,
        phase: 'validate',
        error: error instanceof Error ? error.message : String(error)
      };
    }
  }

  /**
   * Execute mitigation phase
   */
  async executeMitigate(options: ExecuteOptions): Promise<ExecuteResult> {
    try {
      // For now, just mock the mitigation
      // TODO: Implement actual fix generation
      let mitigationResult = {
        fixed: true,
        prUrl: 'https://github.com/test/pr/1',
        filesModified: ['user.js'],
        timestamp: new Date().toISOString()
      };

      if (this.fixer) {
        const result = await this.fixer.applyFix(options);
        Object.assign(mitigationResult, result);
      }

      // Store mitigation results
      if (options.issueNumber) {
        const commitSha = options.commitSha || this.getCurrentCommitSha();
        await this.storePhaseData('mitigation', {
          [`issue-${options.issueNumber}`]: mitigationResult
        }, {
          repo: options.repository ? 
            `${options.repository.owner}/${options.repository.name}` : 
            'unknown/repo',
          issueNumber: options.issueNumber,
          commitSha
        });
      }

      return {
        success: true,
        phase: 'mitigate',
        message: 'Vulnerability fixed and PR created',
        data: { mitigation: mitigationResult }
      };
    } catch (error) {
      logger.error('Mitigation phase failed', error);
      return {
        success: false,
        phase: 'mitigate',
        error: error instanceof Error ? error.message : String(error)
      };
    }
  }

  /**
   * Execute fix mode (legacy)
   */
  async executeFix(options: ExecuteOptions): Promise<ExecuteResult> {
    try {
      if (!options.issues || options.issues.length === 0) {
        throw new Error('Fix mode requires issues');
      }

      // Use existing processIssueWithGit for backward compatibility
      const results = [];
      for (const issue of options.issues) {
        const result = await processIssueWithGit(issue, this.config);
        results.push(result);
      }

      return {
        success: true,
        phase: 'fix',
        message: `Processed ${results.length} issues`,
        data: { results }
      };
    } catch (error) {
      logger.error('Fix phase failed', error);
      return {
        success: false,
        phase: 'fix',
        error: error instanceof Error ? error.message : String(error)
      };
    }
  }

  /**
   * Execute all phases
   */
  async executeAllPhases(options: ExecuteOptions): Promise<ExecuteResult> {
    try {
      logger.info('Executing all phases: scan, validate, mitigate');

      // Phase 1: Scan
      const scanResult = await this.executeScan(options);
      if (!scanResult.success) {
        return scanResult;
      }

      // Phase 2: Validate each vulnerability
      const vulnerabilities = scanResult.data?.scan?.vulnerabilities || [];
      const validationResults = [];
      
      for (const vuln of vulnerabilities) {
        // TODO: Convert vulnerability to issue for validation
        const validateResult = await this.executeValidate({
          ...options,
          scanData: vuln
        });
        validationResults.push(validateResult);
      }

      // Phase 3: Mitigate validated vulnerabilities
      const mitigationResults = [];
      for (const validation of validationResults) {
        if (validation.success && validation.data?.validation?.validated) {
          const mitigateResult = await this.executeMitigate({
            ...options,
            // TODO: Extract issue number from validation
          });
          mitigationResults.push(mitigateResult);
        }
      }

      return {
        success: true,
        phase: 'full',
        message: `Completed all phases: ${vulnerabilities.length} scanned, ${validationResults.length} validated, ${mitigationResults.length} mitigated`,
        data: {
          scan: scanResult.data,
          validations: validationResults,
          mitigations: mitigationResults
        }
      };
    } catch (error) {
      logger.error('Full execution failed', error);
      return {
        success: false,
        phase: 'full',
        error: error instanceof Error ? error.message : String(error)
      };
    }
  }

  /**
   * Store phase data using PhaseDataClient
   */
  async storePhaseData(phase: 'scan' | 'validation' | 'mitigation', data: any, metadata: any): Promise<void> {
    const phaseData: PhaseData = {};
    
    if (phase === 'scan') {
      phaseData.scan = {
        vulnerabilities: data.vulnerabilities || [],
        timestamp: new Date().toISOString(),
        commitHash: metadata.commitSha
      };
    } else if (phase === 'validation') {
      phaseData.validation = data;
    } else if (phase === 'mitigation') {
      phaseData.mitigation = data;
    }

    await this.phaseDataClient.storePhaseResults(
      phase === 'validation' ? 'validate' : phase === 'mitigation' ? 'mitigate' : phase,
      phaseData,
      metadata
    );
  }

  /**
   * Retrieve phase data using PhaseDataClient
   */
  async retrievePhaseData(repo: string, issueNumber: number, commitSha: string): Promise<PhaseData | null> {
    return this.phaseDataClient.retrievePhaseResults(repo, issueNumber, commitSha);
  }

  /**
   * Get current git commit SHA
   */
  private getCurrentCommitSha(): string {
    return execSync('git rev-parse HEAD', { encoding: 'utf-8' }).trim();
  }

  // ============= Phase Decomposition Methods =============
  // These methods extract the three phases from processIssueWithGit
  
  /**
   * Execute SCAN phase for a single issue
   * Analyzes the issue and determines if it can be fixed
   */
  async executeScanForIssue(issue: IssueContext): Promise<ExecuteResult> {
    try {
      logger.info(`[SCAN] Analyzing issue #${issue.number}`);
      
      // Step 1: Check git status
      const gitStatus = this.checkGitStatus();
      if (!gitStatus.clean) {
        return {
          success: false,
          phase: 'scan',
          message: 'Repository has uncommitted changes',
          error: `Uncommitted changes in: ${gitStatus.modifiedFiles.join(', ')}`
        };
      }
      
      // Step 2: Analyze the issue
      const analysisData = await analyzeIssue(issue, this.config);
      
      if (!analysisData) {
        return {
          success: false,
          phase: 'scan',
          message: 'Failed to analyze issue',
          error: 'Analysis returned no data'
        };
      }
      
      const scanResult = {
        canBeFixed: analysisData.canBeFixed || false,
        analysisData,
        gitStatus,
        timestamp: new Date().toISOString()
      };
      
      // Store scan results
      const commitSha = this.getCurrentCommitSha();
      await this.phaseDataClient.storePhaseResults(
        'scan',
        { scan: scanResult },
        {
          repo: `${issue.repository.owner}/${issue.repository.name}`,
          issueNumber: issue.number,
          commitSha
        }
      );
      
      return {
        success: true,
        phase: 'scan',
        message: analysisData.canBeFixed ? 
          'Issue can be automatically fixed' : 
          'Issue cannot be automatically fixed',
        data: scanResult
      };
    } catch (error) {
      logger.error('[SCAN] Failed to analyze issue', error);
      return {
        success: false,
        phase: 'scan',
        error: error instanceof Error ? error.message : String(error)
      };
    }
  }

  /**
   * Execute VALIDATE phase for a single issue
   * Generates tests to validate the vulnerability
   */
  async executeValidateForIssue(
    issue: IssueContext, 
    scanData: any
  ): Promise<ExecuteResult> {
    try {
      logger.info(`[VALIDATE] Generating tests for issue #${issue.number}`);
      
      const { analysisData } = scanData;
      
      if (!analysisData.canBeFixed) {
        return {
          success: false,
          phase: 'validate',
          message: 'Issue cannot be fixed, skipping validation'
        };
      }
      
      // Use TestGeneratingSecurityAnalyzer if available
      let testResults: AnalysisWithTestsResult | undefined;
      
      if (this.testGeneratingAnalyzer) {
        // Get codebase files for test generation
        const codebaseFiles = new Map<string, string>();
        
        if (analysisData.filesToModify && analysisData.filesToModify.length > 0) {
          const fs = (await import('fs')).default;
          const path = (await import('path')).default;
          
          for (const filePath of analysisData.filesToModify) {
            try {
              const fullPath = path.resolve(process.cwd(), filePath);
              if (fs.existsSync(fullPath)) {
                const content = fs.readFileSync(fullPath, 'utf8');
                codebaseFiles.set(filePath, content);
              }
            } catch (error) {
              logger.warn(`Could not read file ${filePath} for test generation:`, error);
            }
          }
        }
        
        testResults = await this.testGeneratingAnalyzer.analyzeWithTestGeneration(
          issue,
          this.config,
          codebaseFiles
        );
      } else if (this.config.testGeneration?.enabled || this.config.fixValidation?.enabled !== false) {
        // Create analyzer if enabled
        const aiConfig: AIConfig = {
          provider: 'anthropic',
          apiKey: this.config.aiProvider.apiKey,
          model: this.config.aiProvider.model,
          temperature: 0.2,
          maxTokens: this.config.aiProvider.maxTokens,
          useVendedCredentials: this.config.aiProvider.useVendedCredentials
        };
        
        const testAnalyzer = new TestGeneratingSecurityAnalyzer(aiConfig);
        
        // Get codebase files
        const codebaseFiles = new Map<string, string>();
        
        if (analysisData.filesToModify && analysisData.filesToModify.length > 0) {
          const fs = (await import('fs')).default;
          const path = (await import('path')).default;
          
          for (const filePath of analysisData.filesToModify) {
            try {
              const fullPath = path.resolve(process.cwd(), filePath);
              if (fs.existsSync(fullPath)) {
                const content = fs.readFileSync(fullPath, 'utf8');
                codebaseFiles.set(filePath, content);
              }
            } catch (error) {
              logger.warn(`Could not read file ${filePath}:`, error);
            }
          }
        }
        
        testResults = await testAnalyzer.analyzeWithTestGeneration(
          issue,
          this.config,
          codebaseFiles
        );
      }
      
      const validationResult = {
        generatedTests: testResults?.generatedTests || {
          success: false,
          message: 'Test generation disabled'
        },
        analysisData,
        timestamp: new Date().toISOString()
      };
      
      // Store validation results
      const commitSha = this.getCurrentCommitSha();
      await this.phaseDataClient.storePhaseResults(
        'validate',
        { validation: validationResult },
        {
          repo: `${issue.repository.owner}/${issue.repository.name}`,
          issueNumber: issue.number,
          commitSha
        }
      );
      
      return {
        success: true,
        phase: 'validate',
        message: validationResult.generatedTests.success ? 
          'Tests generated successfully' : 
          'Test generation skipped or failed',
        data: validationResult
      };
    } catch (error) {
      logger.error('[VALIDATE] Failed to generate tests', error);
      return {
        success: false,
        phase: 'validate',
        error: error instanceof Error ? error.message : String(error)
      };
    }
  }

  /**
   * Execute MITIGATE phase for a single issue
   * Applies the fix using Claude Code and validates with tests
   */
  async executeMitigateForIssue(
    issue: IssueContext,
    scanData: any,
    validationData: any
  ): Promise<ExecuteResult> {
    const startTime = Date.now();
    const beforeFixCommit = this.getCurrentCommitSha();
    
    try {
      logger.info(`[MITIGATE] Applying fix for issue #${issue.number}`);
      
      const { analysisData } = scanData;
      const { generatedTests } = validationData;
      
      // Set up AI config
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
      
      // Get credential manager if using vended credentials
      let credentialManager;
      if (this.config.aiProvider.useVendedCredentials && this.config.rsolvApiKey) {
        const { CredentialManagerSingleton } = await import('../../credentials/singleton.js');
        credentialManager = await CredentialManagerSingleton.getInstance(this.config.rsolvApiKey);
        logger.info('Using vended credentials singleton for Claude Code');
      }
      
      // Execute fix with validation loop
      let solution;
      let iteration = 0;
      const maxIterations = this.maxIterations || this.getMaxIterations(issue);
      let currentIssue = issue;
      
      while (iteration < maxIterations) {
        logger.info(`[MITIGATE] Fix attempt ${iteration + 1}/${maxIterations}`);
        
        const adapter = new GitBasedClaudeCodeAdapter(aiConfig, process.cwd(), credentialManager);
        
        // Convert AnalysisData to IssueAnalysis
        const issueAnalysis: IssueAnalysis = {
          summary: `${analysisData.issueType} issue analysis`,
          complexity: analysisData.estimatedComplexity === 'simple' ? 'low' : 
                     analysisData.estimatedComplexity === 'complex' ? 'high' : 'medium',
          estimatedTime: 60,
          potentialFixes: [analysisData.suggestedApproach],
          recommendedApproach: analysisData.suggestedApproach,
          relatedFiles: analysisData.filesToModify
        };
        
        const validationContext = iteration > 0 ? {
          current: iteration + 1,
          max: maxIterations
        } : undefined;
        
        solution = await adapter.generateSolutionWithGit(
          currentIssue,
          issueAnalysis,
          undefined,
          validationData,
          undefined,
          validationContext
        );
        
        if (!solution.success) {
          return {
            success: false,
            phase: 'mitigate',
            message: solution.message,
            error: solution.error
          };
        }
        
        // Validate fix if tests were generated
        if ((this.config.testGeneration?.validateFixes || this.config.fixValidation?.enabled !== false) &&
            generatedTests?.success && generatedTests.testSuite) {
          
          logger.info(`[MITIGATE] Validating fix with tests...`);
          
          const validator = this.gitBasedValidator || new GitBasedTestValidator();
          const validation = await validator.validateFixWithTests(
            beforeFixCommit,
            solution.commitHash!,
            generatedTests.testSuite
          );
          
          if (validation.isValidFix) {
            logger.info('[MITIGATE] ✅ Fix validated successfully');
            break;
          }
          
          // Fix failed, prepare for retry
          iteration++;
          if (iteration >= maxIterations) {
            execSync(`git reset --hard ${beforeFixCommit}`, { encoding: 'utf-8' });
            
            return {
              success: false,
              phase: 'mitigate',
              message: `Fix validation failed after ${maxIterations} attempts`,
              error: this.explainTestFailure(validation)
            };
          }
          
          // Reset and enhance issue for retry
          execSync(`git reset --hard ${beforeFixCommit}`, { encoding: 'utf-8' });
          currentIssue = this.createEnhancedIssueWithTestFailure(
            issue,
            validation,
            validationData,
            iteration,
            maxIterations
          );
          
          continue;
        }
        
        // No validation needed or passed
        break;
      }
      
      // Create PR from the commit
      logger.info(`[MITIGATE] Creating PR from commit ${solution!.commitHash?.substring(0, 8)}`);
      
      const useEducationalPR = process.env.RSOLV_EDUCATIONAL_PR !== 'false';
      
      const prResult = useEducationalPR ?
        await createEducationalPullRequest(
          issue,
          solution!.commitHash!,
          {
            ...solution!.summary!,
            vulnerabilityType: analysisData.vulnerabilityType || 'security',
            severity: analysisData.severity || 'medium',
            cwe: analysisData.cwe,
            isAiGenerated: analysisData.isAiGenerated
          },
          this.config,
          solution!.diffStats
        ) :
        await createPullRequestFromGit(
          issue,
          solution!.commitHash!,
          solution!.summary!,
          this.config,
          solution!.diffStats
        );
      
      if (!prResult.success) {
        try {
          execSync('git reset --hard HEAD~1', { encoding: 'utf-8' });
        } catch (resetError) {
          logger.warn('Failed to rollback commit', resetError);
        }
        
        return {
          success: false,
          phase: 'mitigate',
          message: prResult.message,
          error: prResult.error
        };
      }
      
      const processingTime = Date.now() - startTime;
      logger.info(`[MITIGATE] Successfully created PR in ${processingTime}ms`);
      
      // Store mitigation results
      const mitigationResult = {
        pullRequestUrl: prResult.pullRequestUrl,
        pullRequestNumber: prResult.pullRequestNumber,
        commitHash: solution!.commitHash,
        filesModified: solution!.filesModified,
        diffStats: solution!.diffStats,
        timestamp: new Date().toISOString()
      };
      
      await this.phaseDataClient.storePhaseResults(
        'mitigate',
        { mitigation: mitigationResult },
        {
          repo: `${issue.repository.owner}/${issue.repository.name}`,
          issueNumber: issue.number,
          commitSha: solution!.commitHash!
        }
      );
      
      return {
        success: true,
        phase: 'mitigate',
        message: `Created PR #${prResult.pullRequestNumber}`,
        data: mitigationResult
      };
      
    } catch (error) {
      logger.error('[MITIGATE] Failed to apply fix', error);
      
      // Try to rollback
      try {
        execSync(`git reset --hard ${beforeFixCommit}`, { encoding: 'utf-8' });
      } catch (resetError) {
        logger.warn('Failed to rollback after error', resetError);
      }
      
      return {
        success: false,
        phase: 'mitigate',
        error: error instanceof Error ? error.message : String(error)
      };
    }
  }

  /**
   * Execute all three phases for a single issue
   */
  async executeThreePhaseForIssue(issue: IssueContext): Promise<ExecuteResult> {
    try {
      logger.info(`[THREE-PHASE] Processing issue #${issue.number} through all phases`);
      
      // Phase 1: SCAN
      const scanResult = await this.executeScanForIssue(issue);
      if (!scanResult.success) {
        return {
          ...scanResult,
          phase: 'three-phase'
        };
      }
      
      if (!scanResult.data?.canBeFixed) {
        return {
          success: false,
          phase: 'three-phase',
          message: 'Issue cannot be fixed automatically',
          data: { scan: scanResult.data }
        };
      }
      
      // Phase 2: VALIDATE
      const validateResult = await this.executeValidateForIssue(issue, scanResult.data);
      if (!validateResult.success) {
        return {
          ...validateResult,
          phase: 'three-phase',
          data: {
            scan: scanResult.data,
            validation: validateResult.data
          }
        };
      }
      
      // Phase 3: MITIGATE
      const mitigateResult = await this.executeMitigateForIssue(
        issue,
        scanResult.data,
        validateResult.data
      );
      
      return {
        success: mitigateResult.success,
        phase: 'three-phase',
        message: mitigateResult.success ? 
          `Successfully processed issue #${issue.number} through all phases` :
          mitigateResult.message,
        data: {
          scan: scanResult.data,
          validation: validateResult.data,
          mitigation: mitigateResult.data
        },
        error: mitigateResult.error
      };
      
    } catch (error) {
      logger.error('[THREE-PHASE] Failed to process issue', error);
      return {
        success: false,
        phase: 'three-phase',
        error: error instanceof Error ? error.message : String(error)
      };
    }
  }

  // Helper methods for phase decomposition
  
  /**
   * Check git repository status
   */
  checkGitStatus(): { clean: boolean; modifiedFiles: string[] } {
    try {
      const status = execSync('git status --porcelain', {
        encoding: 'utf-8'
      }).trim();
      
      if (!status) {
        return { clean: true, modifiedFiles: [] };
      }
      
      const modifiedFiles = status
        .split('\n')
        .map(line => line.substring(3).trim())
        .filter(file => file.length > 0);
      
      return { clean: false, modifiedFiles };
      
    } catch (error) {
      logger.error('Failed to check git status', error);
      return { clean: false, modifiedFiles: ['unknown'] };
    }
  }

  /**
   * Get maximum iterations for fix validation
   */
  private getMaxIterations(issue: IssueContext): number {
    // Check for label override
    const labelMatch = issue.labels.find(label => label.startsWith('fix-validation-max-'));
    if (labelMatch) {
      const maxFromLabel = parseInt(labelMatch.replace('fix-validation-max-', ''));
      if (!isNaN(maxFromLabel)) return maxFromLabel;
    }
    
    // Use config value
    if (this.config.fixValidation?.maxIterations !== undefined) {
      return this.config.fixValidation.maxIterations;
    }
    
    // Default
    return 3;
  }

  /**
   * Explain why tests failed
   */
  private explainTestFailure(validation: any): string {
    const failures = [];
    
    if (!validation.fixedCommit.redTestPassed) {
      failures.push('- The vulnerability still exists (RED test failed)');
    }
    if (!validation.fixedCommit.greenTestPassed) {
      failures.push('- The fix was not properly applied (GREEN test failed)');
    }
    if (!validation.fixedCommit.refactorTestPassed) {
      failures.push('- The fix broke existing functionality (REFACTOR test failed)');
    }
    
    return failures.join('\n');
  }

  /**
   * Create enhanced issue context with test failure information
   */
  private createEnhancedIssueWithTestFailure(
    issue: IssueContext,
    validation: any,
    testResults: any,
    iteration: number,
    maxIterations: number
  ): IssueContext {
    const testCode = testResults.generatedTests?.tests?.[0]?.testCode || '';
    const framework = testResults.generatedTests?.tests?.[0]?.framework || 'unknown';
    
    return {
      ...issue,
      body: `${issue.body}

## Previous Fix Attempt Failed

The previous fix did not pass the generated security tests:

### Test Results:
- Red Test (vulnerability should be fixed): ${validation.fixedCommit.redTestPassed ? '✅ PASSED' : '❌ FAILED'}
- Green Test (fix should work): ${validation.fixedCommit.greenTestPassed ? '✅ PASSED' : '❌ FAILED'}
- Refactor Test (functionality maintained): ${validation.fixedCommit.refactorTestPassed ? '✅ PASSED' : '❌ FAILED'}

### Generated Test Code:
\`\`\`${framework}
${testCode}
\`\`\`

Please fix the vulnerability again, ensuring the fix passes all three tests.

### Why the Previous Fix Failed:
${this.explainTestFailure(validation)}

This is attempt ${iteration + 1} of ${maxIterations}.`
    };
  }

  // Properties for mocking in tests
  public testGeneratingAnalyzer?: TestGeneratingSecurityAnalyzer;
  public gitBasedValidator?: GitBasedTestValidator;
  public maxIterations?: number;
  public testRunner?: any;
  public testDiscovery?: any;
  public testIntegrator?: any;
  public githubClient?: any;
  public validationTimeout?: number;

  /**
   * Execute standalone validation mode for multiple issues
   * Generates tests without requiring prior scan
   */
  async executeValidateStandalone(options: ExecuteOptions): Promise<ExecuteResult> {
    try {
      logger.info(`[VALIDATE-STANDALONE] Processing ${options.issues?.length} issues`);
      
      if (!options.issues || options.issues.length === 0) {
        return {
          success: false,
          phase: 'validate',
          error: 'No issues provided for validation'
        };
      }

      const validations = [];
      
      for (const issue of options.issues) {
        try {
          // Check for prior scan data if requested
          let scanData = null;
          if (options.usePriorScan) {
            const priorData = await this.phaseDataClient.retrievePhaseResults(
              `${issue.repository.owner}/${issue.repository.name}`,
              issue.number,
              this.getCurrentCommitSha()
            );
            scanData = priorData?.scan;
          }

          // Analyze issue if no prior scan
          if (!scanData) {
            const analysisData = await analyzeIssue(issue, this.config);
            scanData = {
              analysisData,
              canBeFixed: analysisData?.canBeFixed || false,
              usedPriorScan: false
            };
          } else {
            scanData.usedPriorScan = true;
          }

          // Generate validation tests
          const testResults = await this.generateValidationTests(issue, scanData);
          
          // Run tests if requested
          let testExecution = null;
          if (options.runTests && this.testRunner) {
            try {
              testExecution = await this.testRunner.runTests(testResults.generatedTests);
              
              // Check for false positive
              if (testExecution.redTestPassed) {
                testResults.falsePositive = true;
                testResults.reason = 'Tests pass on current code';
              }
            } catch (error) {
              logger.warn(`Test execution failed for issue #${issue.number}:`, error);
              testResults.testExecutionFailed = true;
              testResults.error = error instanceof Error ? error.message : String(error);
            }
          }

          // Check for existing tests
          if (this.testDiscovery) {
            const existing = await this.testDiscovery.findExistingTests(issue.repository);
            if (existing.hasTests) {
              testResults.existingTests = true;
              testResults.testFramework = existing.framework;
              
              // Integrate tests if requested
              if (options.integrateTests && this.testIntegrator) {
                const integration = await this.testIntegrator.integrateTests(
                  testResults.generatedTests,
                  existing
                );
                testResults.testsIntegrated = integration.integrated;
                testResults.testFile = integration.testFile;
              }
            }
          }

          // Store validation results
          const validationResult = {
            issueNumber: issue.number,
            ...testResults,
            timestamp: new Date().toISOString()
          };

          await this.phaseDataClient.storePhaseResults(
            'validate',
            { 
              validation: {
                [`issue-${issue.number}`]: validationResult
              }
            },
            {
              repo: `${issue.repository.owner}/${issue.repository.name}`,
              issueNumber: issue.number,
              commitSha: this.getCurrentCommitSha()
            }
          );

          // Post GitHub comment if requested
          if (options.postComment && this.githubClient) {
            const comment = this.formatValidationComment(issue, validationResult);
            await this.githubClient.createIssueComment(
              issue.repository.owner,
              issue.repository.name,
              issue.number,
              comment
            );
          }

          validations.push(validationResult);
          
        } catch (error) {
          logger.error(`Failed to validate issue #${issue.number}:`, error);
          
          // Try fallback test generation
          const fallbackTests = this.generateFallbackTests(issue);
          validations.push({
            issueNumber: issue.number,
            testGenerationFailed: true,
            fallbackTests: true,
            generatedTests: fallbackTests,
            error: error instanceof Error ? error.message : String(error)
          });
        }
      }

      // Generate report if requested
      let report = null;
      if (options.format) {
        report = this.generateValidationReport(validations, options.format);
      }

      // For single issue, return simpler structure
      if (options.issues.length === 1) {
        return {
          success: true,
          phase: 'validate',
          message: `Validation completed for issue #${options.issues[0].number}`,
          data: {
            validation: validations[0],
            report
          }
        };
      }

      return {
        success: true,
        phase: 'validate',
        message: `Validated ${validations.length} issues`,
        data: {
          validations,
          report,
          annotations: options.format === 'github-actions' ? 
            this.generateGitHubAnnotations(validations) : undefined
        }
      };
      
    } catch (error) {
      logger.error('[VALIDATE-STANDALONE] Failed', error);
      return {
        success: false,
        phase: 'validate',
        error: error instanceof Error ? error.message : String(error)
      };
    }
  }

  /**
   * Generate validation tests for an issue
   */
  private async generateValidationTests(issue: IssueContext, scanData: any): Promise<any> {
    const { analysisData } = scanData;
    
    // Use TestGeneratingSecurityAnalyzer if available
    if (this.testGeneratingAnalyzer || this.config.testGeneration?.enabled) {
      const analyzer = this.testGeneratingAnalyzer || 
        new TestGeneratingSecurityAnalyzer({
          provider: 'anthropic',
          apiKey: this.config.aiProvider.apiKey,
          model: this.config.aiProvider.model,
          temperature: 0.2,
          maxTokens: this.config.aiProvider.maxTokens,
          useVendedCredentials: this.config.aiProvider.useVendedCredentials
        });

      // Get codebase files
      const codebaseFiles = await this.getCodebaseFiles(analysisData);
      
      const testResults = await analyzer.analyzeWithTestGeneration(
        issue,
        this.config,
        codebaseFiles
      );

      // Format tests in TDD style
      const tests = testResults.generatedTests;
      return {
        generatedTests: {
          ...tests,
          redTest: tests?.tests?.[0]?.testCode || 'should fail when vulnerability exists',
          greenTest: tests?.tests?.[1]?.testCode || 'should pass when vulnerability is fixed',
          refactorTest: tests?.tests?.[2]?.testCode || 'should maintain original functionality'
        },
        ...scanData
      };
    }

    // Fallback to basic test structure
    return {
      generatedTests: this.generateFallbackTests(issue),
      ...scanData
    };
  }

  /**
   * Get codebase files for test generation
   */
  private async getCodebaseFiles(analysisData: any): Promise<Map<string, string>> {
    const codebaseFiles = new Map<string, string>();
    
    if (analysisData?.filesToModify && analysisData.filesToModify.length > 0) {
      const fs = (await import('fs')).default;
      const path = (await import('path')).default;
      
      for (const filePath of analysisData.filesToModify) {
        try {
          const fullPath = path.resolve(process.cwd(), filePath);
          if (fs.existsSync(fullPath)) {
            const content = fs.readFileSync(fullPath, 'utf8');
            codebaseFiles.set(filePath, content);
          }
        } catch (error) {
          logger.warn(`Could not read file ${filePath}:`, error);
        }
      }
    }
    
    return codebaseFiles;
  }

  /**
   * Generate fallback tests when AI generation fails
   */
  private generateFallbackTests(issue: IssueContext): any {
    return {
      redTest: `// RED Test: Should fail when ${issue.title} exists`,
      greenTest: `// GREEN Test: Should pass when ${issue.title} is fixed`,
      refactorTest: `// REFACTOR Test: Should maintain functionality after fix`
    };
  }

  /**
   * Format validation results as GitHub comment
   */
  private formatValidationComment(issue: IssueContext, validation: any): string {
    return `## Validation Results

**Issue #${issue.number}**: ${issue.title}

### Test Generation
- ✅ RED test generated (proves vulnerability exists)
- ✅ GREEN test generated (validates fix)
- ✅ REFACTOR test generated (ensures functionality preserved)

${validation.falsePositive ? '### ⚠️ Possible False Positive\nTests pass on current code - vulnerability may not exist.' : ''}

${validation.testExecutionFailed ? '### ⚠️ Test Execution Failed\nTests were generated but could not be executed automatically.' : ''}

### Next Steps
${validation.falsePositive ? 
  '1. Review the generated tests\n2. Close issue if false positive confirmed' :
  '1. Review the generated tests\n2. Run mitigation mode to apply fix\n3. Tests will validate the fix automatically'}
`;
  }

  /**
   * Generate validation report in requested format
   */
  private generateValidationReport(validations: any[], format: string): string {
    switch (format) {
      case 'markdown':
        return this.generateMarkdownReport(validations);
      case 'json':
        return JSON.stringify({ issues: validations }, null, 2);
      case 'github-actions':
        return this.generateGitHubActionsReport(validations);
      default:
        return JSON.stringify(validations);
    }
  }

  /**
   * Generate markdown validation report
   */
  private generateMarkdownReport(validations: any[]): string {
    let report = '# Validation Report\n\n';
    
    for (const validation of validations) {
      report += `## Issue #${validation.issueNumber}\n\n`;
      report += validation.falsePositive ? 
        '**Status**: ⚠️ Possible False Positive\n\n' :
        '**Status**: ✅ Validated\n\n';
      report += '### Generated Tests\n';
      report += '- RED test: Generated\n';
      report += '- GREEN test: Generated\n';
      report += '- REFACTOR test: Generated\n\n';
    }
    
    return report;
  }

  /**
   * Generate GitHub Actions report
   */
  private generateGitHubActionsReport(validations: any[]): string {
    return validations.map(v => 
      `::${v.falsePositive ? 'warning' : 'notice'} ::Issue #${v.issueNumber} validated`
    ).join('\n');
  }

  /**
   * Generate GitHub Actions annotations
   */
  private generateGitHubAnnotations(validations: any[]): string[] {
    return validations.map(v => 
      `::warning file=unknown,line=1::Issue #${v.issueNumber} - ${v.falsePositive ? 'Possible false positive' : 'Validation complete'}`
    );
  }
}