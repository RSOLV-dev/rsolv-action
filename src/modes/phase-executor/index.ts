/**
 * PhaseExecutor - Simple switch-based execution for v1
 * Implements RFC-041 three-phase architecture
 */

// PhaseDataClient removed (RFC-126: storage is now platform-driven)
type PhaseData = Record<string, unknown>;
type ScanVulnerability = Record<string, unknown>;
import { ScanOrchestrator } from '../../scanner/index.js';
import { analyzeIssue } from '../../ai/analyzer.js';
import { TestGeneratingSecurityAnalyzer } from '../../ai/test-generating-security-analyzer.js';
import { createEducationalPullRequest } from '../../github/pr-git-educational.js';
import type { ValidationData as PrValidationData } from '../../types/validation.js';
import type { ActionConfig, IssueContext, AnalysisData } from '../../types/index.js';
import type {
  ValidationData,
  ScanPhaseData,
  ValidationPhaseData,
  PhaseMetadata
} from '../../types/vulnerability.js';
import { logger } from '../../utils/logger.js';
import { execSync } from 'child_process';
import { extractValidateRedTest } from '../../ai/validate-test-reuse.js';
import { MitigationClient, type MitigationContext } from '../../pipeline/mitigation-client.js';
import { ValidationClient, type ValidationContext } from '../../pipeline/validation-client.js';
import { TestRunner, type TestFramework } from '../../ai/test-runner.js';
import { applyValidationLabels } from './utils/label-manager.js';

export interface ExecuteOptions {
  repository?: {
    owner: string;
    name: string;
    defaultBranch?: string;
  };
  issueNumber?: number;
  issues?: IssueContext[];
  scanData?: ScanPhaseData;
  commitSha?: string;
  // Validation-specific options
  usePriorScan?: boolean;
  runTests?: boolean;
  integrateTests?: boolean;
  postComment?: boolean;
  format?: 'markdown' | 'json' | 'github-actions';
  
  // Mitigation-specific options
  validationData?: PhaseData | Record<string, unknown>;
  usePriorValidation?: boolean;
  generateTestsIfMissing?: boolean;
  timeout?: number;
  maxRetries?: number;
  refactorStyle?: string;
  createPR?: boolean;
  prType?: string;
  includeBeforeAfter?: boolean;

  // RFC-126: Pipeline run coordination
  pipelineRunId?: string;
}

export interface ExecuteResult {
  success: boolean;
  phase: string;
  message?: string;
  data?: Record<string, unknown>;
  error?: string;
  report?: string;
  jsonReport?: Record<string, unknown>;
}

// Type for validation items from server/local processing
type ValidationItem = {
  issueNumber: number;
  validated?: boolean;
  testGenerationFailed?: boolean;
  canBeFixed?: boolean;
  fallbackTests?: boolean;
  generatedTests?: any;
  error?: string;
  usedPriorScan?: boolean;
  timestamp?: string;
  hasSpecificVulnerabilities?: boolean;
  vulnerabilities?: any[];
  confidence?: 'low' | 'medium' | 'high';
  falsePositive?: boolean;
  reason?: string;
  [key: string]: any;
};

export class PhaseExecutor {
  public scanner?: ScanOrchestrator;
  private config: ActionConfig;

  // These will be used for mocking in tests
  public testGenerator?: TestGeneratingSecurityAnalyzer;

  constructor(config: ActionConfig) {
    this.config = config;
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
    case 'validate-only':
      // RFC-126: Single-issue backend-orchestrated validation
      return this.executeValidate(options);

    case 'mitigate':
    case 'fix-only':
      // RFC-126: Single-issue backend-orchestrated mitigation
      return this.executeMitigate(options);

    case 'process':
      // RFC-126: Process pending issues from a prior scan
      return this.executeProcess(options);

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
      // Extract repository from options or first issue
      let repository = options.repository;
      if (!repository && options.issues && options.issues.length > 0) {
        repository = options.issues[0].repository;
      }
      
      if (!repository) {
        throw new Error('Scan mode requires repository information');
      }

      // If we have specific issues, scan them individually
      if (options.issues && options.issues.length > 0) {
        const scanResults: Record<string, any> = {
          canBeFixed: true,
          vulnerabilities: [],
          timestamp: new Date().toISOString(),
          commitHash: await this.getCurrentCommitSha()
        };

        for (const issue of options.issues) {
          try {
            const result = await this.executeScanForIssue(issue);
            if (result.success && result.data) {
              scanResults.vulnerabilities.push({
                issueNumber: issue.number,
                ...result.data
              });
              if (!result.data.canBeFixed) {
                scanResults.canBeFixed = false;
              }
            }
          } catch (err) {
            logger.warn(`Failed to scan issue #${issue.number}:`, err);
          }
        }

        // Store combined results
        await this.storePhaseData('scan', scanResults, {
          repo: `${repository.owner}/${repository.name}`,
          commitSha: scanResults.commitHash
        });

        return {
          success: true,
          phase: 'scan',
          data: { scan: scanResults }
        };
      }

      // Full repository scan (original behavior)
      const scanResult = await this.getScanner().performScan({
        mode: 'scan',
        repository: {
          ...repository,
          defaultBranch: repository.defaultBranch || 'main'
        },
        createIssues: true,
        batchSimilar: true,
        issueLabel: this.config.issueLabel || 'rsolv:automate',
        enableASTValidation: process.env.RSOLV_ENABLE_AST_VALIDATION !== 'false',
        rsolvApiKey: this.config.rsolvApiKey,
        maxIssues: this.config.maxIssues
      });

      // RFC-126: Register PipelineRun with platform after scan
      const commitSha = options.commitSha || this.getCurrentCommitSha();
      const namespace = `${repository.owner}/${repository.name}`;
      let pipelineRunId: string | undefined;

      if (scanResult.createdIssues && scanResult.createdIssues.length > 0) {
        try {
          const { PipelineRunClient } = await import('../../pipeline/pipeline-run-client.js');
          const runClient = new PipelineRunClient({
            apiUrl: process.env.RSOLV_API_URL || 'https://api.rsolv.dev',
            apiKey: this.config.rsolvApiKey || this.config.apiKey || '',
          });

          const createdIssues = scanResult.createdIssues.map((issue: { number: number; cweId?: string; cwe_id?: string }) => ({
            issue_number: issue.number,
            cwe_id: issue.cweId || issue.cwe_id || '',
          }));

          const runResult = await runClient.createRun({
            commitSha,
            branch: process.env.GITHUB_REF_NAME || 'main',
            mode: 'scan',
            namespace,
            createdIssues,
            vulnerabilities: scanResult.vulnerabilities || [],
            manifestFiles: scanResult.manifestFiles || {},
          });

          pipelineRunId = runResult.pipeline_run_id;
          logger.info(`[SCAN] Registered PipelineRun: ${pipelineRunId} with ${createdIssues.length} issues`);
        } catch (err) {
          logger.warn('[SCAN] Failed to register PipelineRun (non-fatal):', err);
        }
      }

      return {
        success: true,
        phase: 'scan',
        message: `Found ${scanResult.vulnerabilities.length} vulnerabilities`,
        data: { scan: scanResult, pipeline_run_id: pipelineRunId }
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
   * RFC-126: Process pending issues for an existing pipeline run.
   *
   * Discovers work via GET /pending-issues instead of GitHub label queries.
   * For each pending issue:
   * - validate actions → start validation session
   * - mitigate actions → start mitigation session, create PR, PATCH pr_url
   *
   * Idempotent: empty pending = no-op.
   */
  async executeProcess(options: ExecuteOptions): Promise<ExecuteResult> {
    const pipelineRunId = options.pipelineRunId || process.env.RSOLV_PIPELINE_RUN_ID;

    if (!pipelineRunId) {
      return {
        success: false,
        phase: 'process',
        error: 'pipeline_run_id is required for mode=process',
      };
    }

    try {
      const { PipelineRunClient } = await import('../../pipeline/pipeline-run-client.js');
      const runClient = new PipelineRunClient({
        apiUrl: process.env.RSOLV_API_URL || 'https://api.rsolv.dev',
        apiKey: this.config.rsolvApiKey || this.config.apiKey || '',
      });

      logger.info(`[PROCESS] Getting pending issues for run ${pipelineRunId}`);
      const pendingIssues = await runClient.getPendingIssues(pipelineRunId);

      if (pendingIssues.length === 0) {
        logger.info('[PROCESS] No pending issues — nothing to do');
        return {
          success: true,
          phase: 'process',
          message: 'No pending issues',
          data: { pipeline_run_id: pipelineRunId, processed: 0 },
        };
      }

      logger.info(`[PROCESS] Found ${pendingIssues.length} pending issues`);

      let validatedCount = 0;
      let mitigatedCount = 0;

      // Loop: process all pending work, re-querying after each pass.
      // Validations create mitigate-ready issues, so we loop until no pending work remains.
      const MAX_PASSES = 5;
      for (let pass = 0; pass < MAX_PASSES; pass++) {
        const pending = pass === 0
          ? pendingIssues
          : await runClient.getPendingIssues(pipelineRunId);

        if (pending.length === 0) {
          logger.info(`[PROCESS] Pass ${pass + 1}: no pending work remaining`);
          break;
        }

        logger.info(`[PROCESS] Pass ${pass + 1}: ${pending.length} pending issues`);

        const toValidate = pending.filter(i => i.pending_action === 'validate');
        const toMitigate = pending.filter(i => i.pending_action === 'mitigate');

        // Process validations
        for (const issue of toValidate) {
          logger.info(`[PROCESS] Validating issue #${issue.issue_number} (${issue.cwe_id})`);
          try {
            await this.executeValidate({
              ...options,
              issueNumber: issue.issue_number,
            });
            validatedCount++;
          } catch (err) {
            logger.error(`[PROCESS] Validation failed for issue #${issue.issue_number}`, err);
          }
        }

        // Process mitigations
        for (const issue of toMitigate) {
          logger.info(`[PROCESS] Mitigating issue #${issue.issue_number} (${issue.cwe_id})`);
          try {
            const result = await this.executeMitigate({
              ...options,
              issueNumber: issue.issue_number,
              usePriorValidation: true,
            });

            // Report PR if created
            if (result.success && result.data) {
              const resultData = result.data as Record<string, unknown>;
              const prUrl = resultData.pr_url as string | undefined;
              const prNumber = resultData.pr_number as number | undefined;
              if (prUrl && prNumber) {
                await runClient.reportPR(pipelineRunId, issue.issue_number, prUrl, prNumber);
              }
            }
            mitigatedCount++;
          } catch (err) {
            logger.error(`[PROCESS] Mitigation failed for issue #${issue.issue_number}`, err);
          }
        }

        // If we only had mitigations (no new validations), no need to re-query
        if (toValidate.length === 0) break;
      }

      return {
        success: true,
        phase: 'process',
        message: `Processed ${validatedCount} validations, ${mitigatedCount} mitigations`,
        data: {
          pipeline_run_id: pipelineRunId,
          validated: validatedCount,
          mitigated: mitigatedCount,
        },
      };
    } catch (error) {
      logger.error('[PROCESS] Process mode failed', error);
      return {
        success: false,
        phase: 'process',
        error: error instanceof Error ? error.message : String(error),
      };
    }
  }

  /**
   * Execute validation phase - RFC-058 with ValidationMode integration
   */
  async executeValidate(options: ExecuteOptions): Promise<ExecuteResult> {
    try {
      logger.info('[VALIDATE] Starting backend-orchestrated validation phase');

      // Check if we have an issue to validate
      if (!options.issueNumber || !options.repository) {
        return {
          success: false,
          phase: 'validate',
          error: 'Validation requires an issue number and repository'
        };
      }

      // Get the issue from GitHub
      const { getIssue } = await import('../../github/api.js');
      const issue = await getIssue(
        options.repository.owner,
        options.repository.name,
        options.issueNumber
      );

      if (!issue) {
        return {
          success: false,
          phase: 'validate',
          error: `Issue #${options.issueNumber} not found`
        };
      }

      // Convert GitHub issue to IssueContext format
      const issueContext: IssueContext = {
        id: `issue-${issue.number}`,
        number: issue.number,
        title: issue.title,
        body: issue.body || '',
        labels: issue.labels?.map((label: string | { name?: string }) => typeof label === 'string' ? label : label.name || '') || [],
        assignees: issue.assignees?.map((assignee: { login?: string }) => assignee.login || '') || [],
        repository: {
          owner: options.repository.owner,
          name: options.repository.name,
          fullName: `${options.repository.owner}/${options.repository.name}`,
          defaultBranch: options.repository.defaultBranch || 'main'
        },
        source: 'github' as const,
        createdAt: issue.created_at || new Date().toISOString(),
        updatedAt: issue.updated_at || new Date().toISOString(),
        metadata: {}
      };

      // Build ScanPhaseData from issue analysis or options
      const scanData: ScanPhaseData = options.scanData || {
        analysisData: {
          canBeFixed: true,
          issueType: 'security',
          vulnerabilityType: 'security',
          cwe: this.extractCweFromIssue(issueContext),
        },
      };

      // Delegate to the backend-orchestrated path
      return await this.executeValidateForIssue(issueContext, scanData, options.pipelineRunId);

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
   * Execute mitigation phase - Enhanced to use validation data
   */
  async executeMitigate(options: ExecuteOptions): Promise<ExecuteResult> {
    const startTime = Date.now();
    // Increase timeout for multi-file vulnerabilities
    // Default 30 minutes, but can be extended based on file count
    let timeout = 1800000; // 30 minute base timeout
    
    // Override timeout from environment for testing
    if (process.env.AI_TIMEOUT_OVERRIDE) {
      timeout = parseInt(process.env.AI_TIMEOUT_OVERRIDE, 10);
      logger.info(`[MITIGATE] Using timeout override: ${timeout}ms`);
    }
    
    try {
      logger.info('[MITIGATE] Starting enhanced mitigation phase', {
        issueNumber: options.issueNumber,
        repository: options.repository,
        timestamp: new Date().toISOString(),
        initialTimeout: timeout
      });
      
      // Check requirements
      if (!options.issueNumber || !options.repository) {
        logger.error('[MITIGATE] Missing required parameters');
        return {
          success: false,
          phase: 'mitigate',
          error: 'Mitigation requires an issue number and repository'
        };
      }

      // Get the issue from GitHub with timeout
      logger.info('[MITIGATE] Step 1: Fetching issue from GitHub...');
      const { getIssue } = await import('../../github/api.js');
      
      const issuePromise = getIssue(
        options.repository.owner,
        options.repository.name,
        options.issueNumber
      );
      
      const timeoutPromise = new Promise((_, reject) => 
        setTimeout(() => reject(new Error('GitHub API timeout after 30s')), 30000)
      );
      
      let issue;
      try {
        issue = await Promise.race([issuePromise, timeoutPromise]) as any;
        logger.info('[MITIGATE] Step 1 complete: Successfully fetched issue from GitHub');
      } catch (error) {
        logger.error('[MITIGATE] Step 1 failed: Error fetching issue from GitHub:', error);
        return {
          success: false,
          phase: 'mitigate',
          error: `Failed to fetch issue: ${error instanceof Error ? error.message : String(error)}`
        };
      }

      if (!issue) {
        return {
          success: false,
          phase: 'mitigate',
          error: `Issue #${options.issueNumber} not found`
        };
      }

      // Parse issue to estimate file count and adjust timeout EARLY
      logger.info('[MITIGATE] Analyzing issue for file count...');
      const issueBody = issue.body || '';
      const issueTitle = issue.title || '';
      
      // Look for file count in title or body
      let estimatedFileCount = 1;
      const fileCountMatch = issueTitle.match(/(\d+)\s+files?/i) || issueBody.match(/(\d+)\s+files?/i);
      if (fileCountMatch) {
        estimatedFileCount = parseInt(fileCountMatch[1], 10);
        logger.info(`[MITIGATE] Detected ${estimatedFileCount} files from issue description`);
      }
      
      // Adjust timeout based on estimated file count
      if (estimatedFileCount > 3) {
        const perFileTimeout = 60000; // 1 minute per file
        const newTimeout = Math.max(timeout, estimatedFileCount * perFileTimeout);
        logger.info(`[MITIGATE] Adjusting timeout for ${estimatedFileCount} files: ${timeout}ms -> ${newTimeout}ms`);
        timeout = newTimeout;
      }

      // Check for validation data with timeout
      logger.info('[MITIGATE] Step 2: Retrieving validation data...');
      const commitSha = options.commitSha || this.getCurrentCommitSha();

      logger.info('[MITIGATE] Retrieval parameters:', {
        repo: `${options.repository.owner}/${options.repository.name}`,
        issueNumber: options.issueNumber,
        commitSha: commitSha.substring(0, 8),
        commitShaFull: commitSha,
        hasProvidedValidationData: !!options.validationData
      });

      let validationData;

      // Check if validation data was provided in options first
      if (options.validationData) {
        logger.info('[MITIGATE] Using validation data provided in options');
        validationData = options.validationData;
      } else {
        // Retrieve from storage
        try {
          const dataPromise = this.retrievePhaseData(
            `${options.repository.owner}/${options.repository.name}`,
            options.issueNumber,
            commitSha
          );

          const dataTimeoutPromise = new Promise((_, reject) =>
            setTimeout(() => reject(new Error('Phase data retrieval timeout after 15s')), 15000)
          );

          validationData = await Promise.race([dataPromise, dataTimeoutPromise]) as any;
          logger.info('[MITIGATE] Step 2 complete: Retrieved validation data', {
            hasData: !!validationData,
            keys: validationData ? Object.keys(validationData) : [],
            hasValidation: !!validationData?.validation,
            hasValidate: !!validationData?.validate,
            validationKeys: validationData?.validation ? Object.keys(validationData.validation) : [],
            validateKeys: validationData?.validate ? Object.keys(validationData.validate) : []
          });
        } catch (error) {
          logger.warn('[MITIGATE] Step 2 warning: Failed to retrieve validation data:', {
            error: error instanceof Error ? error.message : String(error),
            stack: error instanceof Error ? error.stack : undefined
          });
          // Continue without validation data, will check labels
          validationData = null;
        }
      }

      // If no validation data and issue has rsolv:automate but not rsolv:validated
      logger.info('[MITIGATE] Checking labels...', {
        labels: issue.labels,
        labelType: typeof issue.labels,
        isArray: Array.isArray(issue.labels)
      });
      
      // Safe label checking - labels might be an array of strings or objects
      const labelNames = Array.isArray(issue.labels) 
        ? issue.labels.map((l: string | { name?: string }) => typeof l === 'string' ? l : l.name || '')
        : [];
      
      const hasAutomateLabel = labelNames.includes('rsolv:automate');
      const hasValidatedLabel = labelNames.includes('rsolv:validated');
      
      logger.info('[MITIGATE] Label check complete', {
        labelNames,
        hasAutomateLabel,
        hasValidatedLabel
      });
      
      if (!validationData?.validation && hasAutomateLabel && !hasValidatedLabel) {
        logger.info('[MITIGATE] Step 3: No validation found, running VALIDATE phase first');
        
        // Run validation phase with timeout
        try {
          const validatePromise = this.executeValidate(options);
          const validateTimeoutPromise = new Promise((_, reject) => 
            setTimeout(() => reject(new Error('Validation timeout after 60s')), 60000)
          );
          
          const validateResult = await Promise.race([validatePromise, validateTimeoutPromise]) as ExecuteResult;
          
          if (!validateResult.success) {
            logger.error('[MITIGATE] Step 3 failed: Auto-validation failed');
            return {
              success: false,
              phase: 'mitigate',
              error: `Auto-validation failed: ${validateResult.error}`,
              data: { validationAttempted: true }
            };
          }
          
          logger.info('[MITIGATE] Step 3a: Validation succeeded, retrieving stored data...');
          // Get the validation data that was just stored
          const dataPromise2 = this.retrievePhaseData(
            `${options.repository.owner}/${options.repository.name}`,
            options.issueNumber,
            commitSha
          );
          
          const dataTimeoutPromise2 = new Promise((_, reject) => 
            setTimeout(() => reject(new Error('Phase data retrieval timeout after 15s')), 15000)
          );
          
          validationData = await Promise.race([dataPromise2, dataTimeoutPromise2]) as any;
          logger.info('[MITIGATE] Step 3 complete: Validation data retrieved');
        } catch (error) {
          logger.error('[MITIGATE] Step 3 failed:', error);
          return {
            success: false,
            phase: 'mitigate',
            error: `Validation phase error: ${error instanceof Error ? error.message : String(error)}`,
            data: { validationError: true }
          };
        }
      }

      // RFC-096 Phase F.2: Delegate to backend-orchestrated executeMitigateForIssue
      logger.info('[MITIGATE] Step 4: Building context for backend mitigation...');

      // Build IssueContext from the fetched issue
      const issueContext: IssueContext = {
        id: String(issue.id || options.issueNumber),
        number: options.issueNumber!,
        title: issue.title || '',
        body: issue.body || '',
        labels: Array.isArray(issue.labels)
          ? issue.labels.map((l: string | { name?: string }) => typeof l === 'string' ? l : l.name || '')
          : [],
        assignees: [],
        repository: {
          ...options.repository,
          fullName: `${options.repository.owner}/${options.repository.name}`,
          defaultBranch: options.repository.defaultBranch || 'main',
        },
        source: 'github',
        createdAt: issue.created_at || new Date().toISOString(),
        updatedAt: issue.updated_at || new Date().toISOString(),
      };

      // Build ScanPhaseData from issue analysis
      const cweId = this.extractCweFromIssue(issueContext);
      const scanData: ScanPhaseData = {
        analysisData: {
          issueType: 'security',
          vulnerabilityType: cweId,
          severity: 'medium',
          estimatedComplexity: 'moderate',
          suggestedApproach: `Fix ${cweId} vulnerability`,
          filesToModify: [],
          cwe: cweId,
          isAiGenerated: true,
        },
      } as unknown as ScanPhaseData;

      logger.info('[MITIGATE] Delegating to backend-orchestrated executeMitigateForIssue');
      return await this.executeMitigateForIssue(issueContext, scanData, validationData, options.pipelineRunId);
    } catch (error) {
      const totalTime = Date.now() - startTime;
      logger.error('[MITIGATE] FAILED: Mitigation phase failed', {
        error: error instanceof Error ? error.message : String(error),
        stack: error instanceof Error ? error.stack : undefined,
        totalTimeMs: totalTime,
        totalTimeSec: Math.round(totalTime / 1000)
      });
      return {
        success: false,
        phase: 'mitigate',
        error: error instanceof Error ? error.message : String(error),
        data: {
          executionTimeMs: totalTime,
          errorDetails: error instanceof Error ? error.stack : String(error)
        }
      };
    }
  }

  /**
   * Execute all phases with PipelineRun Coordinator orchestration (RFC-124).
   *
   * Creates a PipelineRun via Channel, registers issues after SCAN,
   * reports progress during VALIDATE/MITIGATE, and passes pipelineRunId
   * to all storePhaseData calls for billing and observability.
   *
   * SCAN (creates issues) -> VALIDATE (tests them) -> MITIGATE (fixes them)
   */
  async executeAllPhases(options: ExecuteOptions): Promise<ExecuteResult> {
    const wsUrl = (process.env.RSOLV_API_URL || 'https://api.rsolv.dev')
      .replace(/^http/, 'ws') + '/action/websocket';
    const apiKey = this.config.rsolvApiKey || this.config.apiKey || '';

    // Import Channel client
    const { PipelineRunChannel } = await import('../../pipeline/pipeline-run-channel.js');
    const channel = new PipelineRunChannel({ wsUrl, apiKey });

    let pipelineRunId: string | undefined;

    try {
      logger.info('[FULL] Executing all phases with PipelineRun Coordinator');

      // Connect to Coordinator via Channel
      try {
        await channel.connect();
        const repoFullName = options.repository
          ? `${options.repository.owner}/${options.repository.name}`
          : 'unknown/unknown';
        const { runId } = await channel.createRun({
          commitSha: options.commitSha || this.getCurrentCommitSha(),
          branch: process.env.GITHUB_REF_NAME,
          mode: 'full',
          maxIssues: this.config.maxIssues || 3,
        });
        pipelineRunId = runId;
        logger.info(`[FULL] PipelineRun created: ${pipelineRunId}`);

        // Transition to scanning
        await channel.transitionStatus('scanning');
      } catch (channelError) {
        // Channel connection is non-fatal — run without Coordinator
        logger.warn('[FULL] Channel connection failed, running without Coordinator:', channelError);
      }

      // Phase 1: SCAN - Creates GitHub issues
      const scanResult = await this.executeScan(options);
      if (!scanResult.success) {
        if (pipelineRunId) {
          try { await channel.fail(scanResult.error || 'Scan failed'); } catch { /* */ }
        }
        return scanResult;
      }

      // Extract created issues from scan results
      const scanData = scanResult.data?.scan as Record<string, unknown> | undefined;
      const createdIssues = (scanData?.createdIssues || []) as Array<{ number: number }>;
      logger.info(`[FULL] Scan created ${createdIssues.length} issues (limited by max_issues: ${this.config.maxIssues})`);

      if (createdIssues.length === 0) {
        logger.info('[FULL] No issues created by scan, skipping validation and mitigation');
        if (pipelineRunId) {
          try { await channel.complete(); } catch { /* */ }
        }
        return {
          success: true,
          phase: 'full',
          message: 'No vulnerabilities found to process',
          data: { scan: scanResult.data, validations: [], mitigations: [], pipelineRunId }
        };
      }

      // Register issues with Coordinator
      if (pipelineRunId && channel.isConnected()) {
        try {
          const issuesForChannel = createdIssues.map(ci => ({
            issue_number: ci.number,
            cwe_id: undefined as string | undefined,
          }));
          await channel.registerIssues(issuesForChannel);
          logger.info(`[FULL] Registered ${issuesForChannel.length} issues with Coordinator`);
        } catch (err) {
          logger.warn('[FULL] Failed to register issues with Coordinator:', err);
        }
      }

      // Import GitHub API for fetching issue details
      const { getIssue } = await import('../../github/api.js');

      // Fetch full issue details for each created issue
      const issues: IssueContext[] = [];
      for (const createdIssue of createdIssues) {
        try {
          const issue = await getIssue(
            options.repository!.owner,
            options.repository!.name,
            createdIssue.number
          );
          issues.push(issue);
        } catch (error) {
          logger.error(`[FULL] Failed to fetch issue #${createdIssue.number}:`, error);
        }
      }

      if (issues.length === 0) {
        if (pipelineRunId) {
          try { await channel.fail('Failed to fetch issue details after scan'); } catch { /* */ }
        }
        return { success: false, phase: 'full', error: 'Failed to fetch issue details after scan' };
      }

      // Phase 2: VALIDATE - Test each issue via backend pipeline
      logger.info(`[FULL] Validating ${issues.length} issues via backend pipeline`);
      const validationResults: Array<{issue: IssueContext, result: ExecuteResult}> = [];

      for (const issue of issues) {
        try {
          logger.info(`[FULL] Validating issue #${issue.number}`);

          const issueScanData: ScanPhaseData = {
            analysisData: {
              canBeFixed: true,
              issueType: 'security',
              vulnerabilityType: 'security',
              cwe: this.extractCweFromIssue(issue),
            },
          };

          const validateResult = await this.executeValidateForIssue(issue, issueScanData, pipelineRunId);
          validationResults.push({ issue, result: validateResult });

          // Store validation with pipelineRunId for billing
          if (pipelineRunId) {
            try {
              const repoFullName = `${issue.repository?.owner || ''}/${issue.repository?.name || ''}`;
              const commitSha = this.getCurrentCommitSha();
              const validationEntry = validateResult.data?.validation as Record<string, unknown> | undefined;
              if (validationEntry) {
                await this.storePhaseData('validation', validationEntry, {
                  repo: repoFullName,
                  issueNumber: issue.number,
                  commitSha,
                  pipelineRunId,
                });
              }
            } catch (storeErr) {
              logger.warn(`[FULL] Failed to store validation with pipelineRunId:`, storeErr);
            }
          }
        } catch (error) {
          logger.error(`[FULL] Validation failed for issue #${issue.number}:`, error);
          validationResults.push({
            issue,
            result: { success: false, phase: 'validate', error: error instanceof Error ? error.message : String(error) }
          });
        }
      }

      // Count validated issues
      const isValidated = (result: ExecuteResult): boolean => {
        const validation = result.data?.validation as Record<string, Record<string, unknown>> | undefined;
        if (!validation) return false;
        return Object.values(validation).some(v => v?.validated === true);
      };
      const validatedIssues = validationResults.filter(v => v.result.success && isValidated(v.result));
      logger.info(`[FULL] ${validatedIssues.length} of ${issues.length} issues validated`);

      // Phase 3: MITIGATE - Fix validated vulnerabilities
      // Coordinator knows which issues are validated — no label polling needed
      const mitigationResults: ExecuteResult[] = [];
      for (const validation of validatedIssues) {
        try {
          logger.info(`[FULL] Mitigating issue #${validation.issue.number}`);

          // Build scan data for mitigation
          const cweId = this.extractCweFromIssue(validation.issue);
          const mitigateScanData: ScanPhaseData = {
            analysisData: {
              issueType: 'security',
              vulnerabilityType: cweId,
              severity: 'medium',
              estimatedComplexity: 'moderate',
              suggestedApproach: `Fix ${cweId} vulnerability`,
              filesToModify: [],
              cwe: cweId,
              isAiGenerated: true,
            },
          } as unknown as ScanPhaseData;

          // Use validation data from the result (no label polling, no retrieval needed)
          const mitigateResult = await this.executeMitigateForIssue(
            validation.issue,
            mitigateScanData,
            validation.result.data,
            pipelineRunId
          );
          mitigationResults.push(mitigateResult);

          // RFC-126: Report PR URL to platform via PATCH endpoint
          if (pipelineRunId && mitigateResult.success && mitigateResult.data) {
            try {
              const prUrl = (mitigateResult.data as Record<string, unknown>).prUrl as string | undefined;
              const prNumber = (mitigateResult.data as Record<string, unknown>).prNumber as number | undefined;
              if (prUrl && prNumber) {
                const { PipelineRunClient } = await import('../../pipeline/pipeline-run-client.js');
                const runClient = new PipelineRunClient({
                  apiUrl: process.env.RSOLV_API_URL || 'https://api.rsolv.dev',
                  apiKey: this.config.rsolvApiKey || this.config.apiKey || '',
                });
                await runClient.reportPR(pipelineRunId, validation.issue.number, prUrl, prNumber);
                logger.info(`[FULL] Reported PR #${prNumber} for issue #${validation.issue.number}`);
              }
            } catch (reportErr) {
              logger.warn('[FULL] Failed to report PR URL:', reportErr);
            }
          }
        } catch (error) {
          logger.error(`[FULL] Mitigation failed for issue #${validation.issue.number}:`, error);
          mitigationResults.push({
            success: false,
            phase: 'mitigate',
            error: error instanceof Error ? error.message : String(error)
          });
        }
      }

      const successfulMitigations = mitigationResults.filter(m => m.success).length;

      // Complete the run
      if (pipelineRunId && channel.isConnected()) {
        try { await channel.complete(); } catch { /* */ }
      }

      return {
        success: true,
        phase: 'full',
        message: `Completed all phases: ${createdIssues.length} issues processed, ${validatedIssues.length} validated, ${successfulMitigations} mitigated`,
        data: {
          scan: scanResult.data,
          validations: validationResults.map(v => v.result),
          mitigations: mitigationResults,
          pipelineRunId,
        }
      };
    } catch (error) {
      logger.error('[FULL] Full execution failed', error);
      if (pipelineRunId && channel.isConnected()) {
        try { await channel.fail(error instanceof Error ? error.message : String(error)); } catch { /* */ }
      }
      return {
        success: false,
        phase: 'full',
        error: error instanceof Error ? error.message : String(error)
      };
    } finally {
      channel.disconnect();
    }
  }

  /**
   * @deprecated RFC-126: Storage is now server-side (Orchestrator.complete_with_storage).
   * Retained as no-op to avoid breaking callers during transition.
   */
  async storePhaseData(
    _phase: 'scan' | 'validation' | 'mitigation',
    _data: Record<string, unknown>,
    _metadata: PhaseMetadata & { commitSha: string }
  ): Promise<void> {
    // No-op: storage is handled server-side by Phases.store_from_session
  }

  /**
   * Retrieve phase data from platform (read-only).
   */
  async retrievePhaseData(repo: string, issueNumber: number, commitSha: string): Promise<PhaseData | null> {
    const client = new (await import('../phase-data-client/index.js')).PhaseDataClient(
      this.config.rsolvApiKey || this.config.apiKey || '',
      process.env.RSOLV_API_URL
    );
    return client.retrievePhaseResults(repo, issueNumber, commitSha);
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
        vulnerabilities: [], // No vulnerabilities found in single issue analysis
        timestamp: new Date().toISOString(),
        commitHash: this.getCurrentCommitSha(),
        // Additional data for internal use
        canBeFixed: analysisData.canBeFixed || false,
        analysisData,
        gitStatus
      };
      
      // RFC-126: Scan storage now handled server-side via POST /api/v1/pipeline-runs
      
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
    scanData: ScanPhaseData,
    pipelineRunId?: string
  ): Promise<ExecuteResult> {
    // RFC-096 Phase F: Backend-orchestrated pipeline is the sole code path
    try {
      logger.info(`[VALIDATE] Starting backend-orchestrated validation for issue #${issue.number}`);

      const rsolvApiUrl = process.env.RSOLV_API_URL || 'https://api.rsolv.dev';
      const validationClient = new ValidationClient({
        baseUrl: rsolvApiUrl,
        apiKey: this.config.rsolvApiKey!,
      });

      const { analysisData } = scanData;

      // Extract vulnerability info from issue and scan data
      const cweId = analysisData.cwe || 'CWE-unknown';
      const vulnerabilityType = analysisData.vulnerabilityType || analysisData.issueType || cweId;
      const sourceFile = analysisData.filesToModify?.[0];

      // Determine framework from existing test infrastructure
      const frameworkName = this.detectTestFramework();

      // Ensure the runtime is available for bash tool requests during the SSE session.
      // The backend AI sends bash commands (e.g., "bundle exec rspec") that need the
      // runtime installed. Without this, executeBash() has mise shims on PATH but no
      // actual runtime binary, causing the AI to fall back to JS.
      if (frameworkName !== 'unknown') {
        try {
          const testRunner = new TestRunner();
          await testRunner.ensureRuntime(frameworkName as TestFramework, process.cwd());
          logger.info(`[VALIDATE] Runtime ensured for framework: ${frameworkName}`);
        } catch (err) {
          const message = err instanceof Error ? err.message : String(err);
          logger.warn(`[VALIDATE] Failed to ensure runtime for ${frameworkName}: ${message} — continuing anyway`);
        }
      }

      // Build context for the backend orchestrator
      const repoFullName = `${issue.repository?.owner || ''}/${issue.repository?.name || ''}`;
      const commitSha = this.getCurrentCommitSha();
      const validationContext: ValidationContext = {
        vulnerability: {
          type: vulnerabilityType,
          description: issue.body || issue.title,
          location: sourceFile,
          source: sourceFile,
        },
        framework: {
          name: frameworkName,
        },
        cwe_id: cweId,
        namespace: repoFullName,
        repo: repoFullName,
        repoPath: process.cwd(),
        // RFC-126: Pass pipeline context so platform can store execution records
        pipeline_run_id: pipelineRunId,
        issue_number: issue.number,
        commit_sha: commitSha,
      };

      // Run the backend-orchestrated validation
      const result = await validationClient.runValidation(validationContext);

      // Build validation data for storage (matches live path structure)
      const validationData = {
        issueNumber: issue.number,
        validated: result.validated,
        test_path: result.test_path,
        test_code: result.test_code,
        framework: result.framework || frameworkName,
        cwe_id: result.cwe_id || cweId,
        classification: result.classification,
        test_type: result.test_type,
        retry_count: result.retry_count,
        timestamp: new Date().toISOString(),
        error: result.error,
        backendOrchestrated: true,
      };

      // Store phase data (no-op: storage is server-side via RFC-126)
      await this.storePhaseData('validation', {
        [`issue-${issue.number}`]: validationData,
      }, {
        repo: repoFullName,
        issueNumber: issue.number,
        commitSha,
      });

      // Apply GitHub labels based on classification
      const currentLabels = issue.labels?.map(
        (l: string | { name?: string }) => typeof l === 'string' ? l : l.name || ''
      ) || [];
      await applyValidationLabels({
        owner: issue.repository?.owner || '',
        repo: issue.repository?.name || '',
        issueNumber: issue.number,
        currentLabels,
      }, result.classification);

      if (!result.validated) {
        logger.warn(`[VALIDATE] Backend validation did not validate: ${result.error || 'test did not prove vulnerability'}`);
        return {
          success: false,
          phase: 'validate',
          message: result.error || 'Backend validation did not validate the vulnerability',
          data: {
            validation: {
              [`issue_${issue.number}`]: validationData,
            },
          },
        };
      }

      logger.info(`[VALIDATE] Backend validation succeeded: ${result.test_path}`);

      // Commit the test file if it exists
      if (result.test_path) {
        try {
          // Configure git user if needed
          try {
            execSync('git config user.name', { encoding: 'utf-8' });
          } catch {
            execSync('git config user.name "RSOLV[bot]"', { encoding: 'utf-8' });
            execSync('git config user.email "bot@rsolv.dev"', { encoding: 'utf-8' });
          }

          execSync(`git add "${result.test_path}"`, { encoding: 'utf-8' });
          const commitMsg = `test: RED test for ${cweId} vulnerability`;
          execSync(`git commit -m "${commitMsg.replace(/"/g, '\\"')}"`, { encoding: 'utf-8' });
          logger.info(`[VALIDATE] Committed test file: ${result.test_path}`);
        } catch (gitError) {
          logger.warn(`[VALIDATE] Git commit failed (test file may not exist on disk): ${gitError}`);
        }
      }

      return {
        success: true,
        phase: 'validate',
        message: 'Tests generated successfully via backend pipeline',
        data: {
          validation: {
            [`issue_${issue.number}`]: validationData,
          },
        },
      };
    } catch (error) {
      logger.error('[VALIDATE] Backend validation failed', error);
      return {
        success: false,
        phase: 'validate',
        error: error instanceof Error ? error.message : String(error),
      };
    }
  }

  /**
   * Detect the test framework from the current repo's file structure.
   * Returns a best-guess framework name for the backend orchestrator.
   */
  private detectTestFramework(): string {
    const fs = require('fs');
    const path = require('path');
    const cwd = process.cwd();

    // Check for framework-specific files/dirs
    if (fs.existsSync(path.join(cwd, 'spec'))) return 'rspec';
    if (fs.existsSync(path.join(cwd, 'test', 'test_helper.exs'))) return 'exunit';
    if (fs.existsSync(path.join(cwd, 'vitest.config.ts')) || fs.existsSync(path.join(cwd, 'vitest.config.js'))) return 'vitest';
    if (fs.existsSync(path.join(cwd, 'jest.config.ts')) || fs.existsSync(path.join(cwd, 'jest.config.js'))) return 'jest';
    if (fs.existsSync(path.join(cwd, 'pytest.ini')) || fs.existsSync(path.join(cwd, 'conftest.py'))) return 'pytest';
    if (fs.existsSync(path.join(cwd, 'phpunit.xml')) || fs.existsSync(path.join(cwd, 'phpunit.xml.dist'))) return 'phpunit';
    if (fs.existsSync(path.join(cwd, 'pom.xml'))) return 'junit';
    if (fs.existsSync(path.join(cwd, 'build.gradle')) || fs.existsSync(path.join(cwd, 'build.gradle.kts'))) return 'junit';

    // Check package.json for test runner
    try {
      const pkgPath = path.join(cwd, 'package.json');
      if (fs.existsSync(pkgPath)) {
        const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf-8'));
        const deps = { ...pkg.dependencies, ...pkg.devDependencies };
        if (deps.vitest) return 'vitest';
        if (deps.jest) return 'jest';
        if (deps.mocha) return 'mocha';
      }
    } catch {
      // ignore parse errors
    }

    // Check Gemfile for test runner
    try {
      const gemfilePath = path.join(cwd, 'Gemfile');
      if (fs.existsSync(gemfilePath)) {
        const gemfile = fs.readFileSync(gemfilePath, 'utf-8');
        if (gemfile.includes('rspec')) return 'rspec';
        if (gemfile.includes('minitest')) return 'minitest';
      }
    } catch {
      // ignore read errors
    }

    // Check requirements.txt / pyproject.toml for pytest
    try {
      const reqPath = path.join(cwd, 'requirements.txt');
      if (fs.existsSync(reqPath)) {
        const reqs = fs.readFileSync(reqPath, 'utf-8');
        if (reqs.includes('pytest')) return 'pytest';
      }
    } catch {
      // ignore
    }

    return 'unknown';
  }

  /**
   * Extract CWE ID from issue title/body/labels.
   * Falls back to 'CWE-unknown' if not found.
   */
  private extractCweFromIssue(issue: IssueContext): string {
    // Check labels first (e.g., "CWE-89")
    const labels = issue.labels || [];
    for (const label of labels) {
      const labelStr = typeof label === 'string' ? label : (label as { name?: string }).name || '';
      const cweMatch = labelStr.match(/CWE-\d+/);
      if (cweMatch) return cweMatch[0];
    }

    // Check title
    const titleMatch = issue.title?.match(/CWE-\d+/);
    if (titleMatch) return titleMatch[0];

    // Check body
    const bodyMatch = issue.body?.match(/CWE-\d+/);
    if (bodyMatch) return bodyMatch[0];

    return 'CWE-unknown';
  }

  /**
   * Execute MITIGATE phase for a single issue.
   * RFC-096 Phase F: Backend-orchestrated pipeline is the sole code path.
   */
  async executeMitigateForIssue(
    issue: IssueContext,
    scanData: ScanPhaseData,
    validationData: unknown,
    pipelineRunId?: string
  ): Promise<ExecuteResult> {
    const startTime = Date.now();

    try {
      logger.info(`[MITIGATE] Starting backend-orchestrated mitigation for issue #${issue.number}`);

      // Ensure the runtime is available for bash tool requests during MITIGATE.
      // Same rationale as VALIDATE: the backend AI sends bash commands that need
      // the runtime installed (e.g., "bundle exec rspec" to verify the fix).
      const frameworkName = this.detectTestFramework();
      if (frameworkName !== 'unknown') {
        try {
          const testRunner = new TestRunner();
          await testRunner.ensureRuntime(frameworkName as TestFramework, process.cwd());
          logger.info(`[MITIGATE] Runtime ensured for framework: ${frameworkName}`);
        } catch (err) {
          const message = err instanceof Error ? err.message : String(err);
          logger.warn(`[MITIGATE] Failed to ensure runtime for ${frameworkName}: ${message} — continuing anyway`);
        }
      }

      const rsolvApiUrl = process.env.RSOLV_API_URL || 'https://api.rsolv.dev';
      const mitigationClient = new MitigationClient({
        baseUrl: rsolvApiUrl,
        apiKey: this.config.rsolvApiKey!,
      });

      const { analysisData } = scanData;

      // Build context for the backend orchestrator
      const commitSha = this.getCurrentCommitSha();
      const mitigationContext: MitigationContext = {
        issue: {
          title: issue.title,
          body: issue.body || '',
          number: issue.number,
        },
        analysis: {
          summary: `${analysisData.issueType} issue analysis`,
          complexity: analysisData.estimatedComplexity === 'simple' ? 'low' :
            analysisData.estimatedComplexity === 'complex' ? 'high' : 'medium',
          recommended_approach: analysisData.suggestedApproach,
          related_files: analysisData.filesToModify,
          cwe: analysisData.cwe,
        },
        repoPath: process.cwd(),
        namespace: `${issue.repository?.owner || ''}/${issue.repository?.name || ''}`,
        // RFC-126: Pipeline context for server-side storage
        pipeline_run_id: pipelineRunId,
        issue_number: issue.number,
        commit_sha: commitSha,
      };

      // Include validation data if available
      if (validationData) {
        const validateRedTest = extractValidateRedTest(
          validationData as Record<string, unknown>,
          issue.number
        );
        if (validateRedTest) {
          mitigationContext.validationData = {
            red_test: {
              test_path: validateRedTest.testFile,
              test_code: validateRedTest.testCode,
              framework: validateRedTest.framework,
              test_command: `${validateRedTest.framework} ${validateRedTest.testFile}`,
            },
          };
        }
      }

      // Run the backend-orchestrated mitigation
      const result = await mitigationClient.runMitigation(mitigationContext);

      if (!result.success) {
        logger.error(`[MITIGATE] Backend mitigation failed: ${result.error}`);
        return {
          success: false,
          phase: 'mitigate',
          error: result.error || 'Backend mitigation failed',
        };
      }

      logger.info(`[MITIGATE] Backend mitigation completed: ${result.title}`);

      // Check for modified files (the backend orchestrator made changes via tool_requests)
      const modifiedFiles = execSync('git diff --name-only', { encoding: 'utf-8' }).trim().split('\n').filter(Boolean);

      if (modifiedFiles.length === 0) {
        logger.warn('[MITIGATE] No files modified by backend orchestrator');
        return {
          success: false,
          phase: 'mitigate',
          error: 'No files were modified during mitigation',
        };
      }

      // Create commit from modified files
      logger.info(`[MITIGATE] Creating commit for ${modifiedFiles.length} modified files`);

      // Configure git user if needed
      try {
        execSync('git config user.name', { encoding: 'utf-8' });
      } catch {
        execSync('git config user.name "RSOLV[bot]"', { encoding: 'utf-8' });
        execSync('git config user.email "bot@rsolv.dev"', { encoding: 'utf-8' });
      }

      const commitMessage = result.title || `fix: ${issue.title}`;
      execSync(`git add ${modifiedFiles.map(f => `"${f}"`).join(' ')}`, { encoding: 'utf-8' });
      execSync(`git commit -m "${commitMessage.replace(/"/g, '\\"')}"`, { encoding: 'utf-8' });
      const commitHash = execSync('git rev-parse HEAD', { encoding: 'utf-8' }).trim();

      // Get diff stats
      const diffStatOutput = execSync('git diff HEAD~1 --stat', { encoding: 'utf-8' });
      const statMatch = diffStatOutput.match(/(\d+) files? changed(?:, (\d+) insertions?\(\+\))?(?:, (\d+) deletions?\(-\))?/);
      const diffStats = {
        filesChanged: statMatch ? parseInt(statMatch[1], 10) : modifiedFiles.length,
        insertions: statMatch ? parseInt(statMatch[2] || '0', 10) : 0,
        deletions: statMatch ? parseInt(statMatch[3] || '0', 10) : 0,
      };

      // Create PR
      logger.info(`[MITIGATE] Creating PR from commit ${commitHash.substring(0, 8)}`);

      const prResult = await createEducationalPullRequest(
        issue,
        commitHash,
        {
          title: result.title || issue.title,
          description: result.description || '',
          vulnerabilityType: scanData.analysisData.vulnerabilityType || 'security',
          severity: scanData.analysisData.severity || 'medium',
          cwe: scanData.analysisData.cwe,
          isAiGenerated: scanData.analysisData.isAiGenerated,
          educationalContent: result.educational_content,
        },
        this.config,
        diffStats,
        validationData as PrValidationData
      );

      const duration = Date.now() - startTime;
      logger.info(`[MITIGATE] Completed in ${duration}ms`);

      // Store mitigation phase data for cross-phase persistence
      const issueKey = `issue-${issue.number}`;
      const mitigationResult = {
        fixed: prResult.success,
        prUrl: prResult.pullRequestUrl,
        prNumber: prResult.pullRequestNumber,
        filesModified: modifiedFiles,
        commitHash,
        backendOrchestrated: true,
        timestamp: new Date().toISOString(),
      };

      try {
        await this.storePhaseData('mitigation', {
          [issueKey]: mitigationResult,
        }, {
          repo: `${issue.repository?.owner || ''}/${issue.repository?.name || ''}`,
          issueNumber: issue.number,
          commitSha: commitHash,
        });
        logger.info(`[MITIGATE] Phase data stored for issue #${issue.number}`);
      } catch (storeError) {
        logger.warn('[MITIGATE] Failed to store phase data (non-fatal):', storeError);
      }

      return {
        success: prResult.success,
        phase: 'mitigate',
        message: prResult.message,
        data: {
          pullRequestUrl: prResult.pullRequestUrl,
          pullRequestNumber: prResult.pullRequestNumber,
          commitHash,
          filesModified: modifiedFiles,
          diffStats,
          backendOrchestrated: true,
        },
      };
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      logger.error(`[MITIGATE] Error: ${message}`);
      return {
        success: false,
        phase: 'mitigate',
        error: `Backend mitigation error: ${message}`,
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
      const scanPhaseData = scanResult.data as unknown as ScanPhaseData;
      const validateResult = await this.executeValidateForIssue(issue, scanPhaseData);
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
        scanPhaseData,
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

  // Properties for mocking in tests
  public testGeneratingAnalyzer?: TestGeneratingSecurityAnalyzer;
  public testRunner?: any;
  public testDiscovery?: any;
  public testIntegrator?: any;
  public githubClient?: any;

  /**
   * Execute standalone validation mode for multiple issues
   * Generates tests without requiring prior scan
   */
  async executeValidateStandalone(options: ExecuteOptions): Promise<ExecuteResult> {
    try {
      logger.info(`[VALIDATE-STANDALONE] Processing ${options.issues?.length} issues via backend pipeline`);

      if (!options.issues || options.issues.length === 0) {
        return {
          success: false,
          phase: 'validate',
          error: 'No issues provided for validation'
        };
      }

      const validations: ValidationItem[] = [];

      for (const issue of options.issues) {
        try {
          // Check for prior scan data if requested
          let scanData: ScanPhaseData | null = null;
          if (options.usePriorScan) {
            const priorData = await this.retrievePhaseData(
              `${issue.repository.owner}/${issue.repository.name}`,
              issue.number,
              this.getCurrentCommitSha()
            );
            if (priorData?.scan) {
              scanData = priorData.scan as unknown as ScanPhaseData;
            }
          }

          // Build minimal scan data from issue context (no AI call needed —
          // backend enriches from stored SCAN data via PhaseContext)
          if (!scanData) {
            const cweId = this.extractCweFromIssue(issue);
            scanData = {
              analysisData: {
                issueType: 'security',
                vulnerabilityType: cweId,
                severity: 'medium',
                estimatedComplexity: 'moderate',
                suggestedApproach: `Validate ${cweId} vulnerability`,
                filesToModify: [],
                cwe: cweId,
                canBeFixed: true,
              },
              canBeFixed: true,
              usedPriorScan: false,
            };
          }

          // Skip validation if issue cannot be fixed
          const canBeFixed = scanData.canBeFixed ?? scanData.analysisData?.canBeFixed ?? true;
          if (!canBeFixed) {
            logger.info(`[VALIDATE] Skipping issue #${issue.number} - cannot be automatically fixed`);
            validations.push({
              issueNumber: issue.number,
              validated: false,
              canBeFixed: false,
              reason: 'Issue cannot be automatically fixed',
              usedPriorScan: scanData.usedPriorScan || false,
              timestamp: new Date().toISOString()
            });
            continue;
          }

          // Delegate to backend-orchestrated validation
          logger.info(`[VALIDATE-STANDALONE] Delegating issue #${issue.number} to backend pipeline`);
          const result = await this.executeValidateForIssue(issue, scanData);

          // Extract validation data from result for aggregation
          const validationEntry = result.data?.validation as Record<string, unknown> | undefined;
          const issueKey = `issue_${issue.number}`;
          const issueData = (validationEntry?.[issueKey] || validationEntry?.[`issue-${issue.number}`] || validationEntry || {}) as Record<string, unknown>;

          validations.push({
            issueNumber: issue.number,
            validated: (issueData.validated as boolean | undefined) ?? result.success,
            test_path: issueData.test_path,
            test_code: issueData.test_code,
            framework: issueData.framework,
            cwe_id: issueData.cwe_id,
            classification: issueData.classification,
            test_type: issueData.test_type,
            retry_count: issueData.retry_count,
            timestamp: (issueData.timestamp as string | undefined) || new Date().toISOString(),
            error: (issueData.error as string | undefined) || result.error,
            backendOrchestrated: true,
            usedPriorScan: scanData.usedPriorScan || false,
          });

          // Post GitHub comment if requested
          if (options.postComment && this.githubClient) {
            const comment = this.formatValidationComment(issue, issueData);
            await this.githubClient.createIssueComment(
              issue.repository.owner,
              issue.repository.name,
              issue.number,
              comment
            );
          }

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

      // Check if any validations succeeded
      const hasSuccessfulValidation = validations.some(v =>
        v.validated !== false &&
        !v.testGenerationFailed &&
        v.canBeFixed !== false
      );

      // For single issue, return simpler structure
      if (options.issues.length === 1) {
        const validation = validations[0];
        const isSuccess = validation.validated !== false &&
                         validation.canBeFixed !== false &&
                         !validation.testGenerationFailed;

        return {
          success: isSuccess,
          phase: 'validate',
          message: validation.canBeFixed === false ?
            'Issue cannot be automatically fixed' :
            validation.testGenerationFailed ?
              'Test generation failed' :
              `Validation completed for issue #${options.issues[0].number}`,
          data: {
            validation,
            report
          },
          error: validation.testGenerationFailed ? validation.error : undefined
        };
      }

      return {
        success: hasSuccessfulValidation,
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
  private async generateValidationTests(issue: IssueContext, scanData: ScanPhaseData | { vulnerabilities: any[]; timestamp: string; commitHash: string; analysisData?: any }): Promise<ValidationPhaseData> {
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
          success: tests?.success ?? true,
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
  private async getCodebaseFiles(analysisData: ScanPhaseData['analysisData']): Promise<Map<string, string>> {
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
  private generateFallbackTests(issue: IssueContext): ValidationPhaseData['generatedTests'] {
    return {
      success: false,
      redTest: `// RED Test: Should fail when ${issue.title} exists`,
      greenTest: `// GREEN Test: Should pass when ${issue.title} is fixed`,  
      refactorTest: '// REFACTOR Test: Should maintain functionality after fix'
    };
  }

  /**
   * Format validation results as GitHub comment
   */
  private formatValidationComment(issue: IssueContext, validation: ValidationPhaseData): string {
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
  private generateValidationReport(validations: ValidationItem[], format: string): string {
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
  private generateMarkdownReport(validations: ValidationItem[]): string {
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
  private generateGitHubActionsReport(validations: ValidationPhaseData[]): string {
    return validations.map(v => 
      `::${v.falsePositive ? 'warning' : 'notice'} ::Issue #${v.issueNumber} validated`
    ).join('\n');
  }

  /**
   * Generate GitHub Actions annotations
   */
  private generateGitHubAnnotations(validations: ValidationPhaseData[]): string[] {
    return validations.map(v => 
      `::warning file=unknown,line=1::Issue #${v.issueNumber} - ${v.falsePositive ? 'Possible false positive' : 'Validation complete'}`
    );
  }

  /**
   * Mitigation-only mode: Apply fixes using validation data
   * Can accept validation data directly or retrieve from prior phase
   */
  async executeMitigateStandalone(options: ExecuteOptions): Promise<ExecuteResult> {
    try {
      logger.info(`[MITIGATE-STANDALONE] Starting mitigation for ${options.issues?.length || 1} issues`);
      
      // Check for required inputs
      if (!options.issues || options.issues.length === 0) {
        // Try to retrieve from PhaseDataClient if we have repository info
        if (options.repository && options.issueNumber) {
          const phaseData = await this.retrievePhaseData(
            `${options.repository.owner}/${options.repository.name}`,
            options.issueNumber,
            await this.getCurrentCommitSha()
          );
          
          // Check both 'validation' and 'validate' (PhaseDataClient remaps validation->validate)
          if (!phaseData?.validation && !phaseData?.validate) {
            return {
              success: false,
              phase: 'mitigate',
              error: 'No validation data available for mitigation'
            };
          }
          
          // Create issue from repository info
          const issue: IssueContext = {
            id: `issue-${options.issueNumber}`,
            number: options.issueNumber,
            title: 'Issue from prior validation',
            body: '',
            labels: [],
            assignees: [],
            repository: {
              ...options.repository,
              fullName: `${options.repository.owner}/${options.repository.name}`,
              defaultBranch: options.repository.defaultBranch || 'main'
            },
            source: 'github',
            createdAt: new Date().toISOString(),
            updatedAt: new Date().toISOString(),
            metadata: {}
          };
          
          options.issues = [issue];
          options.validationData = phaseData;
        } else {
          return {
            success: false,
            phase: 'mitigate',
            error: 'No issues provided for mitigation'
          };
        }
      }
      
      // Check for validation data
      let validationData = options.validationData;
      
      if (!validationData && options.usePriorValidation) {
        // Try to retrieve validation data for each issue
        const collectedValidation: Record<string, unknown> = {};

        for (const issue of options.issues) {
          const phaseData = await this.retrievePhaseData(
            issue.repository.fullName,
            issue.number,
            await this.getCurrentCommitSha()
          );

          // Handle both 'validation' and 'validate' (PhaseDataClient remaps validation->validate)
          if (phaseData?.validation) {
            Object.assign(collectedValidation, phaseData.validation);
          } else if (phaseData?.validate) {
            Object.assign(collectedValidation, phaseData.validate);
          }
        }

        validationData = { validation: collectedValidation };
      }
      
      const validationEntries = (validationData as Record<string, unknown>)?.validation;
      if (!validationData || Object.keys((validationEntries as Record<string, unknown>) || {}).length === 0) {
        if (options.generateTestsIfMissing) {
          // Generate tests on the fly
          logger.info('[MITIGATE-STANDALONE] No validation data, generating tests...');
          const validateResult = await this.executeValidateStandalone(options);
          
          if (!validateResult.success) {
            return {
              success: false,
              phase: 'mitigate',
              error: 'Failed to generate validation tests'
            };
          }
          
          validationData = validateResult.data;
        } else {
          return {
            success: false,
            phase: 'mitigate',
            error: 'No validation data provided or found'
          };
        }
      }
      
      // RFC-096 Phase F.2: Delegate to backend-orchestrated executeMitigateForIssue
      const mitigationResults: Record<string, unknown> = {};
      let allSuccess = true;
      let partialSuccess = false;

      for (const issue of options.issues) {
        const issueKey = issue.number;

        // Build ScanPhaseData from issue context
        const cweId = this.extractCweFromIssue(issue);
        const scanData: ScanPhaseData = {
          analysisData: {
            issueType: 'security',
            vulnerabilityType: cweId,
            severity: 'medium',
            estimatedComplexity: 'moderate',
            suggestedApproach: `Fix ${cweId} vulnerability`,
            filesToModify: [],
            cwe: cweId,
            isAiGenerated: true,
          },
        } as unknown as ScanPhaseData;

        try {
          const timeout = options.timeout || 1800000;
          const mitigationPromise = this.executeMitigateForIssue(
            issue,
            scanData,
            validationData
          );

          const result = await Promise.race([
            mitigationPromise,
            new Promise<ExecuteResult>((_, reject) =>
              setTimeout(() => reject(new Error('Mitigation timeout')), timeout)
            ),
          ]);

          mitigationResults[issueKey] = result.data || { success: result.success };

          if (!result.success) {
            allSuccess = false;
          } else {
            partialSuccess = true;
          }
        } catch (error) {
          logger.error(`[MITIGATE-STANDALONE] Failed to mitigate issue #${issue.number}:`, error);
          mitigationResults[issueKey] = {
            success: false,
            error: error instanceof Error ? error.message : 'Unknown error',
          };
          allSuccess = false;
        }
      }
      
      // Generate report if requested
      let report: string | undefined;
      let jsonReport: Record<string, unknown> | undefined;
      
      if (options.format === 'markdown') {
        report = this.generateMitigationMarkdownReport(mitigationResults);
      } else if (options.format === 'json') {
        jsonReport = {
          mitigations: Object.entries(mitigationResults).map(([key, result]) => ({
            issue: key,
            ...(typeof result === 'object' && result !== null ? result : { result })
          }))
        };
      }
      
      // Store results — executeMitigateForIssue already stores per-issue,
      // but standalone also stores the aggregate for report generation
      try {
        await this.storePhaseData('mitigation', mitigationResults, {
          repo: options.issues[0].repository.fullName,
          issueNumber: options.issues.length === 1 ? options.issues[0].number : undefined,
          commitSha: this.getCurrentCommitSha(),
        });
      } catch (storeError) {
        logger.warn('[MITIGATE-STANDALONE] Failed to store aggregate results (non-fatal):', storeError);
      }
      
      return {
        success: allSuccess,
        phase: 'mitigate',
        message: !allSuccess && partialSuccess ? 'Partial success' : undefined,
        data: {
          mitigation: mitigationResults,
          testsGenerated: options.generateTestsIfMissing
        },
        report,
        jsonReport
      };
    } catch (error) {
      logger.error('[MITIGATE-STANDALONE] Unexpected error:', error);
      return {
        success: false,
        phase: 'mitigate',
        error: error instanceof Error ? error.message : 'Unknown error'
      };
    }
  }


  /**
   * Generate markdown report for mitigation
   */
  private generateMitigationMarkdownReport(mitigations: Record<string, unknown>): string {
    let report = '## Mitigation Report\n\n';

    for (const [key, result] of Object.entries(mitigations)) {
      const issueNumber = key.replace('issue-', '');
      report += `### Issue #${issueNumber}\n`;

      const entry = result as Record<string, unknown>;
      if (entry.success) {
        report += '✅ Fixed\n';
        if (entry.prUrl) {
          report += `- PR: ${entry.prUrl}\n`;
        }
        if (entry.testsPass) {
          report += '- Tests: Passing\n';
        }
      } else {
        report += `❌ Failed: ${entry.error}\n`;
      }

      report += '\n';
    }

    return report;
  }

  /**
   * Test helper: Inject dependencies for testing
   * @internal Only use in tests
   */
  _setTestDependencies(deps: {
    scanner?: ScanOrchestrator;
  }): void {
    if (process.env.NODE_ENV !== 'test' && process.env.RSOLV_TESTING_MODE !== 'true') {
      throw new Error('_setTestDependencies can only be called in test environment');
    }

    if (deps.scanner) {
      this.scanner = deps.scanner;
    }
  }
}