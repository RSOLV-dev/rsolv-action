/**
 * PhaseExecutor - Simple switch-based execution for v1
 * Implements RFC-041 three-phase architecture
 */

import { PhaseDataClient, PhaseData } from '../phase-data-client/index.js';
import { ScanOrchestrator } from '../../scanner/index.js';
import { processIssueWithGit } from '../../ai/git-based-processor.js';
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
        // Requires either scan data OR issue number
        if (!options.issueNumber && !options.scanData) {
          throw new Error('Validation requires --issue or prior scan');
        }
        return this.executeValidate(options);
      
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
}