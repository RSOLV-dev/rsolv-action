import { loadConfig } from './config/index.js';
import { logger } from './utils/logger.js';
import { ActionStatus } from './types/index.js';
import { getRepositoryDetails } from './github/api.js';
import { getExecutionMode, getModeDescription } from './utils/mode-selector.js';
import { PhaseExecutor } from './modes/phase-executor/index.js';

async function run(): Promise<ActionStatus> {
  try {
    // Allow TARGET_REPOSITORY to override GITHUB_REPOSITORY for cross-repo scanning
    // (e.g., when the workflow runs in repo A but scans/creates issues in repo B)
    if (process.env.TARGET_REPOSITORY) {
      logger.info(`TARGET_REPOSITORY override: ${process.env.TARGET_REPOSITORY} (was: ${process.env.GITHUB_REPOSITORY})`);
      process.env.GITHUB_REPOSITORY = process.env.TARGET_REPOSITORY;
    }

    // Log startup information
    logger.info('Starting RSOLV action v2.0 - Enhanced Logging Active');
    logger.info(`Build timestamp: ${new Date().toISOString()}`);

    // Load configuration
    const config = await loadConfig();
    logger.info('Configuration loaded successfully');

    // Get execution mode using new mode selector
    const mode = getExecutionMode();
    logger.info(`Execution mode: ${mode} - ${getModeDescription(mode)}`);

    // Handle pipeline modes (RFC-126: scan, process, full; legacy: validate, mitigate)
    if (mode === 'scan' || mode === 'validate' || mode === 'mitigate' || mode === 'full' || mode === 'process') {
      const executor = new PhaseExecutor(config);

      // Get repository information
      const repoFullName = process.env.GITHUB_REPOSITORY;
      if (!repoFullName) {
        throw new Error('GITHUB_REPOSITORY environment variable not set');
      }

      const [owner, name] = repoFullName.split('/');
      const repoDetails = await getRepositoryDetails(owner, name);

      // Execute the selected mode
      const result = await executor.execute(mode, {
        repository: {
          owner,
          name,
          defaultBranch: repoDetails.defaultBranch || 'main',
        },
        issueNumber: process.env.RSOLV_ISSUE_NUMBER
          ? parseInt(process.env.RSOLV_ISSUE_NUMBER)
          : undefined,
        createPR: config.createPR,
        prType: process.env.RSOLV_EDUCATIONAL_PR !== 'false' ? 'educational' : 'standard',
        pipelineRunId: process.env.RSOLV_PIPELINE_RUN_ID || undefined,
      });

      // Set outputs for GitHub Actions
      if (process.env.GITHUB_OUTPUT) {
        const fs = await import('fs');
        const outputFile = process.env.GITHUB_OUTPUT;

        // Set generic phase_results output
        if (result.data) {
          fs.appendFileSync(outputFile, `phase_results=${JSON.stringify(result)}\n`);
        }

        // RFC-126: Set pipeline_run_id output for downstream steps
        if (result.data) {
          const resultData = result.data as Record<string, unknown>;
          if (resultData.pipeline_run_id) {
            fs.appendFileSync(outputFile, `pipeline_run_id=${resultData.pipeline_run_id}\n`);
          }
        }

        // Set specific outputs based on mode
        if (mode === 'scan' && result.data) {
          const scanData = result.data as Record<string, unknown>;
          // PhaseExecutor wraps scan results as { scan: ScanResult }
          const scanResult = (scanData.scan || scanData) as Record<string, unknown>;
          if (scanResult.createdIssues) {
            fs.appendFileSync(
              outputFile,
              `created_issues=${JSON.stringify(scanResult.createdIssues)}\n`
            );
            fs.appendFileSync(outputFile, `issues_created=${(scanResult.createdIssues as unknown[]).length}\n`);
          }
          if (scanResult.vulnerabilities) {
            fs.appendFileSync(
              outputFile,
              `scan_results=${JSON.stringify(scanResult.vulnerabilities)}\n`
            );
            fs.appendFileSync(
              outputFile,
              `security_findings=${JSON.stringify(scanResult.vulnerabilities)}\n`
            );
          }
        }
      }

      return {
        success: result.success,
        message: result.message || `${mode} phase completed`,
      };
    }

    // If we get here, the mode wasn't handled
    throw new Error(`Unsupported mode: ${mode}. Supported modes: scan, validate, mitigate, full, process`);
  } catch (error) {
    logger.error('Action failed', error);
    return {
      success: false,
      message: `RSOLV action failed: ${error instanceof Error ? error.message : String(error)}`
    };
  }
}

// Start the action
run().then(status => {
  if (status.success) {
    process.exit(0);
  } else {
    process.exit(1);
  }
});
