import { loadConfig } from './config/index.js';
import { detectIssuesFromAllPlatforms } from './platforms/issue-detector.js';
import { securityCheck } from './utils/security.js';
import { logger } from './utils/logger.js';
import { processIssues } from './ai/unified-processor.js';
import { setupContainer } from './containers/setup.js';
import { ActionStatus } from './types/index.js';
import { ScanOrchestrator } from './scanner/index.js';
import { getRepositoryDetails } from './github/api.js';

async function run(): Promise<ActionStatus> {
  try {
    // Log startup information
    logger.info('Starting RSOLV action');
    
    // Load configuration
    const config = await loadConfig();
    logger.info('Configuration loaded successfully');
    
    // Check if we're in scan mode
    const scanMode = process.env.RSOLV_SCAN_MODE || 'fix';
    
    if (scanMode === 'scan') {
      logger.info('Running in SCAN mode - proactive vulnerability detection');
      
      // Get repository information from environment
      const repoFullName = process.env.GITHUB_REPOSITORY;
      if (!repoFullName) {
        throw new Error('GITHUB_REPOSITORY environment variable not set');
      }
      
      const [owner, name] = repoFullName.split('/');
      const repoDetails = await getRepositoryDetails(owner, name);
      
      // Run security scan
      const scanOrchestrator = new ScanOrchestrator();
      const scanResult = await scanOrchestrator.performScan({
        mode: 'scan',
        repository: {
          owner,
          name,
          defaultBranch: repoDetails.defaultBranch || 'main'
        },
        createIssues: true,
        batchSimilar: true,
        issueLabel: config.issueLabel || 'rsolv:automate'
      });
      
      // Set outputs for GitHub Actions
      if (process.env.GITHUB_OUTPUT) {
        const fs = await import('fs');
        fs.appendFileSync(process.env.GITHUB_OUTPUT, `scan_results=${JSON.stringify(scanResult)}\n`);
        fs.appendFileSync(process.env.GITHUB_OUTPUT, `created_issues=${JSON.stringify(scanResult.createdIssues)}\n`);
      }
      
      return {
        success: true,
        message: `Security scan completed. Found ${scanResult.vulnerabilities.length} vulnerabilities and created ${scanResult.createdIssues.length} issues.`
      };
    }
    
    // Otherwise, continue with normal fix mode
    logger.info('Running in FIX mode - processing existing issues');
    
    // Verify security constraints
    await securityCheck(config);
    logger.info('Security check passed');
    
    // Set up containerized environment for code analysis
    await setupContainer(config);
    logger.info('Analysis container ready');
    
    // Detect issues for automation from all configured platforms
    const issues = await detectIssuesFromAllPlatforms(config);
    logger.info(`Found ${issues.length} issues for automation across all platforms`);
    
    if (issues.length === 0) {
      logger.info('No issues to process, exiting');
      return { success: true, message: 'No issues found for automation' };
    }
    
    // Process issues with AI (enable security analysis and enhanced context by default)
    const processingOptions = {
      enableSecurityAnalysis: config.enableSecurityAnalysis !== false, // Default to true
      enableEnhancedContext: true, // Enable Claude Code enhanced context gathering
      verboseLogging: process.env.DEBUG === 'true'
    };
    
    // Add overall timeout to prevent hanging, but allow time for complex analysis
    // This supports multi-LLM orchestration where Claude Code coordinates multiple AI models
    const WORKFLOW_TIMEOUT = 1200000; // 20 minutes - allow time for complex multi-LLM orchestrated analysis
    const timeoutPromise = new Promise<never>((_, reject) => {
      setTimeout(() => {
        reject(new Error(`Workflow timeout: Processing ${issues.length} issues took longer than ${WORKFLOW_TIMEOUT/1000} seconds`));
      }, WORKFLOW_TIMEOUT);
    });
    
    const results = await Promise.race([
      processIssues(issues, config, processingOptions),
      timeoutPromise
    ]);
    
    logger.info(`Successfully processed ${results.filter((r: { success: boolean }) => r.success).length}/${issues.length} issues`);
    
    return { 
      success: true, 
      message: `RSOLV action completed successfully. Processed ${results.length} issues.` 
    };
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
