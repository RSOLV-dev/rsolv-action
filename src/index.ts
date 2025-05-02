import { loadConfig } from './config/index';
import { detectIssues } from './github/issues';
import { securityCheck } from './utils/security';
import { logger } from './utils/logger';
import { processIssues } from './ai/processor';
import { setupContainer } from './containers/setup';
import { ActionStatus } from './types/index';

async function run(): Promise<ActionStatus> {
  try {
    // Log startup information
    logger.info('Starting RSOLV action');
    
    // Load configuration
    const config = await loadConfig();
    logger.info('Configuration loaded successfully');
    
    // Verify security constraints
    await securityCheck(config);
    logger.info('Security check passed');
    
    // Set up containerized environment for code analysis
    await setupContainer(config);
    logger.info('Analysis container ready');
    
    // Detect issues for automation
    const issues = await detectIssues(config);
    logger.info(`Found ${issues.length} issues for automation`);
    
    if (issues.length === 0) {
      logger.info('No issues to process, exiting');
      return { success: true, message: 'No issues found for automation' };
    }
    
    // Process issues with AI
    const results = await processIssues(issues, config);
    logger.info(`Successfully processed ${results.filter(r => r.success).length}/${issues.length} issues`);
    
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
