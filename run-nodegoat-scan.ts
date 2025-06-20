#!/usr/bin/env bun
// Script to run security scan on NodeGoat demo repository

import { ScanOrchestrator } from './src/scanner/scan-orchestrator.js';
import { logger } from './src/utils/logger.js';
import type { ScanConfig } from './src/scanner/types.js';

async function runNodeGoatScan() {
  logger.info('🔍 Starting NodeGoat security scan demonstration');
  
  // Configuration for the scan
  const config: ScanConfig = {
    repository: {
      owner: 'RSOLV-dev',
      name: 'nodegoat-vulnerability-demo',
      defaultBranch: 'main'
    },
    createIssues: true,
    issueLabel: 'rsolv:security',
    filePatterns: ['**/*.js', '**/*.ts'],
    excludePatterns: ['node_modules/**', 'test/**', 'coverage/**'],
    maxFilesToScan: 100
  };
  
  const orchestrator = new ScanOrchestrator();
  
  try {
    logger.info(`📂 Scanning repository: ${config.repository.owner}/${config.repository.name}`);
    logger.info(`🏷️  Issues will be labeled: ${config.issueLabel}`);
    
    const result = await orchestrator.performScan(config);
    
    logger.info('\n✅ Scan complete!');
    logger.info(`📊 Summary:`);
    logger.info(`   - Files scanned: ${result.scannedFiles}`);
    logger.info(`   - Vulnerabilities found: ${result.vulnerabilities.length}`);
    logger.info(`   - Vulnerability groups: ${result.groupedVulnerabilities.length}`);
    logger.info(`   - Issues created: ${result.createdIssues.length}`);
    
    if (result.createdIssues.length > 0) {
      logger.info('\n📝 Created issues:');
      result.createdIssues.forEach(issue => {
        logger.info(`   - Issue #${issue.number}: ${issue.title}`);
        logger.info(`     ${issue.url}`);
      });
    }
    
    return result;
  } catch (error) {
    logger.error('❌ Scan failed:', error);
    throw error;
  }
}

// Run the scan
if (import.meta.main) {
  runNodeGoatScan()
    .then(() => {
      logger.info('\n🎉 Demo complete!');
      process.exit(0);
    })
    .catch((error) => {
      logger.error('Fatal error:', error);
      process.exit(1);
    });
}