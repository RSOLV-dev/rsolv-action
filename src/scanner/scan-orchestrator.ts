import { RepositoryScanner } from './repository-scanner.js';
import { IssueCreator } from './issue-creator.js';
import { logger } from '../utils/logger.js';
import type { ScanConfig, ScanResult } from './types.js';

export class ScanOrchestrator {
  private scanner: RepositoryScanner;
  private issueCreator: IssueCreator;

  constructor() {
    this.scanner = new RepositoryScanner();
    this.issueCreator = new IssueCreator();
  }

  async performScan(config: ScanConfig): Promise<ScanResult> {
    logger.info('Starting proactive security scan');
    
    try {
      // Perform the scan
      const scanResult = await this.scanner.scan(config);
      
      // Create issues if configured and vulnerabilities found
      if (config.createIssues && scanResult.groupedVulnerabilities.length > 0) {
        logger.info(`Creating issues for ${scanResult.groupedVulnerabilities.length} vulnerability groups`);
        
        const createdIssues = await this.issueCreator.createIssuesFromGroups(
          scanResult.groupedVulnerabilities,
          config
        );
        
        scanResult.createdIssues = createdIssues;
        logger.info(`Created ${createdIssues.length} issues`);
      }
      
      // Output summary
      this.logScanSummary(scanResult);
      
      return scanResult;
    } catch (error) {
      logger.error('Scan failed:', error);
      throw error;
    }
  }

  private logScanSummary(result: ScanResult): void {
    logger.info('');
    logger.info('=== SECURITY SCAN SUMMARY ===');
    logger.info(`Repository: ${result.repository}`);
    logger.info(`Branch: ${result.branch}`);
    logger.info(`Files scanned: ${result.scannedFiles}/${result.totalFiles}`);
    logger.info(`Total vulnerabilities: ${result.vulnerabilities.length}`);
    logger.info('');
    
    if (result.groupedVulnerabilities.length > 0) {
      logger.info('Vulnerabilities by type:');
      for (const group of result.groupedVulnerabilities) {
        logger.info(`  - ${group.type} (${group.severity}): ${group.count} instances in ${group.files.length} files`);
      }
      logger.info('');
    }
    
    if (result.createdIssues.length > 0) {
      logger.info('Created issues:');
      for (const issue of result.createdIssues) {
        logger.info(`  - #${issue.number}: ${issue.title}`);
        logger.info(`    ${issue.url}`);
      }
      logger.info('');
    }
    
    logger.info('=============================');
  }
}