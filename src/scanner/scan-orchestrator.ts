import { RepositoryScanner } from './repository-scanner.js';
import { IssueCreator } from './issue-creator.js';
import { GitHubAdapter } from '../forge/github-adapter.js';
import { logger } from '../utils/logger.js';
import { ensureLabelsExist } from '../github/label-manager.js';
import type { ScanConfig, ScanResult } from './types.js';
import { prioritizeFindings, fetchSeverityTiers } from './finding-prioritizer.js';
import type { SeverityTierMap } from './finding-prioritizer.js';

export class ScanOrchestrator {
  private scanner: RepositoryScanner;
  private issueCreator: IssueCreator;

  constructor() {
    this.scanner = new RepositoryScanner();
    const token = process.env.GITHUB_TOKEN || '';
    this.issueCreator = new IssueCreator(new GitHubAdapter(token));
  }

  async performScan(config: ScanConfig): Promise<ScanResult> {
    logger.info('Starting proactive security scan');
    
    try {
      // Ensure all required labels exist first
      if (config.createIssues && process.env.GITHUB_TOKEN) {
        await ensureLabelsExist(
          config.repository.owner,
          config.repository.name,
          process.env.GITHUB_TOKEN
        );
      }

      // Perform the scan
      const scanResult = await this.scanner.scan(config);

      // Create issues if configured and vulnerabilities found
      if (config.createIssues && scanResult.groupedVulnerabilities.length > 0) {
        // RFC-133: Fetch CWE severity tiers from platform (single source of truth)
        const tiers = await this.fetchTiers();

        // RFC-133: Prioritize by CWE severity tier before applying max_issues cap
        const prioritized = prioritizeFindings(scanResult.groupedVulnerabilities, tiers);

        // Respect max_issues limit in logging
        const maxIssues = config.maxIssues;
        const groupsToProcess = maxIssues ?
          Math.min(maxIssues, prioritized.length) :
          prioritized.length;

        logger.info(`Creating issues for ${groupsToProcess} vulnerability groups` +
                    (maxIssues && prioritized.length > maxIssues ?
                      ` (limited by max_issues: ${maxIssues})` : ''));

        // Slice the prioritized groups to respect max_issues limit
        const groupsToCreate = prioritized.slice(0, groupsToProcess);

        const result = await this.issueCreator.createIssuesFromGroups(
          groupsToCreate,
          config
        );

        scanResult.createdIssues = result.issues;
        scanResult.skippedValidated = result.skippedValidated;
        scanResult.skippedFalsePositive = result.skippedFalsePositive;

        logger.info(`Created ${result.issues.length} issues`);
        if (result.skippedValidated > 0) {
          logger.info(`Skipped ${result.skippedValidated} already validated issues`);
        }
        if (result.skippedFalsePositive > 0) {
          logger.info(`Skipped ${result.skippedFalsePositive} false positive issues`);
        }
      }
      
      // Output summary
      this.logScanSummary(scanResult);
      
      return scanResult;
    } catch (error) {
      logger.error('Scan failed:', error);
      throw error;
    }
  }

  private async fetchTiers(): Promise<SeverityTierMap> {
    const apiBaseUrl = process.env.RSOLV_API_BASE_URL || process.env.API_BASE_URL || '';
    const apiKey = process.env.RSOLV_API_KEY || '';

    if (!apiBaseUrl || !apiKey) {
      throw new Error('RSOLV_API_BASE_URL and RSOLV_API_KEY are required for severity tier prioritization');
    }

    return fetchSeverityTiers(apiBaseUrl, apiKey);
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

    if (result.skippedValidated || result.skippedFalsePositive) {
      logger.info('Skipped issues:');
      if (result.skippedValidated) {
        logger.info(`  - ${result.skippedValidated} validated issues`);
      }
      if (result.skippedFalsePositive) {
        logger.info(`  - ${result.skippedFalsePositive} false positive issues`);
      }
      logger.info('');
    }

    logger.info('=============================');
  }
}