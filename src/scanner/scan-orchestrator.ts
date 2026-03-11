import { RepositoryScanner } from './repository-scanner.js';
import { IssueCreator } from './issue-creator.js';
import { GitHubAdapter } from '../forge/github-adapter.js';
import { logger } from '../utils/logger.js';
import { ensureLabelsExist } from '../github/label-manager.js';
import type { ScanConfig, ScanResult, ScanReport, VulnerabilityGroup } from './types.js';
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

    // RFC-133: Resolve whether to create issues from scanOutput or legacy createIssues
    const shouldCreateIssues = config.scanOutput
      ? config.scanOutput.includes('issues')
      : config.createIssues ?? true;

    const shouldGenerateReport = config.scanOutput?.includes('report') ?? false;

    try {
      // Ensure all required labels exist first
      if (shouldCreateIssues && process.env.GITHUB_TOKEN) {
        await ensureLabelsExist(
          config.repository.owner,
          config.repository.name,
          process.env.GITHUB_TOKEN
        );
      }

      // Perform the scan
      const scanResult = await this.scanner.scan(config);

      // RFC-133: Fetch tiers once — needed for both issue creation and report
      let tiers: SeverityTierMap | undefined;
      let prioritized: VulnerabilityGroup[] | undefined;

      if (scanResult.groupedVulnerabilities.length > 0 && (shouldCreateIssues || shouldGenerateReport)) {
        tiers = await this.fetchTiers();
        prioritized = prioritizeFindings(scanResult.groupedVulnerabilities, tiers);
      }

      // Create issues if configured and vulnerabilities found
      if (shouldCreateIssues && prioritized && prioritized.length > 0) {
        const maxIssues = config.maxIssues;
        const groupsToProcess = maxIssues ?
          Math.min(maxIssues, prioritized.length) :
          prioritized.length;

        logger.info(`Creating issues for ${groupsToProcess} vulnerability groups` +
                    (maxIssues && prioritized.length > maxIssues ?
                      ` (limited by max_issues: ${maxIssues})` : ''));

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

      // RFC-133: Generate structured report (includes ALL findings, not capped)
      if (shouldGenerateReport && prioritized) {
        scanResult.scanReport = this.buildReport(scanResult, prioritized);
        logger.info(`Generated scan report with ${prioritized.length} findings`);
      }

      // Output summary
      this.logScanSummary(scanResult);

      return scanResult;
    } catch (error) {
      logger.error('Scan failed:', error);
      throw error;
    }
  }

  private buildReport(scanResult: ScanResult, prioritizedGroups: VulnerabilityGroup[]): ScanReport {
    const json = {
      repository: scanResult.repository,
      scanDate: scanResult.scanDate,
      findings: prioritizedGroups,
      stats: {
        totalFiles: scanResult.totalFiles,
        scannedFiles: scanResult.scannedFiles,
        totalVulnerabilities: scanResult.vulnerabilities.length,
      },
    };

    const markdown = this.buildMarkdownReport(scanResult, prioritizedGroups);

    return { json, markdown };
  }

  private buildMarkdownReport(scanResult: ScanResult, groups: VulnerabilityGroup[]): string {
    const lines: string[] = [
      '# RSOLV Scan Report',
      '',
      `**Repository:** ${scanResult.repository}`,
      `**Date:** ${scanResult.scanDate}`,
      `**Files scanned:** ${scanResult.scannedFiles}/${scanResult.totalFiles}`,
      `**Total vulnerabilities:** ${scanResult.vulnerabilities.length}`,
      '',
      '## Findings by Severity',
      '',
      '| Type | Severity | Files | Count |',
      '|------|----------|-------|-------|',
    ];

    for (const group of groups) {
      lines.push(`| ${group.type} | ${group.severity} | ${group.files.join(', ')} | ${group.count} |`);
    }

    return lines.join('\n');
  }

  private async fetchTiers(): Promise<SeverityTierMap> {
    const apiBaseUrl = process.env.RSOLV_API_URL || 'https://api.rsolv.dev';
    const apiKey = process.env.RSOLV_API_KEY || '';

    if (!apiKey) {
      throw new Error('RSOLV_API_KEY is required for severity tier prioritization');
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

    if (result.scanReport) {
      logger.info('Scan report generated (available as workflow artifact)');
      logger.info('');
    }

    logger.info('=============================');
  }
}
