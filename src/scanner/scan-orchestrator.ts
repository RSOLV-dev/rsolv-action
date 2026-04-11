import { RepositoryScanner } from './repository-scanner.js';
import { IssueCreator } from './issue-creator.js';
import { GitHubAdapter } from '../forge/github-adapter.js';
import { logger } from '../utils/logger.js';
import { ensureLabelsExist } from '../github/label-manager.js';
import type { ScanConfig, ScanResult, ScanReport, VulnerabilityGroup } from './types.js';
import type { ScanPlanResponse, ScanPlanFinding } from './types.js';
import type { Vulnerability } from '../security/types.js';
import { prioritizeFindings, prioritizeFindingInstances, fetchSeverityTiers } from './finding-prioritizer.js';
import type { SeverityTierMap } from './finding-prioritizer.js';
import { ScanPlanClient } from './scan-plan-client.js';

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
      let prioritizedFindings: Vulnerability[] | undefined;

      const hasVulnerabilities = scanResult.vulnerabilities.length > 0;

      if (hasVulnerabilities && (shouldCreateIssues || shouldGenerateReport)) {
        tiers = await this.fetchTiers();
        // RFC-142: Prioritize individual findings for per-instance issue creation
        prioritizedFindings = prioritizeFindingInstances(scanResult.vulnerabilities, tiers);
        // Keep group-based prioritization for reports
        if (scanResult.groupedVulnerabilities.length > 0) {
          prioritized = prioritizeFindings(scanResult.groupedVulnerabilities, tiers);
        }
      }

      // RFC-146 Phase 2: Budget-aware scan planning + issue creation
      let scanPlan: ScanPlanResponse | null = null;

      if (shouldCreateIssues && prioritizedFindings && prioritizedFindings.length > 0) {
        // Step 1: Query the platform for budget-aware plan
        const apiUrl = process.env.RSOLV_API_URL || 'https://api.rsolv.dev';
        const apiKey = process.env.RSOLV_API_KEY || '';

        if (apiKey) {
          const planClient = new ScanPlanClient({ apiUrl, apiKey });

          const planFindings: ScanPlanFinding[] = prioritizedFindings.map(f => ({
            cwe_id: f.cweId || 'CWE-unknown',
            severity: f.severity,
            file_path: f.filePath || 'unknown',
            line: f.line,
            type: f.type,
            confidence: String(f.confidence || 'medium'),
          }));

          try {
            scanPlan = await planClient.getPlan({
              findings: planFindings,
              max_issues: config.maxIssues || 3,
              max_validations: config.maxValidations ?? undefined,
              namespace: `${config.repository.owner}/${config.repository.name}`,
            });

            if (scanPlan) {
              logger.info(
                `[ScanPlan] Budget: ${scanPlan.budget.validate_used}/${scanPlan.budget.validate_limit} used, ` +
                `effective cap: ${scanPlan.budget.effective_cap}, ` +
                `selected: ${scanPlan.selected.length}, deferred: ${scanPlan.deferred.length}`
              );
            }
          } catch (error) {
            // Hard failure (401/403/400) — fail the job
            logger.error(`[ScanPlan] Hard failure: ${error}`);
            throw error;
          }
        }

        // Step 2: Apply plan to select which findings to process
        let findingsToProcess: Vulnerability[];
        if (scanPlan) {
          // Map selected findings back to original Vulnerability objects.
          // Keys use the same fallbacks as planFindings construction above.
          const selectedSet = new Set(
            scanPlan.selected.map(f => `${f.cwe_id}:${f.file_path}:${f.line}`)
          );
          findingsToProcess = prioritizedFindings.filter(f =>
            selectedSet.has(`${f.cweId || 'CWE-unknown'}:${f.filePath || 'unknown'}:${f.line}`)
          );
        } else {
          // Fallback: conservative default (planning endpoint unavailable)
          const fallbackCap = Math.min(
            config.maxIssues || 3,
            config.maxValidations ?? Infinity
          );
          findingsToProcess = prioritizedFindings.slice(0, fallbackCap);
          logger.warn(`[ScanPlan] Using conservative fallback — processing ${findingsToProcess.length} findings`);
        }

        // Step 3: Create issues from selected findings
        logger.info(
          `RFC-142: Creating per-instance issues for ${findingsToProcess.length} findings` +
          (config.maxIssues ? ` (max_issues: ${config.maxIssues})` : '')
        );

        const result = await this.issueCreator.createIssuesFromFindings(
          findingsToProcess,
          { ...config, createIssues: true }
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

      // Attach plan metadata for job summary (Task 10)
      (scanResult as unknown as Record<string, unknown>).scanPlan = scanPlan;

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
