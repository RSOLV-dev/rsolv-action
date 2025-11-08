/**
 * RFC-081 Integration Test: Issue Lifecycle State Management
 *
 * This test proves that the skip logic correctly integrates with the existing system
 * and handles the complete three-phase workflow (SCAN → VALIDATE → MITIGATE).
 *
 * Test Scenarios:
 * 1. First SCAN run creates issues with rsolv:detected
 * 2. VALIDATE phase changes labels from rsolv:detected to rsolv:validated
 * 3. Second SCAN run skips validated issues (no duplicates)
 * 4. Statistics accurately track all state transitions
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { IssueCreator } from '../issue-creator.js';
import { ScanOrchestrator } from '../scan-orchestrator.js';
import type { VulnerabilityGroup, ScanConfig, GitHubIssue } from '../types.js';
import { getGitHubClient } from '../../github/api.js';

vi.mock('../../github/api.js');
vi.mock('../../utils/logger.js');
vi.mock('../../github/label-manager.js', () => ({
  ensureLabelsExist: vi.fn().mockResolvedValue(undefined)
}));

describe('RFC-081: Issue Lifecycle Integration Test', () => {
  let mockGitHub: any;
  let issueCreator: IssueCreator;

  // Simulate issue database
  const issueDatabase: Map<string, GitHubIssue & { body: string }> = new Map();
  let nextIssueNumber = 1;

  beforeEach(() => {
    vi.clearAllMocks();
    issueDatabase.clear();
    nextIssueNumber = 1;

    // Mock GitHub API with realistic behavior
    mockGitHub = {
      issues: {
        listForRepo: vi.fn(async ({ labels }: { labels: string }) => {
          const issues = Array.from(issueDatabase.values())
            .filter(issue =>
              issue.labels.some(label =>
                typeof label === 'string' ? label === labels : label.name === labels
              )
            );
          return { data: issues };
        }),

        create: vi.fn(async ({ title, body, labels }: any) => {
          const issue: GitHubIssue & { body: string } = {
            number: nextIssueNumber++,
            title,
            body,
            html_url: `https://github.com/test/repo/issues/${nextIssueNumber - 1}`,
            labels: labels.map((l: string) => ({ name: l }))
          };

          // Store by vulnerability type label
          const vulnTypeLabel = labels.find((l: string) => l.startsWith('rsolv:vuln-'));
          if (vulnTypeLabel) {
            issueDatabase.set(vulnTypeLabel, issue);
          }

          return { data: issue };
        }),

        update: vi.fn(async ({ issue_number, title, body }: any) => {
          const issue = Array.from(issueDatabase.values()).find(i => i.number === issue_number);
          if (issue) {
            issue.title = title;
            issue.body = body;
          }
          return { data: issue };
        }),

        createComment: vi.fn().mockResolvedValue({ data: {} })
      },

      git: {
        getTree: vi.fn().mockResolvedValue({
          data: { tree: [] }
        })
      }
    };

    vi.mocked(getGitHubClient).mockReturnValue(mockGitHub);

    issueCreator = new IssueCreator();
  });

  /**
   * Simulates the VALIDATE phase changing issue labels
   */
  function simulateValidationPhase(issueNumbers: number[], markAsValidated: boolean = true) {
    for (const issue of issueDatabase.values()) {
      if (issueNumbers.includes(issue.number)) {
        // Remove rsolv:detected, add rsolv:validated or rsolv:false-positive
        issue.labels = issue.labels.filter(l =>
          (typeof l === 'string' ? l : l.name) !== 'rsolv:detected'
        );

        const newLabel = markAsValidated ? 'rsolv:validated' : 'rsolv:false-positive';
        issue.labels.push({ name: newLabel });
      }
    }
  }

  it('INTEGRATION: Full three-phase workflow - SCAN → VALIDATE → SCAN', async () => {
    const config: ScanConfig = {
      repository: { owner: 'test', name: 'repo', defaultBranch: 'main' },
      createIssues: true,
      issueLabel: 'rsolv:detected',
      batchSimilar: true
    };

    const vulnerabilityGroups: VulnerabilityGroup[] = [
      {
        type: 'sql-injection',
        severity: 'critical',
        count: 3,
        files: ['db.js', 'query.js'],
        vulnerabilities: []
      },
      {
        type: 'xss',
        severity: 'high',
        count: 2,
        files: ['render.js'],
        vulnerabilities: []
      },
      {
        type: 'command-injection',
        severity: 'critical',
        count: 1,
        files: ['exec.js'],
        vulnerabilities: []
      }
    ];

    // ===== PHASE 1: Initial SCAN =====
    console.log('\n📊 PHASE 1: Initial SCAN');

    const firstScanResult = await issueCreator.createIssuesFromGroups(
      vulnerabilityGroups,
      config
    );

    // Verify: All issues created with rsolv:detected
    expect(firstScanResult.issues).toHaveLength(3);
    expect(firstScanResult.skippedValidated).toBe(0);
    expect(firstScanResult.skippedFalsePositive).toBe(0);
    expect(mockGitHub.issues.create).toHaveBeenCalledTimes(3);

    // Verify: All issues have rsolv:detected label
    for (const issue of issueDatabase.values()) {
      const hasDetectedLabel = issue.labels.some(l =>
        (typeof l === 'string' ? l : l.name) === 'rsolv:detected'
      );
      expect(hasDetectedLabel).toBe(true);
    }

    console.log(`✅ Created ${firstScanResult.issues.length} issues`);
    console.log('   Issue #1: SQL Injection (rsolv:detected)');
    console.log('   Issue #2: XSS (rsolv:detected)');
    console.log('   Issue #3: Command Injection (rsolv:detected)');

    // ===== PHASE 2: VALIDATE Phase =====
    console.log('\n🔍 PHASE 2: VALIDATE (simulated)');

    // Simulate validation phase: Mark issues #1 and #2 as validated, #3 as false-positive
    simulateValidationPhase([1, 2], true);  // Validated
    simulateValidationPhase([3], false);     // False positive

    // Verify: Labels changed correctly
    const issue1 = Array.from(issueDatabase.values()).find(i => i.number === 1)!;
    const issue2 = Array.from(issueDatabase.values()).find(i => i.number === 2)!;
    const issue3 = Array.from(issueDatabase.values()).find(i => i.number === 3)!;

    expect(issue1.labels.some(l => (typeof l === 'string' ? l : l.name) === 'rsolv:validated')).toBe(true);
    expect(issue2.labels.some(l => (typeof l === 'string' ? l : l.name) === 'rsolv:validated')).toBe(true);
    expect(issue3.labels.some(l => (typeof l === 'string' ? l : l.name) === 'rsolv:false-positive')).toBe(true);

    console.log('✅ Issue #1: SQL Injection → rsolv:validated');
    console.log('✅ Issue #2: XSS → rsolv:validated');
    console.log('✅ Issue #3: Command Injection → rsolv:false-positive');

    // ===== PHASE 3: Second SCAN (with same vulnerabilities) =====
    console.log('\n🔄 PHASE 3: Second SCAN (re-run on same codebase)');

    vi.clearAllMocks(); // Clear call counts but keep database

    const secondScanResult = await issueCreator.createIssuesFromGroups(
      vulnerabilityGroups,
      config
    );

    // Verify: No new issues created, all existing issues skipped
    expect(secondScanResult.issues).toHaveLength(0);
    expect(secondScanResult.skippedValidated).toBe(2);  // SQL Injection, XSS
    expect(secondScanResult.skippedFalsePositive).toBe(1);  // Command Injection
    expect(mockGitHub.issues.create).not.toHaveBeenCalled();
    expect(mockGitHub.issues.update).not.toHaveBeenCalled();

    console.log(`✅ Skipped ${secondScanResult.skippedValidated} validated issues`);
    console.log(`✅ Skipped ${secondScanResult.skippedFalsePositive} false positive issues`);
    console.log('✅ No duplicate issues created');

    // Verify: Issue count unchanged
    expect(issueDatabase.size).toBe(3);
  });

  it('INTEGRATION: Mixed workflow - some new, some validated, some false-positive', async () => {
    const config: ScanConfig = {
      repository: { owner: 'test', name: 'repo', defaultBranch: 'main' },
      createIssues: true,
      issueLabel: 'rsolv:detected',
      batchSimilar: true
    };

    // First scan: Create initial issues
    const initialGroups: VulnerabilityGroup[] = [
      { type: 'sql-injection', severity: 'critical', count: 1, files: ['db.js'], vulnerabilities: [] },
      { type: 'xss', severity: 'high', count: 1, files: ['page.js'], vulnerabilities: [] }
    ];

    await issueCreator.createIssuesFromGroups(initialGroups, config);

    // Simulate validation: SQL validated, XSS marked false-positive
    simulateValidationPhase([1], true);
    simulateValidationPhase([2], false);

    vi.clearAllMocks();

    // Second scan: Same issues + new command-injection
    const secondGroups: VulnerabilityGroup[] = [
      { type: 'sql-injection', severity: 'critical', count: 1, files: ['db.js'], vulnerabilities: [] },
      { type: 'xss', severity: 'high', count: 1, files: ['page.js'], vulnerabilities: [] },
      { type: 'command-injection', severity: 'critical', count: 1, files: ['exec.js'], vulnerabilities: [] }
    ];

    const result = await issueCreator.createIssuesFromGroups(secondGroups, config);

    // Verify: Only new issue created, existing ones skipped
    expect(result.issues).toHaveLength(1);
    expect(result.issues[0].vulnerabilityType).toBe('command-injection');
    expect(result.skippedValidated).toBe(1);
    expect(result.skippedFalsePositive).toBe(1);
    expect(mockGitHub.issues.create).toHaveBeenCalledTimes(1);
  });

  it('INTEGRATION: Statistics aggregation through ScanOrchestrator', async () => {
    const orchestrator = new ScanOrchestrator();

    // Mock the scanner to return vulnerabilities
    const mockVulnerabilityGroups: VulnerabilityGroup[] = [
      { type: 'sql-injection', severity: 'critical', count: 1, files: ['db.js'], vulnerabilities: [] },
      { type: 'xss', severity: 'high', count: 1, files: ['page.js'], vulnerabilities: [] }
    ];

    orchestrator['scanner'].scan = vi.fn().mockResolvedValue({
      repository: 'test/repo',
      branch: 'main',
      scanDate: new Date().toISOString(),
      totalFiles: 10,
      scannedFiles: 10,
      vulnerabilities: [],
      groupedVulnerabilities: mockVulnerabilityGroups,
      createdIssues: []
    });

    const config: ScanConfig = {
      repository: { owner: 'test', name: 'repo', defaultBranch: 'main' },
      createIssues: true,
      issueLabel: 'rsolv:detected',
      batchSimilar: true
    };

    // First scan
    const firstResult = await orchestrator.performScan(config);
    expect(firstResult.createdIssues).toHaveLength(2);
    expect(firstResult.skippedValidated).toBe(0);  // No validated issues yet
    expect(firstResult.skippedFalsePositive).toBe(0);  // No false positives yet

    // Simulate validation
    simulateValidationPhase([1], true);
    simulateValidationPhase([2], false);

    // Second scan
    const secondResult = await orchestrator.performScan(config);
    expect(secondResult.createdIssues).toHaveLength(0);
    expect(secondResult.skippedValidated).toBe(1);
    expect(secondResult.skippedFalsePositive).toBe(1);
  });

  it('PROPERTY: Skip logic is idempotent - multiple scans produce same result', async () => {
    const config: ScanConfig = {
      repository: { owner: 'test', name: 'repo', defaultBranch: 'main' },
      createIssues: true,
      issueLabel: 'rsolv:detected',
      batchSimilar: true
    };

    const groups: VulnerabilityGroup[] = [
      { type: 'sql-injection', severity: 'critical', count: 1, files: ['db.js'], vulnerabilities: [] }
    ];

    // Initial scan
    await issueCreator.createIssuesFromGroups(groups, config);
    simulateValidationPhase([1], true);

    vi.clearAllMocks();

    // Run scan 5 times
    const results = [];
    for (let i = 0; i < 5; i++) {
      const result = await issueCreator.createIssuesFromGroups(groups, config);
      results.push(result);
    }

    // Verify: All scans produce identical results
    for (const result of results) {
      expect(result.issues).toHaveLength(0);
      expect(result.skippedValidated).toBe(1);
      expect(result.skippedFalsePositive).toBe(0);
    }

    // Verify: No new issues created, no updates
    expect(mockGitHub.issues.create).not.toHaveBeenCalled();
    expect(mockGitHub.issues.update).not.toHaveBeenCalled();
    expect(issueDatabase.size).toBe(1);
  });

  it('PROPERTY: Label extraction handles all GitHub label formats', async () => {
    const config: ScanConfig = {
      repository: { owner: 'test', name: 'repo', defaultBranch: 'main' },
      createIssues: true,
      issueLabel: 'rsolv:detected',
      batchSimilar: true
    };

    // Create issue with mixed label formats
    const mixedLabelIssue: GitHubIssue & { body: string } = {
      number: 999,
      title: 'Test Issue',
      body: 'Test',
      html_url: 'https://github.com/test/repo/issues/999',
      labels: [
        'rsolv:validated',  // String format
        { name: 'rsolv:vuln-sql-injection' },  // Object format
        { name: 'security' },
        'critical'  // String format
      ]
    };

    issueDatabase.set('rsolv:vuln-sql-injection', mixedLabelIssue);

    const groups: VulnerabilityGroup[] = [
      { type: 'sql-injection', severity: 'critical', count: 1, files: ['db.js'], vulnerabilities: [] }
    ];

    const result = await issueCreator.createIssuesFromGroups(groups, config);

    // Verify: Correctly identified as validated despite mixed label formats
    expect(result.skippedValidated).toBe(1);
    expect(result.issues).toHaveLength(0);
  });

  it('INVARIANT: Skip statistics always sum correctly', async () => {
    const config: ScanConfig = {
      repository: { owner: 'test', name: 'repo', defaultBranch: 'main' },
      createIssues: true,
      issueLabel: 'rsolv:detected',
      batchSimilar: true
    };

    const groups: VulnerabilityGroup[] = [
      { type: 'sql-injection', severity: 'critical', count: 1, files: ['db.js'], vulnerabilities: [] },
      { type: 'xss', severity: 'high', count: 1, files: ['page.js'], vulnerabilities: [] },
      { type: 'command-injection', severity: 'critical', count: 1, files: ['exec.js'], vulnerabilities: [] },
      { type: 'path-traversal', severity: 'high', count: 1, files: ['file.js'], vulnerabilities: [] }
    ];

    await issueCreator.createIssuesFromGroups(groups, config);

    // Mark in different states
    simulateValidationPhase([1, 2], true);  // 2 validated
    simulateValidationPhase([3], false);     // 1 false-positive
    // Issue 4 remains detected

    vi.clearAllMocks();

    const result = await issueCreator.createIssuesFromGroups(groups, config);

    // Invariant: created + skippedValidated + skippedFalsePositive = total groups
    const totalProcessed = result.issues.length + result.skippedValidated + result.skippedFalsePositive;
    expect(totalProcessed).toBe(groups.length);

    // Verify breakdown
    expect(result.issues).toHaveLength(1);  // Path traversal (updated)
    expect(result.skippedValidated).toBe(2);
    expect(result.skippedFalsePositive).toBe(1);
  });
});
