import { Vulnerability, Severity } from '../security/types.js';

export type ScanMode = 'fix' | 'scan';

export interface ScanConfig {
  mode?: ScanMode;
  repository: {
    owner: string;
    name: string;
    defaultBranch: string;
  };
  createIssues?: boolean; // Deprecated: use scanOutput. Kept for backward compat.
  scanOutput?: ScanOutputDestination[]; // RFC-133: where findings go (default: ['issues'])
  batchSimilar?: boolean;
  issueLabel?: string;
  enableASTValidation?: boolean;
  astValidationBatchSize?: number;
  rsolvApiKey?: string; // Needed for validation API
  maxIssues?: number; // Limit number of issues to create
  maxValidations?: number; // RFC-146: Maximum validations to process, capped by budget
  scanDirectory?: string;
  excludePaths?: string[];
}

export type ScanOutputDestination = 'issues' | 'report' | 'dashboard';

export interface ScanReport {
  json: {
    repository: string;
    scanDate: string;
    findings: VulnerabilityGroup[];
    stats: { totalFiles: number; scannedFiles: number; totalVulnerabilities: number };
  };
  markdown: string;
}

export interface ScanResult {
  repository: string;
  branch: string;
  scanDate: string;
  totalFiles: number;
  scannedFiles: number;
  vulnerabilities: Vulnerability[];
  groupedVulnerabilities: VulnerabilityGroup[];
  createdIssues: CreatedIssue[];
  skippedValidated?: number;
  skippedFalsePositive?: number;
  /** RFC-101: Manifest/config file contents for project shape detection */
  manifestFiles?: Record<string, string>;
  /** Scanned file paths for platform-side test discovery (PhaseContext) */
  fileList?: string[];
  /** RFC-133: Structured scan report when scan_output includes 'report' */
  scanReport?: ScanReport;
}

export interface VulnerabilityGroup {
  type: string;
  severity: Severity;
  count: number;
  files: string[];
  vulnerabilities: Vulnerability[];
  isVendor?: boolean; // True if all vulnerabilities in group are from vendor files
}

export interface CreatedIssue {
  number: number;
  title: string;
  url: string;
  vulnerabilityType: string;
  fileCount: number;
  cweId?: string;
  /** RFC-142: file path for per-instance issues */
  filePath?: string;
  /** RFC-142: line number for per-instance issues */
  line?: number;
}

export type IssueLabel = string | { name?: string };

export interface GitHubIssue {
  number: number;
  title: string;
  html_url: string;
  labels: IssueLabel[];
}

export type ExistingIssueResult = GitHubIssue | 'skip:validated' | 'skip:false-positive' | 'skip:dismissed' | null;

export interface IssueCreationResult {
  issues: CreatedIssue[];
  skippedValidated: number;
  skippedFalsePositive: number;
  skippedDismissed?: number;
  /** RFC-142 Phase 1.5: findings skipped because an open issue already tracks them */
  skippedDuplicate?: number;
}

export interface FileToScan {
  path: string;
  content: string;
  language: string;
}

// RFC-146 Phase 2: Scan plan types

export interface ScanPlanFinding {
  cwe_id: string;
  severity: string;
  file_path: string;
  line: number;
  type: string;
  confidence: string;
}

export interface ScanPlanDeferredFinding extends ScanPlanFinding {
  reason: 'capacity_exceeded';
}

export interface ScanPlanBudget {
  tier: string;
  validate_limit: number;
  validate_used: number;
  validate_remaining: number;
  overage_cap_cents: number;
  overage_remaining_cents: number;
  max_validations: number;
  effective_cap: number;
  period_ends_at: string | null;
  currency: string;
}

export interface ScanPlanResponse {
  selected: ScanPlanFinding[];
  deferred: ScanPlanDeferredFinding[];
  budget: ScanPlanBudget;
}

export interface ScanPlanRequest {
  findings: ScanPlanFinding[];
  max_issues: number;
  max_validations?: number | null;
  namespace: string;
}