import { Vulnerability, Severity } from '../security/types.js';

export type ScanMode = 'fix' | 'scan';

export interface ScanConfig {
  mode?: ScanMode;
  repository: {
    owner: string;
    name: string;
    defaultBranch: string;
  };
  createIssues: boolean;
  batchSimilar?: boolean;
  issueLabel: string;
  enableASTValidation?: boolean;
  astValidationBatchSize?: number;
  rsolvApiKey?: string; // Needed for validation API
  maxIssues?: number; // Limit number of issues to create
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
}

export interface FileToScan {
  path: string;
  content: string;
  language: string;
}