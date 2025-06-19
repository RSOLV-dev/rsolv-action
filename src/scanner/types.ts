import { Vulnerability } from '../security/types.js';

export type ScanMode = 'fix' | 'scan';

export interface ScanConfig {
  mode: ScanMode;
  repository: {
    owner: string;
    name: string;
    defaultBranch: string;
  };
  createIssues: boolean;
  batchSimilar: boolean;
  issueLabel: string;
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
}

export interface VulnerabilityGroup {
  type: string;
  severity: string;
  count: number;
  files: string[];
  vulnerabilities: Vulnerability[];
}

export interface CreatedIssue {
  number: number;
  title: string;
  url: string;
  vulnerabilityType: string;
  fileCount: number;
}

export interface FileToScan {
  path: string;
  content: string;
  language: string;
}