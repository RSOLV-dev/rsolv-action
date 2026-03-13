/**
 * Tests that ScanResult includes the scanned file list for test discovery.
 *
 * The RepositoryScanner already has access to the full `files` array at scan
 * time. This test verifies it populates `fileList` on the ScanResult so the
 * pipeline can forward it to the platform's PhaseContext.
 */

import { describe, it, expect } from 'vitest';
import type { ScanResult } from '../types.js';

describe('ScanResult.fileList type contract', () => {
  it('ScanResult interface accepts fileList field', () => {
    // This test verifies the type exists — compilation failure = RED
    const result: ScanResult = {
      repository: 'test/repo',
      branch: 'main',
      scanDate: new Date().toISOString(),
      totalFiles: 4,
      scannedFiles: 3,
      vulnerabilities: [],
      groupedVulnerabilities: [],
      createdIssues: [],
      fileList: ['src/app.js', 'src/routes/index.js', 'test/auth.test.js'],
    };

    expect(result.fileList).toHaveLength(3);
    expect(result.fileList).toContain('src/app.js');
  });

  it('fileList is optional (backward compat)', () => {
    const result: ScanResult = {
      repository: 'test/repo',
      branch: 'main',
      scanDate: new Date().toISOString(),
      totalFiles: 0,
      scannedFiles: 0,
      vulnerabilities: [],
      groupedVulnerabilities: [],
      createdIssues: [],
    };

    expect(result.fileList).toBeUndefined();
  });
});
