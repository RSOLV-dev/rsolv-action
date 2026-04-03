/**
 * ContextPrefetch — Builds initial context for pipeline session start (RFC-096).
 *
 * Collects repository metadata, manifest files, project shape,
 * and vulnerable file contents to send as part of the session start request.
 * This minimizes round-trips during the session.
 */

import * as fs from 'fs';
import * as path from 'path';

/** Context data sent with session start */
export interface PrefetchedContext {
  repo: string;
  issue_number?: number;
  branch?: string;
  commit_sha?: string;
  manifest_files?: Record<string, string>;
  vulnerable_files?: Record<string, string>;
}

/** Files commonly needed for project shape detection */
const MANIFEST_FILES = [
  'package.json',
  'package-lock.json',
  'Gemfile',
  'Gemfile.lock',
  'requirements.txt',
  'pyproject.toml',
  'setup.py',
  'mix.exs',
  'mix.lock',
  'pom.xml',
  'build.gradle',
  'build.gradle.kts',
  'composer.json',
  'composer.lock',
  '.ruby-version',
  '.python-version',
  '.node-version',
  '.tool-versions',
];

/**
 * Collects manifest files from the repository root.
 */
export function collectManifestFiles(repoPath: string): Record<string, string> {
  const manifests: Record<string, string> = {};

  for (const file of MANIFEST_FILES) {
    const fullPath = path.join(repoPath, file);
    try {
      if (fs.existsSync(fullPath)) {
        const stat = fs.statSync(fullPath);
        // Skip files larger than 100KB
        if (stat.size <= 100 * 1024) {
          manifests[file] = fs.readFileSync(fullPath, 'utf-8');
        }
      }
    } catch {
      // Skip files that can't be read
    }
  }

  return manifests;
}

/**
 * Reads contents of files identified as vulnerable by SCAN phase.
 */
export function collectVulnerableFiles(
  repoPath: string,
  filePaths: string[]
): Record<string, string> {
  const files: Record<string, string> = {};

  for (const filePath of filePaths) {
    const fullPath = path.join(repoPath, filePath);
    try {
      if (fs.existsSync(fullPath)) {
        const stat = fs.statSync(fullPath);
        // Skip files larger than 500KB
        if (stat.size <= 500 * 1024) {
          files[filePath] = fs.readFileSync(fullPath, 'utf-8');
        }
      }
    } catch {
      // Skip files that can't be read
    }
  }

  return files;
}
