/**
 * Forge-agnostic file collection via git CLI (RFC-096 Phase D).
 *
 * Replaces GitHub API file collection with local git operations.
 * Works with any forge (GitHub, GitLab, Bitbucket, Gitea) since
 * the repo is already cloned in the CI workspace.
 */

import { execSync } from 'child_process';
import { readFileSync, existsSync } from 'fs';
import { join } from 'path';
import type { ForgeTreeEntry } from './forge-adapter.js';

/** Manifest/config files captured for project shape detection (matches repository-scanner.ts) */
const MANIFEST_FILES = [
  'Gemfile', 'Gemfile.lock', 'config/database.yml', '.ruby-version',
  'package.json', 'prisma/schema.prisma', '.node-version',
  'requirements.txt', 'pyproject.toml', 'setup.py',
  'setup.cfg', 'manage.py', '.python-version',
  'mix.exs', 'config/dev.exs', 'config/test.exs',
  'pom.xml', 'build.gradle',
  'composer.json', '.php-version',
  '.tool-versions',
];

export class GitCliScanner {
  private repoPath: string;

  constructor(repoPath: string) {
    this.repoPath = repoPath;
  }

  /**
   * Lists all files in the git repository using `git ls-tree`.
   * Returns ForgeTreeEntry[] compatible with the ForgeAdapter interface.
   */
  getFileTree(): ForgeTreeEntry[] {
    const output = execSync('git ls-tree -r --name-only HEAD', {
      cwd: this.repoPath,
      maxBuffer: 10 * 1024 * 1024, // 10MB — large repos
    });

    return output
      .toString()
      .split('\n')
      .filter((line) => line.length > 0)
      .map((path) => ({
        path,
        type: 'blob' as const,
        sha: '', // SHA not available from --name-only; not needed for scanning
      }));
  }

  /**
   * Reads file content from the local filesystem.
   * No API call — just reads from the cloned repo.
   */
  getFileContent(path: string): string | null {
    try {
      return readFileSync(join(this.repoPath, path), 'utf-8');
    } catch {
      return null;
    }
  }

  /**
   * Reads all manifest/config files that exist in the repo.
   * Same list as RepositoryScanner.MANIFEST_FILES.
   */
  getManifestFiles(): Record<string, string> {
    const result: Record<string, string> = {};

    for (const manifestPath of MANIFEST_FILES) {
      const fullPath = join(this.repoPath, manifestPath);

      if (existsSync(fullPath)) {
        try {
          result[manifestPath] = readFileSync(fullPath, 'utf-8');
        } catch {
          // Skip files that can't be read
        }
      }
    }

    return result;
  }
}
