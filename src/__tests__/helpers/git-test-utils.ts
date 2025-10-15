/**
 * Git Test Utilities
 *
 * Helper functions for initializing and managing git repositories in tests.
 * Ensures consistent git configuration across all test files and handles
 * differences between CI and local environments (e.g., default branch names).
 */

import { execSync } from 'child_process';

/**
 * Initialize a test git repository with consistent configuration.
 *
 * @param path - The path where the repository should be initialized
 * @param branch - The initial branch name (defaults to 'main')
 * @returns The name of the created branch
 *
 * @example
 * ```typescript
 * const testRepoPath = '/tmp/test-repo-' + Date.now();
 * fs.mkdirSync(testRepoPath, { recursive: true });
 *
 * // Initialize with default 'main' branch
 * const branchName = initTestRepo(testRepoPath);
 *
 * // Or specify a custom branch name
 * const customBranch = initTestRepo(testRepoPath, 'trunk');
 * ```
 */
export function initTestRepo(path: string, branch = 'main'): string {
  // Initialize git repository with explicit initial branch
  execSync(`git init --initial-branch=${branch}`, { cwd: path });

  // Configure git user for commits
  execSync('git config user.email "test@example.com"', { cwd: path });
  execSync('git config user.name "Test User"', { cwd: path });

  return branch;
}

/**
 * Create an initial commit in a test repository.
 * Useful for tests that need a commit history.
 *
 * @param path - The repository path
 * @param message - The commit message (defaults to 'Initial commit')
 *
 * @example
 * ```typescript
 * initTestRepo(testRepoPath);
 * fs.writeFileSync(path.join(testRepoPath, 'README.md'), '# Test Repo');
 * createInitialCommit(testRepoPath);
 * ```
 */
export function createInitialCommit(path: string, message = 'Initial commit'): void {
  execSync('git add .', { cwd: path });
  execSync(`git commit -m "${message}"`, { cwd: path });
}

/**
 * Get the current branch name in a repository.
 *
 * @param path - The repository path
 * @returns The current branch name
 */
export function getCurrentBranch(path: string): string {
  return execSync('git branch --show-current', { cwd: path })
    .toString()
    .trim();
}

/**
 * Get all branches in a repository.
 *
 * @param path - The repository path
 * @returns Array of branch names
 */
export function getAllBranches(path: string): string[] {
  return execSync('git branch --list', { cwd: path })
    .toString()
    .split('\n')
    .map(b => b.trim().replace('* ', ''))
    .filter(b => b.length > 0);
}
