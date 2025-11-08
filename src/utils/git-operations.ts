/**
 * Git operations helper module
 * Provides safe, testable git command utilities
 */

import { execSync } from 'child_process';

/**
 * Get the current branch name
 * @returns The current branch name, or null if it cannot be determined
 */
export function getCurrentBranch(): string | null {
  try {
    return execSync('git rev-parse --abbrev-ref HEAD', {
      encoding: 'utf-8',
      stdio: 'pipe'
    }).trim();
  } catch {
    return null;
  }
}

/**
 * Create a new branch from a commit SHA
 * If the branch already exists, switches to it and resets to the commit
 * @param branchName - Name of the branch to create
 * @param commitSha - SHA of the commit to branch from
 */
export function createBranchFromCommit(branchName: string, commitSha: string): void {
  try {
    execSync(`git checkout -b ${branchName} ${commitSha}`, {
      encoding: 'utf-8',
      stdio: 'pipe'
    });
  } catch {
    // Branch might already exist, try to switch to it and reset
    execSync(`git checkout ${branchName}`, { encoding: 'utf-8', stdio: 'pipe' });
    execSync(`git reset --hard ${commitSha}`, { encoding: 'utf-8', stdio: 'pipe' });
  }
}

/**
 * Push a branch to remote
 * @param branchName - Name of the branch to push
 * @param force - Whether to force push (default: false)
 */
export function pushBranch(branchName: string, force: boolean = false): void {
  const forceFlag = force ? '-f ' : '';
  execSync(`git push ${forceFlag}origin ${branchName}`, {
    encoding: 'utf-8',
    stdio: 'pipe'
  });
}

/**
 * Safely switch back to a branch
 * @param branchName - Name of the branch to switch to
 * @param currentBranch - Optional current branch to avoid redundant checkout
 * @returns true if checkout succeeded, false otherwise
 */
export function safeCheckout(branchName: string, currentBranch?: string): boolean {
  // Don't checkout if we're already on the target branch
  if (currentBranch === branchName) {
    return true;
  }

  try {
    execSync(`git checkout ${branchName}`, {
      encoding: 'utf-8',
      stdio: 'pipe'
    });
    return true;
  } catch {
    return false;
  }
}
