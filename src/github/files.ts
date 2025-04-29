import * as github from '@actions/github';
import { logger } from '../utils/logger';

/**
 * Helper class for GitHub repository file operations
 */
export class GitHubFileManager {
  private octokit: ReturnType<typeof github.getOctokit>;
  private owner: string;
  private repo: string;

  constructor(token: string, owner: string, repo: string) {
    this.octokit = github.getOctokit(token);
    this.owner = owner;
    this.repo = repo;
  }

  /**
   * Get file content from repository
   */
  async getFileContent(path: string, ref?: string): Promise<{ content: string; sha: string }> {
    try {
      const { data } = await this.octokit.rest.repos.getContent({
        owner: this.owner,
        repo: this.repo,
        path,
        ref: ref || undefined,
      });

      // Handle directory case
      if (Array.isArray(data) || !('content' in data)) {
        throw new Error(`Path ${path} is a directory, not a file`);
      }

      const content = Buffer.from(data.content, 'base64').toString('utf-8');
      return { content, sha: data.sha };
    } catch (error) {
      // Check if file doesn't exist - we'll treat this differently than other errors
      if ((error as any).status === 404) {
        logger.debug(`File ${path} not found in ${this.owner}/${this.repo}`);
        return { content: '', sha: '' };
      }
      
      logger.error(`Error getting file content for ${path} in ${this.owner}/${this.repo}`, error as Error);
      throw error;
    }
  }

  /**
   * Create or update a file in the repository
   */
  async updateFile(
    path: string,
    content: string,
    message: string,
    branch: string,
    sha?: string
  ): Promise<string> {
    try {
      const params: any = {
        owner: this.owner,
        repo: this.repo,
        path,
        message,
        content: Buffer.from(content).toString('base64'),
        branch,
      };

      // If sha is provided, this is an update, otherwise it's a create
      if (sha) {
        params.sha = sha;
      }

      const { data } = await this.octokit.rest.repos.createOrUpdateFileContents(params);
      return data.content.sha;
    } catch (error) {
      logger.error(`Error updating file ${path} in ${this.owner}/${this.repo}`, error as Error);
      throw error;
    }
  }

  /**
   * Create multiple file changes in the repository
   * This is an abstraction that handles batch file operations
   */
  async updateMultipleFiles(
    files: Array<{ path: string; content: string }>,
    commitMessage: string,
    branch: string
  ): Promise<void> {
    try {
      // Process files sequentially to avoid race conditions
      for (const file of files) {
        // Get the current file to check if it exists and get its SHA
        let currentFileData;
        try {
          currentFileData = await this.getFileContent(file.path, branch);
        } catch (error) {
          // If the file doesn't exist, that's fine - we're creating it
          currentFileData = { content: '', sha: '' };
        }

        // Skip if the content is the same
        if (currentFileData.content === file.content) {
          logger.debug(`File ${file.path} content unchanged, skipping`);
          continue;
        }

        // Update the file
        await this.updateFile(
          file.path,
          file.content,
          commitMessage,
          branch,
          currentFileData.sha || undefined
        );
      }
    } catch (error) {
      logger.error(`Error updating multiple files in ${this.owner}/${this.repo}`, error as Error);
      throw error;
    }
  }

  /**
   * Get reference (branch, tag, etc.)
   */
  async getReference(ref: string): Promise<string> {
    try {
      const { data } = await this.octokit.rest.git.getRef({
        owner: this.owner,
        repo: this.repo,
        ref: ref.startsWith('refs/') ? ref.substring(5) : ref,
      });
      return data.object.sha;
    } catch (error) {
      logger.error(`Error getting reference ${ref} in ${this.owner}/${this.repo}`, error as Error);
      throw error;
    }
  }

  /**
   * Create a new branch
   */
  async createBranch(branchName: string, baseSha: string): Promise<void> {
    try {
      await this.octokit.rest.git.createRef({
        owner: this.owner,
        repo: this.repo,
        ref: `refs/heads/${branchName}`,
        sha: baseSha,
      });
      logger.debug(`Created branch ${branchName} in ${this.owner}/${this.repo}`);
    } catch (error) {
      logger.error(`Error creating branch ${branchName} in ${this.owner}/${this.repo}`, error as Error);
      throw error;
    }
  }

  /**
   * Check if a branch exists
   */
  async branchExists(branchName: string): Promise<boolean> {
    try {
      await this.getReference(`heads/${branchName}`);
      return true;
    } catch (error) {
      if ((error as any).status === 404) {
        return false;
      }
      throw error;
    }
  }

  /**
   * Get diff between two references
   */
  async getDiff(base: string, head: string): Promise<string> {
    try {
      const { data } = await this.octokit.rest.repos.compareCommits({
        owner: this.owner,
        repo: this.repo,
        base,
        head,
      });
      
      return data.files?.map(file => {
        return {
          path: file.filename,
          status: file.status,
          additions: file.additions,
          deletions: file.deletions,
          changes: file.changes,
          patch: file.patch
        };
      }) || [];
    } catch (error) {
      logger.error(`Error getting diff between ${base} and ${head} in ${this.owner}/${this.repo}`, error as Error);
      throw error;
    }
  }
}