/**
 * PhaseDataClient - Manages storage and retrieval of phase data
 * Implements RFC-041 Phase Data Storage specification
 */

export interface StoreResult {
  success: boolean;
  id?: string;
  message?: string;
  storage?: 'platform' | 'local';
  warning?: string;
}

export interface PhaseData {
  scan?: {
    vulnerabilities: Array<{
      type: string;
      file: string;
      line: number;
      [key: string]: any;
    }>;
    timestamp: string;
    commitHash: string;
  };
  
  validation?: {
    [issueId: string]: {
      validated: boolean;
      redTests?: any;
      testResults?: any;
      falsePositiveReason?: string;
      timestamp: string;
    };
  };
  
  mitigation?: {
    [issueId: string]: {
      fixed: boolean;
      prUrl?: string;
      fixCommit?: string;
      timestamp: string;
    };
  };
}

export class PhaseDataClient {
  private readonly headers: Headers;
  
  constructor(
    private apiKey: string,
    private baseUrl: string = process.env.RSOLV_API_URL || 'https://api.rsolv.dev'
  ) {
    this.headers = new Headers({
      'Content-Type': 'application/json',
      'X-API-Key': apiKey
    });
  }
  
  async storePhaseResults(
    phase: 'scan' | 'validate' | 'mitigate',
    data: PhaseData,
    metadata: {
      repo: string;
      issueNumber?: number;
      commitSha: string;
    }
  ): Promise<StoreResult> {
    // For now, use GitHub comments as storage since platform API doesn't have these endpoints
    // This ensures data persists across different GitHub Actions runners
    if (metadata.issueNumber) {
      return this.storeInGitHubComment(phase, data, metadata);
    }
    
    // Fallback to local storage for non-issue operations
    return this.storeLocally(phase, data, metadata);
  }
  
  async retrievePhaseResults(
    repo: string,
    issueNumber: number,
    commitSha: string
  ): Promise<PhaseData | null> {
    // For now, use GitHub comments as storage since platform API doesn't have these endpoints
    // This ensures data persists across different GitHub Actions runners
    const result = await this.retrieveFromGitHubComment(repo, issueNumber, commitSha);
    if (result) {
      return result;
    }
    
    // Fallback to local storage
    return this.retrieveLocally(repo, issueNumber, commitSha);
  }
  
  async validatePhaseTransition(
    fromPhase: string,
    toPhase: string,
    commitSha: string
  ): Promise<boolean> {
    // Check if commit has changed
    const currentSha = await this.getCurrentCommitSha();
    if (currentSha !== commitSha) {
      return false;  // Data is stale
    }
    
    // Validate phase progression
    const validTransitions: Record<string, string[]> = {
      'scan': ['validate'],
      'validate': ['mitigate'],
      'mitigate': []
    };
    
    return validTransitions[fromPhase]?.includes(toPhase) ?? false;
  }
  
  // Local storage fallback for platform unavailability
  private async storeLocally(
    phase: string,
    data: PhaseData,
    metadata: any
  ): Promise<StoreResult> {
    const fs = await import('fs/promises');
    const path = await import('path');
    
    const dir = '.rsolv/phase-data';
    await fs.mkdir(dir, { recursive: true });
    
    const filename = `${metadata.repo.replace('/', '-')}-${metadata.issueNumber || 'scan'}-${phase}.json`;
    const filepath = path.join(dir, filename);
    
    await fs.writeFile(filepath, JSON.stringify({
      phase,
      data,
      metadata,
      timestamp: new Date().toISOString()
    }, null, 2));
    
    return { 
      success: true, 
      storage: 'local',
      warning: 'Platform unavailable, stored locally'
    };
  }
  
  private async retrieveLocally(
    repo: string,
    issueNumber: number,
    commitSha: string
  ): Promise<PhaseData | null> {
    const fs = await import('fs/promises');
    const path = await import('path');
    
    const dir = '.rsolv/phase-data';
    const repoName = repo.replace('/', '-');
    const pattern = `${repoName}-${issueNumber}-`;
    
    try {
      const files = await fs.readdir(dir);
      const matches = files.filter(f => f.startsWith(pattern));
      
      const allData: PhaseData = {};
      for (const file of matches) {
        const content = await fs.readFile(path.join(dir, file), 'utf-8');
        const parsed = JSON.parse(content);
        
        // Only use if commit matches
        if (parsed.metadata.commitSha === commitSha) {
          Object.assign(allData, parsed.data);
        }
      }
      
      return Object.keys(allData).length > 0 ? allData : null;
    } catch {
      return null;
    }
  }
  
  private async getCurrentCommitSha(): Promise<string> {
    const { execSync } = await import('child_process');
    return execSync('git rev-parse HEAD').toString().trim();
  }

  // GitHub comment-based storage for cross-workflow persistence
  private async storeInGitHubComment(
    phase: string,
    data: PhaseData,
    metadata: any
  ): Promise<StoreResult> {
    const { createIssueComment } = await import('../../github/api.js');
    
    const [owner, name] = metadata.repo.split('/');
    const commentData = {
      phase,
      data,
      metadata,
      timestamp: new Date().toISOString()
    };
    
    // Create a hidden comment with phase data
    const commentBody = `<!-- RSOLV_PHASE_DATA:${phase}:${metadata.commitSha}
${JSON.stringify(commentData, null, 2)}
-->
Phase data stored for ${phase} phase (commit: ${metadata.commitSha.substring(0, 8)})`;
    
    try {
      await createIssueComment(owner, name, metadata.issueNumber, commentBody);
      return {
        success: true,
        storage: 'platform' as const,
        message: 'Stored in GitHub comment'
      };
    } catch (error) {
      // Fallback to local storage
      return this.storeLocally(phase, data, metadata);
    }
  }
  
  private async retrieveFromGitHubComment(
    repo: string,
    issueNumber: number,
    commitSha: string
  ): Promise<PhaseData | null> {
    try {
      const { getGitHubClient } = await import('../../github/api.js');
      const [owner, name] = repo.split('/');
      
      // GitHub API doesn't return comments with getIssue, need to fetch separately
      const octokit = getGitHubClient();
      const { data: comments } = await octokit.rest.issues.listComments({
        owner,
        repo: name,
        issue_number: issueNumber
      });
      
      // Find phase data comments
      const phaseData: PhaseData = {};
      const pattern = /<!-- RSOLV_PHASE_DATA:(\w+):([a-f0-9]+)\n([\s\S]*?)\n-->/g;
      
      for (const comment of comments) {
        if (!comment.body) continue;
        const matches = [...comment.body.matchAll(pattern)];
        for (const match of matches) {
          const [, phase, sha, jsonData] = match;
          if (sha === commitSha || commitSha === 'latest') {
            try {
              const parsed = JSON.parse(jsonData);
              Object.assign(phaseData, parsed.data);
            } catch {
              // Invalid JSON, skip
            }
          }
        }
      }
      
      return Object.keys(phaseData).length > 0 ? phaseData : null;
    } catch (error) {
      return null;
    }
  }
}