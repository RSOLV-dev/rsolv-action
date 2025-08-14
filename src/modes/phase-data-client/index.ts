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
    try {
      const response = await fetch(`${this.baseUrl}/api/v1/phases/store`, {
        method: 'POST',
        headers: this.headers,
        body: JSON.stringify({
          phase,
          data,
          ...metadata
        })
      });
      
      if (!response.ok) {
        throw new Error(`Platform storage failed: ${response.statusText}`);
      }
      
      return await response.json();
    } catch (error) {
      // Fallback to local storage
      return this.storeLocally(phase, data, metadata);
    }
  }
  
  async retrievePhaseResults(
    repo: string,
    issueNumber: number,
    commitSha: string
  ): Promise<PhaseData | null> {
    console.log(`[PhaseDataClient] Retrieving phase results for ${repo} issue #${issueNumber}`);
    try {
      const response = await fetch(
        `${this.baseUrl}/api/v1/phases/retrieve?` +
        `repo=${repo}&issue=${issueNumber}&commit=${commitSha}`,
        { headers: this.headers }
      );
      
      console.log(`[PhaseDataClient] Platform API response: ${response.status}`);
      
      if (response.status === 404) {
        console.log('[PhaseDataClient] Platform API returned 404, falling back to local storage');
        // Fallback to local storage immediately on 404
        return this.retrieveLocally(repo, issueNumber, commitSha);
      }
      
      if (!response.ok) {
        throw new Error(`Platform retrieval failed: ${response.statusText}`);
      }
      
      const data = await response.json();
      console.log('[PhaseDataClient] Retrieved from platform:', data);
      return data;
    } catch (error) {
      console.log('[PhaseDataClient] Platform error, falling back to local:', error);
      // Fallback to local storage
      return this.retrieveLocally(repo, issueNumber, commitSha);
    }
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
    console.log(`[PhaseDataClient] Retrieving locally for ${repo} issue #${issueNumber}`);
    const fs = await import('fs/promises');
    const path = await import('path');
    
    const dir = '.rsolv/phase-data';
    const repoName = repo.replace('/', '-');
    const pattern = `${repoName}-${issueNumber}-`;
    
    console.log(`[PhaseDataClient] Looking in ${dir} for files matching ${pattern}*`);
    
    try {
      const files = await fs.readdir(dir);
      console.log(`[PhaseDataClient] Found ${files.length} files in directory:`, files);
      
      const matches = files.filter(f => f.startsWith(pattern));
      console.log(`[PhaseDataClient] Found ${matches.length} matching files:`, matches);
      
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
}