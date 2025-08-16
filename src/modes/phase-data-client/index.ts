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

interface Vulnerability {
  type: string;
  file: string;
  line: number;
  [key: string]: any;
}

interface ValidationData {
  validated: boolean;
  vulnerabilities?: Vulnerability[];
  redTests?: any;
  testResults?: any;
  falsePositiveReason?: string;
  timestamp: string;
}

interface MitigationData {
  fixed: boolean;
  prUrl?: string;
  prNumber?: number;
  fixCommit?: string;
  filesChanged?: number;
  timestamp: string;
}

export interface PhaseData {
  scan?: {
    vulnerabilities: Vulnerability[];
    timestamp: string;
    commitHash: string;
  };
  
  validation?: {
    [issueId: string]: ValidationData;
  };
  
  mitigation?: {
    [issueId: string]: MitigationData;
  };
}

export class PhaseDataClient {
  private readonly headers: Headers;
  private readonly usePlatformStorage: boolean;
  
  constructor(
    private apiKey: string,
    private baseUrl: string = process.env.RSOLV_API_URL || 'https://api.rsolv.dev'
  ) {
    this.headers = new Headers({
      'Content-Type': 'application/json',
      'X-API-Key': apiKey
    });
    
    // Environment variable flag for gradual rollout
    // Default to true unless explicitly disabled
    this.usePlatformStorage = process.env.USE_PLATFORM_STORAGE !== 'false';
  }
  
  async storePhaseResults(
    phase: 'scan' | 'validate' | 'mitigate',
    data: PhaseData,
    metadata: {
      repo: string;
      issueNumber?: number;
      commitSha: string;
      branch?: string;
    }
  ): Promise<StoreResult> {
    // Skip platform storage if not enabled
    if (!this.usePlatformStorage) {
      return this.storeLocally(phase, data, metadata);
    }
    
    try {
      // Format data for platform API based on phase
      const platformData = this.formatDataForPlatform(phase, data, metadata);
      
      const response = await fetch(`${this.baseUrl}/api/v1/phases/store`, {
        method: 'POST',
        headers: this.headers,
        body: JSON.stringify(platformData)
      });
      
      if (!response.ok) {
        const errorText = await response.text();
        console.error(`Platform storage failed: ${response.status} - ${errorText}`);
        throw new Error(`Platform storage failed: ${response.statusText}`);
      }
      
      const result = await response.json();
      return {
        success: result.success,
        id: result.id,
        storage: 'platform',
        message: `Stored ${phase} data to platform`
      };
    } catch (error) {
      console.warn(`Platform storage failed, falling back to local: ${error}`);
      // Fallback to local storage
      return this.storeLocally(phase, data, metadata);
    }
  }
  
  async retrievePhaseResults(
    repo: string,
    issueNumber: number,
    commitSha: string
  ): Promise<PhaseData | null> {
    // Skip platform retrieval if not enabled
    if (!this.usePlatformStorage) {
      return this.retrieveLocally(repo, issueNumber, commitSha);
    }
    
    try {
      const response = await fetch(
        `${this.baseUrl}/api/v1/phases/retrieve?` +
        `repo=${encodeURIComponent(repo)}&issue=${issueNumber}&commit=${encodeURIComponent(commitSha)}`,
        { headers: this.headers }
      );
      
      if (response.status === 404) {
        // No data found, fallback to local
        return this.retrieveLocally(repo, issueNumber, commitSha);
      }
      
      if (!response.ok) {
        const errorText = await response.text();
        console.error(`Platform retrieval failed: ${response.status} - ${errorText}`);
        throw new Error(`Platform retrieval failed: ${response.statusText}`);
      }
      
      const data = await response.json();
      // Platform returns data in the expected PhaseData format
      return data;
    } catch (error) {
      console.warn(`Platform retrieval failed, falling back to local: ${error}`);
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
  
  // Helper to format data for platform API
  private formatDataForPlatform(
    phase: 'scan' | 'validate' | 'mitigate',
    data: PhaseData,
    metadata: {
      repo: string;
      issueNumber?: number;
      commitSha: string;
      branch?: string;
    }
  ): any {
    // Map client phase names to platform phase names
    const phaseMapping: { [key: string]: string } = {
      'scan': 'scan',
      'validate': 'validation',
      'mitigate': 'mitigation'
    };
    
    const basePayload = {
      phase: phaseMapping[phase] || phase,
      repo: metadata.repo,
      commit_sha: metadata.commitSha,  // Platform expects snake_case
    };
    
    switch (phase) {
      case 'scan':
        return {
          ...basePayload,
          branch: metadata.branch || 'main',
          data: data.scan || {
            vulnerabilities: [],
            timestamp: new Date().toISOString(),
            commitHash: metadata.commitSha
          }
        };
      
      case 'validate':
        const validationKey = `issue-${metadata.issueNumber}`;
        const validationData: ValidationData | undefined = data.validation?.[validationKey] || 
                              data.validation?.[metadata.issueNumber?.toString() || ''];
        return {
          ...basePayload,
          issue_number: metadata.issueNumber,  // Platform expects snake_case
          data: {
            validation: {
              [validationKey]: validationData || {}
            }
          }
        };
      
      case 'mitigate':
        const mitigationKey = `issue-${metadata.issueNumber}`;
        const mitigationData: MitigationData | undefined = data.mitigation?.[mitigationKey] || 
                               data.mitigation?.[metadata.issueNumber?.toString() || ''];
        return {
          ...basePayload,
          issue_number: metadata.issueNumber,  // Platform expects snake_case
          data: {
            mitigation: {
              [mitigationKey]: mitigationData || {}
            }
          }
        };
      
      default:
        throw new Error(`Unknown phase: ${phase}`);
    }
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
}