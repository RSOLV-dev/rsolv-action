/**
 * PhaseDataClient - Manages storage and retrieval of phase data
 * Implements RFC-041 Phase Data Storage specification
 */

import type { TestExecutionResult } from '../types.js';
import type { VulnerabilityTestSuite } from '../../ai/test-generator.js';
import type { ValidationResult as GitValidationResult } from '../../ai/git-based-test-validator.js';

export interface StoreResult {
  success: boolean;
  id?: string;
  message?: string;
  storage?: 'platform' | 'local';
  warning?: string;
}

/**
 * Vulnerability data for scan phase
 */
export interface ScanVulnerability {
  type: string;
  file: string;
  line: number;
  severity?: string;
  description?: string;
  cwe?: string;
  [key: string]: unknown; // Allow additional properties
}

/**
 * Validation phase data for a single issue
 */
export interface ValidationPhaseData {
  validated: boolean;
  branchName?: string;
  testPath?: string;
  redTests?: VulnerabilityTestSuite;
  testResults?: GitValidationResult;
  testExecutionResult?: TestExecutionResult;
  falsePositiveReason?: string;
  timestamp: string;
}

/**
 * Mitigation phase data for a single issue
 */
export interface MitigationPhaseData {
  fixed: boolean;
  prUrl?: string;
  fixCommit?: string;
  timestamp: string;
}

export interface PhaseData {
  scan?: {
    vulnerabilities: ScanVulnerability[];
    timestamp: string;
    commitHash: string;
  };

  // Platform returns 'validation', client uses 'validate'
  validation?: {
    [issueId: string]: ValidationPhaseData;
  };

  // Alias for validation (after remapping)
  validate?: {
    [issueId: string]: ValidationPhaseData;
  };

  mitigation?: {
    [issueId: string]: MitigationPhaseData;
  };

  // Alias for mitigation (after remapping)
  mitigate?: {
    [issueId: string]: MitigationPhaseData;
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
    
    // Use platform storage by default, unless explicitly disabled
    this.usePlatformStorage = process.env.USE_PLATFORM_STORAGE !== 'false';
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
    // If platform storage is disabled, go straight to local
    if (!this.usePlatformStorage) {
      return this.storeLocally(phase, data, metadata);
    }

    // Map client phase names to platform phase names
    const phaseMapping: { [key: string]: string } = {
      'scan': 'scan',
      'validate': 'validation',
      'mitigate': 'mitigation'
    };

    const platformPhase = phaseMapping[phase] || phase;

    // Extract and validate the specific phase data for the platform API
    // Platform expects direct phase data, not wrapped in PhaseData structure
    // NOTE: This validation happens BEFORE the try-catch so errors propagate to caller
    let phaseSpecificData: any;

    if (phase === 'scan') {
      // For scan, send the scan data directly
      phaseSpecificData = data.scan;
    } else if (phase === 'validate' || phase === 'mitigate') {
      // For validation/mitigation, extract the data for the specific issue
      // Use the client-side key names (validate/mitigate, not validation/mitigation)
      const phaseIssueData = (data as any)[phase];

      if (!metadata.issueNumber) {
        throw new Error(`Issue number is required for ${phase} phase`);
      }

      if (!phaseIssueData) {
        throw new Error(`No ${phase} data found for issue ${metadata.issueNumber}`);
      }

      // Extract just the data for this specific issue using the issue number as key
      const issueKey = String(metadata.issueNumber);
      phaseSpecificData = phaseIssueData[issueKey];

      // If no data found for this specific issue, throw validation error
      if (!phaseSpecificData) {
        throw new Error(`No ${phase} data found for issue ${metadata.issueNumber}`);
      }
    }

    // Try to store on platform, fall back to local on platform errors only
    try {
      const requestPayload = {
        phase: platformPhase,
        data: phaseSpecificData,
        ...metadata
      };

      const url = `${this.baseUrl}/api/v1/phases/store`;

      console.log('[PhaseDataClient] Storing phase data:', {
        url,
        phase: platformPhase,
        hasData: !!phaseSpecificData,
        dataType: typeof phaseSpecificData,
        repo: metadata.repo,
        issueNumber: metadata.issueNumber,
        commitSha: metadata.commitSha?.substring(0, 8)
      });

      console.log('[PhaseDataClient] Full request payload:', JSON.stringify(requestPayload, null, 2));

      const response = await fetch(url, {
        method: 'POST',
        headers: this.headers,
        body: JSON.stringify(requestPayload)
      });

      if (!response.ok) {
        const errorText = await response.text().catch(() => 'Unable to read error response');
        const headers: Record<string, string> = {};
        response.headers.forEach((value, key) => {
          headers[key] = value;
        });
        console.error('[PhaseDataClient] Platform storage failed:', {
          url,
          status: response.status,
          statusText: response.statusText,
          headers,
          errorBody: errorText
        });
        throw new Error(`Platform storage failed: ${response.statusText}`);
      }

      const result = await response.json();
      return { ...result, storage: 'platform' as const };
    } catch (error) {
      // Fallback to local storage on platform errors
      console.warn('Platform storage failed, falling back to local:', error);
      return this.storeLocally(phase, data, metadata);
    }
  }
  
  async retrievePhaseResults(
    repo: string,
    issueNumber: number,
    commitSha: string
  ): Promise<PhaseData | null> {
    // If platform storage is disabled, go straight to local
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
        // Fallback to local storage immediately on 404
        return this.retrieveLocally(repo, issueNumber, commitSha);
      }
      
      if (!response.ok) {
        throw new Error(`Platform retrieval failed: ${response.statusText}`);
      }
      
      const data = await response.json();
      
      // Log what we got from platform for debugging
      console.log('[PhaseDataClient] Retrieved from platform:', {
        hasValidation: !!data?.validation,
        hasValidate: !!data?.validate,
        keys: Object.keys(data || {})
      });
      
      // Map platform phase names back to client phase names if needed
      if (data && data.validation && !data.validate) {
        console.log('[PhaseDataClient] Mapping validation -> validate');
        data.validate = data.validation;
        delete data.validation;
      }
      if (data && data.mitigation && !data.mitigate) {
        console.log('[PhaseDataClient] Mapping mitigation -> mitigate');
        data.mitigate = data.mitigation;
        delete data.mitigation;
      }
      
      console.log('[PhaseDataClient] Returning data with keys:', Object.keys(data || {}));
      return data;
    } catch (error) {
      // Fallback to local storage
      console.warn('Platform retrieval failed, falling back to local:', error);
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
    // First, check if GITHUB_SHA is available (provided by GitHub Actions and act)
    if (process.env.GITHUB_SHA) {
      return process.env.GITHUB_SHA.trim();
    }

    // Fall back to git command if available
    try {
      const { execSync } = await import('child_process');
      return execSync('git rev-parse HEAD').toString().trim();
    } catch (error) {
      // In act Docker containers, git may not be available
      // Use a fallback value to allow the action to continue
      console.warn('[PhaseDataClient] Git not available, using fallback commit SHA');
      return 'no-git-available';
    }
  }

  /**
   * RFC-060 Phase 3.2: Get test information for an issue
   */
  async getPhaseTestInfo(issueId: string): Promise<{
    branchName: string;
    testPath: string;
    framework: string;
    command: string;
  }> {
    // This would normally fetch from the API
    // For now, return mock data for testing
    return {
      branchName: `rsolv/validate/${issueId}`,
      testPath: `__tests__/security/rsolv-${issueId}.test.js`,
      framework: 'jest',
      command: `npm test -- __tests__/security/rsolv-${issueId}.test.js`
    };
  }

  /**
   * RFC-060 Phase 3.2: Save test execution results
   */
  async saveTestResults(results: {
    issueId: string;
    preTestPassed: boolean;
    postTestPassed: boolean;
    trustScore: number;
  }): Promise<void> {
    // This would normally save to the API
    // For now, just log for testing
    console.log('[PhaseDataClient] Saving test results:', results);
  }

  /**
   * RFC-060 Phase 3.2: Calculate trust score
   */
  async calculateTrustScore(preTestPassed: boolean, postTestPassed: boolean): Promise<number> {
    if (!preTestPassed && postTestPassed) {
      return 100;
    } else if (preTestPassed && postTestPassed) {
      return 50;
    } else {
      return 0;
    }
  }

  /**
   * RFC-060 Phase 4.3: Store failure details with metadata
   */
  async storeFailureDetails(
    repo: string,
    issueNumber: number,
    failureDetails: {
      phase: string;
      issueNumber: number;
      error: string;
      timestamp: string;
      retryCount: number;
      metadata?: Record<string, any>;
    }
  ): Promise<void> {
    const fs = await import('fs/promises');
    const path = await import('path');

    const dir = '.rsolv/observability/failures';
    await fs.mkdir(dir, { recursive: true });

    const filename = `${repo.replace('/', '-')}-${issueNumber}-failure-${Date.now()}.json`;
    const filepath = path.join(dir, filename);

    await fs.writeFile(filepath, JSON.stringify(failureDetails, null, 2));
    console.log(`[PhaseDataClient] Stored failure details: ${filepath}`);
  }

  /**
   * RFC-060 Phase 4.3: Store retry attempt with metadata
   */
  async storeRetryAttempt(
    repo: string,
    issueNumber: number,
    retryAttempt: {
      phase: string;
      issueNumber: number;
      attemptNumber: number;
      maxRetries: number;
      error: string;
      timestamp: string;
      metadata?: Record<string, any>;
    }
  ): Promise<void> {
    const fs = await import('fs/promises');
    const path = await import('path');

    const dir = '.rsolv/observability/retries';
    await fs.mkdir(dir, { recursive: true });

    const filename = `${repo.replace('/', '-')}-${issueNumber}-retry-${retryAttempt.attemptNumber}.json`;
    const filepath = path.join(dir, filename);

    await fs.writeFile(filepath, JSON.stringify(retryAttempt, null, 2));
    console.log(`[PhaseDataClient] Stored retry attempt ${retryAttempt.attemptNumber}/${retryAttempt.maxRetries}: ${filepath}`);
  }

  /**
   * RFC-060 Phase 4.3: Store trust score with calculation metadata
   */
  async storeTrustScore(
    repo: string,
    issueNumber: number,
    trustScoreData: {
      issueNumber: number;
      preTestPassed: boolean;
      postTestPassed: boolean;
      trustScore: number;
      timestamp: string;
      metadata?: {
        testFramework?: string;
        testFile?: string;
        executionTime?: number;
        [key: string]: any;
      };
    }
  ): Promise<void> {
    const fs = await import('fs/promises');
    const path = await import('path');

    const dir = '.rsolv/observability/trust-scores';
    await fs.mkdir(dir, { recursive: true });

    const filename = `${repo.replace('/', '-')}-${issueNumber}-trust-score.json`;
    const filepath = path.join(dir, filename);

    await fs.writeFile(filepath, JSON.stringify(trustScoreData, null, 2));
    console.log(`[PhaseDataClient] Stored trust score (${trustScoreData.trustScore}): ${filepath}`);
  }

  /**
   * RFC-060 Phase 4.3: Store execution timeline with phase transitions
   */
  async storeExecutionTimeline(
    repo: string,
    issueNumber: number,
    timeline: {
      issueNumber: number;
      phases: Array<{
        phase: string;
        startTime: string;
        endTime: string;
        durationMs: number;
        success: boolean;
        metadata?: Record<string, any>;
      }>;
      totalDurationMs: number;
      metadata?: Record<string, any>;
    }
  ): Promise<void> {
    const fs = await import('fs/promises');
    const path = await import('path');

    const dir = '.rsolv/observability/timelines';
    await fs.mkdir(dir, { recursive: true });

    const filename = `${repo.replace('/', '-')}-${issueNumber}-timeline.json`;
    const filepath = path.join(dir, filename);

    await fs.writeFile(filepath, JSON.stringify(timeline, null, 2));
    console.log(`[PhaseDataClient] Stored execution timeline (${timeline.totalDurationMs}ms): ${filepath}`);
  }
}