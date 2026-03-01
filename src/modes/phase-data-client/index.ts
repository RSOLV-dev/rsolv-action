/**
 * Phase data retrieval client (read-only).
 *
 * RFC-126: The store methods were removed — storage is now handled server-side
 * by Orchestrator.complete_with_storage. This client retains only retrieve,
 * used by the mitigation phase to read prior validation data.
 */

export type PhaseData = Record<string, unknown>;

export interface ScanVulnerability {
  cwe_id?: string;
  severity?: string;
  description?: string;
  [key: string]: unknown;
}

export class PhaseDataClient {
  private apiKey: string;
  private apiUrl: string;

  constructor(apiKey: string, apiUrl?: string) {
    this.apiKey = apiKey;
    this.apiUrl = (apiUrl || 'https://api.rsolv.dev').replace(/\/$/, '');
  }

  /**
   * Retrieve accumulated phase data for a repository/issue/commit.
   */
  async retrievePhaseResults(
    repo: string,
    issueNumber: number | undefined,
    commitSha: string
  ): Promise<PhaseData | null> {
    try {
      const params = new URLSearchParams({
        repo,
        commit: commitSha,
        ...(issueNumber !== undefined ? { issue: String(issueNumber) } : {}),
      });

      const response = await fetch(
        `${this.apiUrl}/api/v1/phases/retrieve?${params}`,
        {
          method: 'GET',
          headers: { 'x-api-key': this.apiKey },
        }
      );

      if (!response.ok) {
        return null;
      }

      return response.json();
    } catch {
      return null;
    }
  }

  /**
   * @deprecated Use Orchestrator.complete_with_storage (server-side) instead.
   */
  async storePhaseResults(): Promise<{ success: boolean }> {
    throw new Error('storePhaseResults removed in RFC-126. Storage is now server-side.');
  }
}
