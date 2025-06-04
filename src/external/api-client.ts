// Bun has built-in fetch, no import needed

interface RsolvApiClientConfig {
  baseUrl: string;
  apiKey: string;
}

interface FixAttemptData {
  github_org: string;
  repo_name: string;
  issue_number?: number;
  pr_number: number;
  pr_title: string;
  pr_url: string;
  issue_title?: string;
  issue_url?: string;
  api_key_used: string;
  metadata?: {
    branch?: string;
    labels?: string[];
    created_by?: string;
    [key: string]: any;
  };
}

interface FixAttemptResponse {
  id: number;
  status: string;
  github_org: string;
  repo_name: string;
  pr_number: number;
  billing_status?: string;
}

interface ApiResult<T> {
  success: boolean;
  data?: T;
  error?: string;
}

export class RsolvApiClient {
  private baseUrl: string;
  private apiKey: string;

  constructor(config: RsolvApiClientConfig) {
    this.baseUrl = config.baseUrl;
    this.apiKey = config.apiKey;
  }

  async recordFixAttempt(fixAttempt: FixAttemptData): Promise<ApiResult<FixAttemptResponse>> {
    try {
      const response = await fetch(`${this.baseUrl}/api/v1/fix-attempts`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${this.apiKey}`
        },
        body: JSON.stringify(fixAttempt)
      });

      if (response.ok) {
        const data = await response.json() as FixAttemptResponse;
        return {
          success: true,
          data
        };
      } else {
        const errorData = await response.json();
        return {
          success: false,
          error: `API Error: ${response.status} - ${JSON.stringify(errorData)}`
        };
      }
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error'
      };
    }
  }
}