/**
 * TestIntegrationClient - Backend API client for test integration
 * RFC-060-AMENDMENT-001: Test Integration
 *
 * Responsibilities:
 * 1. Analyze test files and score integration suitability
 * 2. Generate AST-based test integration
 * 3. Handle retry logic with exponential backoff
 * 4. Authenticate with x-api-key header (per project convention)
 *
 * Environment-aware URL configuration:
 * - Production: https://api.rsolv.dev
 * - Staging: https://api.rsolv-staging.com (via RSOLV_API_URL env)
 * - Local/CI: Custom URL via constructor or env variable
 */

// Type definitions based on RFC-060-AMENDMENT-001 API specification
export interface AnalyzeRequest {
  vulnerableFile: string;
  vulnerabilityType: string;
  candidateTestFiles: string[];
  framework: string;
}

export interface AnalyzeResponse {
  recommendations: Array<{
    path: string;
    score: number;
    reason: string;
  }>;
  fallback: {
    path: string;
    reason: string;
  };
}

export interface GenerateRequest {
  targetFileContent: string;
  testSuite: VulnerabilityTestSuite;
  framework: string;
  language: string;
}

export interface VulnerabilityTestSuite {
  redTests: Array<{
    testName: string;
    testCode: string;
    attackVector: string;
    expectedBehavior: string;
    vulnerableCodePath?: string;
    vulnerablePattern?: string;
  }>;
}

export interface GenerateResponse {
  integratedContent: string;
  method: 'ast' | 'append';
  insertionPoint: {
    line?: number;
    strategy: string;
  };
}

export class TestIntegrationClient {
  private readonly baseUrl: string;
  private readonly maxRetries: number = 3;
  private readonly baseDelayMs: number = 100;
  private readonly timeoutMs: number = 30000;

  constructor(
    private apiKey: string,
    baseUrl?: string
  ) {
    // Support environment variable override with production default
    this.baseUrl = baseUrl || process.env.RSOLV_API_URL || 'https://api.rsolv.dev';
  }

  async analyze(request: AnalyzeRequest): Promise<AnalyzeResponse> {
    return this.post<AnalyzeRequest, AnalyzeResponse>(
      '/api/v1/test-integration/analyze',
      request
    );
  }

  async generate(request: GenerateRequest): Promise<GenerateResponse> {
    return this.post<GenerateRequest, GenerateResponse>(
      '/api/v1/test-integration/generate',
      request
    );
  }

  private async post<TRequest, TResponse>(
    endpoint: string,
    data: TRequest
  ): Promise<TResponse> {
    let lastError: Error | null = null;

    for (let attempt = 0; attempt < this.maxRetries; attempt++) {
      // Add exponential backoff delay for retries (100ms, 200ms, 400ms)
      if (attempt > 0) {
        const delay = this.baseDelayMs * Math.pow(2, attempt - 1);
        await new Promise(resolve => setTimeout(resolve, delay));
      }

      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), this.timeoutMs);

      try {
        const response = await fetch(`${this.baseUrl}${endpoint}`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'x-api-key': this.apiKey
          },
          body: JSON.stringify(data),
          signal: controller.signal
        });

        clearTimeout(timeoutId);

        // Handle HTTP errors
        if (!response.ok) {
          // Don't retry on 4xx client errors
          if (response.status >= 400 && response.status < 500) {
            let errorMessage = response.statusText;

            // Try to get error details from response body
            if (response.json && typeof response.json === 'function') {
              try {
                const errorBody = await response.json();
                errorMessage = (errorBody as any).error || errorMessage;
              } catch {
                // If json parsing fails, use statusText
              }
            }

            if (response.status === 401) {
              throw new Error(`Authentication failed: ${errorMessage}`);
            }

            throw new Error(`Client error (${response.status}): ${errorMessage}`);
          }

          // Retry on 5xx server errors
          if (response.status >= 500) {
            lastError = new Error(`Server error: ${response.status} ${response.statusText}`);
            continue;
          }
        }

        // Success - parse and return response
        const result = await response.json();
        return result as TResponse;

      } catch (error) {
        clearTimeout(timeoutId);

        // Re-throw 4xx errors immediately (no retry)
        if (error instanceof Error &&
            (error.message.includes('Client error') ||
             error.message.includes('Authentication failed'))) {
          throw error;
        }

        // Handle abort/timeout
        if (error instanceof Error && error.name === 'AbortError') {
          lastError = new Error('Network timeout');
          continue;
        }

        // Handle network errors (retry)
        if (error instanceof Error) {
          lastError = error;
          continue;
        }

        // Unknown error - store and retry
        lastError = new Error('Unknown error occurred');
        continue;
      }
    }

    // All retries exhausted
    throw lastError || new Error('Request failed after retries');
  }
}
