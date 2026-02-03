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

import { logger } from '../utils/logger.js';

// Types based on RFC-060-AMENDMENT-001 API specification
export interface FrameworkDetectRequest {
  packageJson?: { devDependencies?: Record<string, string>; dependencies?: Record<string, string> } | null;
  gemfile?: string | null;
  requirementsTxt?: string | null;
  composerJson?: { 'require-dev'?: Record<string, string>; require?: Record<string, string> } | null;
  mixExs?: string | null;
  pomXml?: string | null;
  buildGradle?: string | null;
  configFiles?: string[];
}

export interface FrameworkDetectResponse {
  framework: string;
  version?: string | null;
  testDir: string;
  compatibleWith: string[];
}

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
  testSuite: {
    redTests: Array<{
      testName: string;
      testCode: string;
      attackVector: string;
      expectedBehavior: string;
      vulnerableCodePath?: string;
      vulnerablePattern?: string;
    }>;
  };
  framework: string;
  language: string;
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
  private readonly maxRetries = 3;
  private readonly baseDelay = 100; // milliseconds

  constructor(
    private apiKey: string,
    baseUrl?: string
  ) {
    // Support environment variable override with production default
    this.baseUrl = baseUrl || process.env.RSOLV_API_URL || 'https://api.rsolv.dev';
  }

  /**
   * Detect test framework from package/manifest files via backend API
   */
  async detectFramework(request: FrameworkDetectRequest): Promise<FrameworkDetectResponse> {
    return this.makeRequest<FrameworkDetectResponse>(
      '/api/v1/framework/detect',
      request
    );
  }

  /**
   * Analyze test files and recommend best integration target
   */
  async analyze(request: AnalyzeRequest): Promise<AnalyzeResponse> {
    return this.makeRequest<AnalyzeResponse>(
      '/api/v1/test-integration/analyze',
      request
    );
  }

  /**
   * Generate AST-based test integration
   */
  async generate(request: GenerateRequest): Promise<GenerateResponse> {
    return this.makeRequest<GenerateResponse>(
      '/api/v1/test-integration/generate',
      request
    );
  }

  /**
   * Make HTTP request with retry logic and exponential backoff
   */
  private async makeRequest<T>(
    endpoint: string,
    body: any,
    attempt: number = 0
  ): Promise<T> {
    const url = `${this.baseUrl}${endpoint}`;

    try {
      const response = await fetch(url, {
        method: 'POST',
        headers: {
          'x-api-key': this.apiKey,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(body)
      });

      // Handle 4xx client errors - don't retry
      if (response.status >= 400 && response.status < 500) {
        if (response.status === 401) {
          throw new Error('Unauthorized: Invalid API key');
        }

        let errorMessage = `HTTP ${response.status}: ${response.statusText}`;
        try {
          const errorData = await response.json();
          if (errorData.error) {
            errorMessage = `HTTP ${response.status}: ${errorData.error}`;
          }
        } catch {
          // Ignore JSON parse errors
        }

        throw new Error(errorMessage);
      }

      // Handle 5xx server errors - retry with exponential backoff
      if (response.status >= 500) {
        if (attempt < this.maxRetries) {
          const delay = this.baseDelay * Math.pow(2, attempt);
          logger.warn(`Server error (${response.status}), retrying in ${delay}ms (attempt ${attempt + 1}/${this.maxRetries})`);
          await this.sleep(delay);
          return this.makeRequest<T>(endpoint, body, attempt + 1);
        }
        throw new Error(`Server error after ${this.maxRetries} attempts: ${response.statusText}`);
      }

      // Success - parse and return response
      if (!response.ok) {
        throw new Error(`Unexpected response: ${response.status} ${response.statusText}`);
      }

      return await response.json();

    } catch (error) {
      // Network errors - retry with exponential backoff
      if (this.isRetriableError(error) && attempt < this.maxRetries) {
        const delay = this.baseDelay * Math.pow(2, attempt);
        logger.warn(`Network error, retrying in ${delay}ms (attempt ${attempt + 1}/${this.maxRetries}):`, error);
        await this.sleep(delay);
        return this.makeRequest<T>(endpoint, body, attempt + 1);
      }

      // Re-throw if we've exhausted retries or it's not retriable
      throw error;
    }
  }

  /**
   * Check if error is retriable (network issues)
   */
  private isRetriableError(error: any): boolean {
    // Network errors from fetch
    if (error instanceof TypeError && error.message.includes('fetch')) {
      return true;
    }

    // Connection errors
    const retriableMessages = [
      'ECONNREFUSED',
      'ENOTFOUND',
      'ETIMEDOUT',
      'ECONNRESET',
      'Network timeout',
      'Network error'
    ];

    return retriableMessages.some(msg =>
      error?.message?.includes(msg) || error?.code?.includes(msg)
    );
  }

  /**
   * Sleep utility for backoff
   */
  private sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}
