import { logger } from '../utils/logger.js';

export interface ProviderCredential {
  api_key: string;
  expires_at: string;
}

export interface CredentialExchangeResponse {
  credentials: Record<string, ProviderCredential>;
  usage: {
    remaining_fixes: number;
    reset_at: string;
  };
}

export interface UsageReport {
  tokensUsed: number;
  requestCount: number;
}

export class RSOLVCredentialManager {
  private credentials: Map<string, ProviderCredential> = new Map();
  private apiKey: string = '';
  private rsolvApiUrl: string;
  private refreshTimers: Map<string, ReturnType<typeof setTimeout>> = new Map();

  constructor() {
    this.rsolvApiUrl = process.env.RSOLV_API_URL || 'https://api.rsolv.dev';
  }

  async initialize(apiKey: string): Promise<void> {
    this.apiKey = apiKey;
    logger.info('Initializing RSOLV credential manager');

    try {
      const requestBody = {
        api_key: apiKey,
        providers: ['anthropic', 'openai', 'openrouter'],
        ttl_minutes: 60
      };
      
      logger.info(`Requesting credential exchange from ${this.rsolvApiUrl}/api/v1/credentials/exchange`);
      
      const response = await fetch(`${this.rsolvApiUrl}/api/v1/credentials/exchange`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${apiKey}`,
          'Content-Type': 'application/json',
          'X-GitHub-Job': process.env.GITHUB_JOB || '',
          'X-GitHub-Run': process.env.GITHUB_RUN_ID || ''
        },
        body: JSON.stringify(requestBody),
        signal: AbortSignal.timeout(15000) // 15 second timeout to prevent hanging
      });

      if (!response.ok) {
        const error = await response.json();
        logger.error(`Credential exchange failed - Status: ${response.status}, Body:`, error);
        throw new Error(`Failed to exchange credentials: ${error.error || response.statusText}`);
      }

      const data: CredentialExchangeResponse = await response.json();
      
      // Check if response has expected structure
      if (!data || !data.credentials) {
        logger.error('Invalid credential exchange response:', data);
        throw new Error('Invalid response from credential exchange API');
      }
      
      // Store credentials
      Object.entries(data.credentials).forEach(([provider, credential]) => {
        logger.debug(`Storing credential for ${provider}`, { 
          hasApiKey: !!credential.api_key,
          apiKeyLength: credential.api_key?.length || 0,
          expiresAt: credential.expires_at 
        });
        this.credentials.set(provider, credential);
      });

      // Log usage info
      if (data.usage) {
        logger.info(`Credentials initialized. Remaining fixes: ${data.usage.remaining_fixes}`);
      } else {
        logger.info('Credentials initialized');
      }

      // Schedule refresh for credentials
      this.scheduleRefresh(data.credentials);
    } catch (error) {
      logger.error('Failed to initialize credentials', error);
      throw error;
    }
  }

  getCredential(provider: string): string {
    const credential = this.credentials.get(provider);
    
    logger.debug(`Getting credential for ${provider}`, {
      hasCredential: !!credential,
      hasApiKey: !!credential?.api_key,
      apiKeyLength: credential?.api_key?.length || 0
    });
    
    if (!credential) {
      throw new Error(`No valid credential for ${provider}`);
    }

    // Check if expired
    const expiresAt = new Date(credential.expires_at);
    if (expiresAt < new Date()) {
      throw new Error(`Credential for ${provider} has expired`);
    }
    
    if (!credential.api_key) {
      throw new Error(`Credential for ${provider} has no API key`);
    }

    return credential.api_key;
  }

  async reportUsage(provider: string, usage: UsageReport): Promise<void> {
    try {
      const response = await fetch(`${this.rsolvApiUrl}/api/v1/usage/report`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${this.apiKey}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          provider: provider,
          tokens_used: usage.tokensUsed,
          request_count: usage.requestCount,
          job_id: process.env.GITHUB_JOB
        }),
        signal: AbortSignal.timeout(5000) // 5 second timeout for usage reporting
      });

      if (!response.ok) {
        const error = await response.json();
        throw new Error(`Failed to report usage: ${error.error || response.statusText}`);
      }
    } catch (error) {
      // Don't throw on usage reporting failures - just log
      logger.warn('Failed to report usage', error);
    }
  }

  cleanup(): void {
    // Clear credentials
    this.credentials.clear();
    
    // Cancel refresh timers
    this.refreshTimers.forEach(timer => clearTimeout(timer));
    this.refreshTimers.clear();
    
    logger.info('Credential manager cleaned up');
  }

  private scheduleRefresh(credentials: Record<string, ProviderCredential>): void {
    Object.entries(credentials).forEach(([provider, credential]) => {
      const expiresAt = new Date(credential.expires_at);
      const now = new Date();
      const msUntilExpiry = expiresAt.getTime() - now.getTime();
      
      // Refresh 5 minutes before expiry
      const refreshTime = msUntilExpiry - (5 * 60 * 1000);
      
      if (refreshTime > 0) {
        const timer = setTimeout(() => {
          this.refreshCredentials(provider).catch(err => {
            logger.error('Failed to refresh credentials', err);
          });
        }, refreshTime);
        
        this.refreshTimers.set(provider, timer);
        logger.debug(`Scheduled refresh for ${provider} in ${refreshTime}ms`);
      }
    });
  }

  private async refreshCredentials(provider: string): Promise<void> {
    const currentCredential = this.credentials.get(provider);
    if (!currentCredential) {
      logger.warn(`No credential found for ${provider} during refresh`);
      return;
    }

    logger.info(`Refreshing credentials for ${provider}`);

    try {
      const response = await fetch(`${this.rsolvApiUrl}/api/v1/credentials/refresh`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${this.apiKey}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          api_key: this.apiKey,
          credential_id: provider // Using provider as ID for simplicity
        }),
        signal: AbortSignal.timeout(10000) // 10 second timeout for refresh
      });

      if (!response.ok) {
        const error = await response.json();
        throw new Error(`Failed to refresh credentials: ${error.error || response.statusText}`);
      }

      const data = await response.json();
      const newCredential = data.credentials[provider];
      
      if (newCredential) {
        this.credentials.set(provider, newCredential);
        logger.info(`Successfully refreshed credentials for ${provider}`);
        
        // Schedule next refresh
        this.scheduleRefresh({ [provider]: newCredential });
      }
    } catch (error) {
      logger.error(`Failed to refresh credentials for ${provider}`, error);
      throw error;
    }
  }
}