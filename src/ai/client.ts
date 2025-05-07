import { AiProviderConfig } from '../types/index.js';
import { logger } from '../utils/logger.js';

/**
 * Interface for AI client implementations
 */
export interface AiClient {
  complete(prompt: string, options?: CompletionOptions): Promise<string>;
  streamComplete?(prompt: string, callback: (chunk: string) => void, options?: CompletionOptions): Promise<void>;
}

/**
 * Options for AI completions
 */
export interface CompletionOptions {
  model?: string;
  temperature?: number;
  maxTokens?: number;
  stop?: string[];
  topP?: number;
  frequencyPenalty?: number;
  presencePenalty?: number;
}

/**
 * Factory function to create an appropriate AI client based on provider config
 */
export function getAiClient(config: AiProviderConfig): AiClient {
  switch (config.provider.toLowerCase()) {
  case 'openai':
    return new OpenAiClient(config);
  case 'anthropic':
    return new AnthropicClient(config);
  case 'mistral':
    return new MistralClient(config);
  case 'ollama':
    return new OllamaClient(config);
  default:
    throw new Error(`Unsupported AI provider: ${config.provider}`);
  }
}

/**
 * OpenAI client implementation
 */
class OpenAiClient implements AiClient {
  private config: AiProviderConfig;
  
  constructor(config: AiProviderConfig) {
    this.config = config;
    
    if (!config.apiKey) {
      throw new Error('OpenAI API key is required');
    }
  }
  
  async complete(prompt: string, options: CompletionOptions = {}): Promise<string> {
    try {
      logger.debug('Sending request to OpenAI', { prompt: prompt.substring(0, 100) + '...' });
      
      // Make actual API call to OpenAI
      const response = await this.makeApiCall(prompt, options);
      
      return response;
    } catch (error) {
      logger.error('OpenAI API error', error);
      throw new Error(`OpenAI API error: ${error instanceof Error ? error.message : String(error)}`);
    }
  }
  
  // Make real API call to OpenAI
  private async makeApiCall(prompt: string, options: CompletionOptions): Promise<string> {
    try {
      const baseUrl = this.config.baseUrl || 'https://api.openai.com/v1';
      const model = options.model || this.config.model || 'gpt-4';
      const temperature = options.temperature ?? this.config.temperature ?? 0.2;
      const maxTokens = options.maxTokens ?? this.config.maxTokens ?? 2000;
      
      // If in test mode, fall back to mock response
      if (process.env.NODE_ENV === 'test') {
        return this.getMockResponse(prompt);
      }
      
      // Prepare the request body
      const requestBody = {
        model,
        messages: [{ role: 'user', content: prompt }],
        temperature,
        max_tokens: maxTokens,
        top_p: options.topP ?? 1,
        frequency_penalty: options.frequencyPenalty ?? 0,
        presence_penalty: options.presencePenalty ?? 0
      };
      
      // Make the API call
      const response = await fetch(`${baseUrl}/chat/completions`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${this.config.apiKey}`
        },
        body: JSON.stringify(requestBody)
      });
      
      // Handle errors
      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        throw new Error(`OpenAI API error (${response.status}): ${errorData.error?.message || response.statusText}`);
      }
      
      // Parse the response
      const data = await response.json();
      
      // Extract the completion text
      return data.choices[0]?.message?.content || '';
    } catch (error) {
      logger.error('Error calling OpenAI API', error);
      
      // In development, fall back to mock response if API call fails
      if (process.env.NODE_ENV === 'development') {
        logger.warn('Using mock response due to API error');
        return this.getMockResponse(prompt);
      }
      
      throw error;
    }
  }
  
  // Get mock response for testing and development fallback
  private getMockResponse(prompt: string): string {
    return `Analysis of the issue:

This appears to be a bug in the authentication system where token validation is failing for valid tokens that contain special characters. The issue is likely in the token parsing logic.

Files to modify:
- \`src/auth/tokenValidator.js\`
- \`src/utils/stringEscaping.js\`

Suggested Approach:
The token validator is not properly handling URL-encoded characters. We need to update the validation function to properly decode tokens before validation, and ensure that special characters are correctly handled throughout the authentication flow.`;
  }
}

/**
 * Anthropic client implementation
 */
class AnthropicClient implements AiClient {
  private config: AiProviderConfig;
  
  constructor(config: AiProviderConfig) {
    this.config = config;
    
    if (!config.apiKey) {
      throw new Error('Anthropic API key is required');
    }
  }
  
  async complete(prompt: string, options: CompletionOptions = {}): Promise<string> {
    try {
      logger.debug('Sending request to Anthropic', { prompt: prompt.substring(0, 100) + '...' });
      
      // Make actual API call to Anthropic
      const response = await this.makeApiCall(prompt, options);
      
      return response;
    } catch (error) {
      logger.error('Anthropic API error', error);
      throw new Error(`Anthropic API error: ${error instanceof Error ? error.message : String(error)}`);
    }
  }
  
  // Make real API call to Anthropic
  private async makeApiCall(prompt: string, options: CompletionOptions): Promise<string> {
    try {
      const baseUrl = this.config.baseUrl || 'https://api.anthropic.com';
      const model = options.model || this.config.model || 'claude-3-sonnet-20240229';
      const temperature = options.temperature ?? this.config.temperature ?? 0.2;
      const maxTokens = options.maxTokens ?? this.config.maxTokens ?? 2000;
      
      // If in test mode, fall back to mock response
      if (process.env.NODE_ENV === 'test') {
        return this.getMockResponse(prompt);
      }
      
      // Prepare the request body
      const requestBody = {
        model,
        messages: [{ role: 'user', content: prompt }],
        temperature,
        max_tokens: maxTokens,
        top_p: options.topP ?? 1,
        anthropic_version: '2023-06-01'
      };
      
      // Make the API call
      const response = await fetch(`${baseUrl}/v1/messages`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-API-Key': this.config.apiKey,
          'anthropic-version': '2023-06-01'
        },
        body: JSON.stringify(requestBody)
      });
      
      // Handle errors
      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        throw new Error(`Anthropic API error (${response.status}): ${errorData.error?.message || response.statusText}`);
      }
      
      // Parse the response
      const data = await response.json();
      
      // Extract the completion text
      return data.content?.[0]?.text || '';
    } catch (error) {
      logger.error('Error calling Anthropic API', error);
      
      // In development, fall back to mock response if API call fails
      if (process.env.NODE_ENV === 'development') {
        logger.warn('Using mock response due to API error');
        return this.getMockResponse(prompt);
      }
      
      throw error;
    }
  }
  
  // Get mock response for testing and development fallback
  private getMockResponse(prompt: string): string {
    return `Based on my analysis, this is a performance issue in the data processing pipeline.

The main bottleneck appears to be in the file processing function that's not properly streaming large files, leading to excessive memory usage.

Files that need modification:
- \`src/services/fileProcessor.js\`
- \`src/utils/streamHandler.js\`

This is a medium complexity issue that will require implementing proper stream processing instead of loading the entire file into memory. The fix should significantly reduce memory usage and improve processing speed.`;
  }
}

/**
 * Mistral client implementation
 */
class MistralClient implements AiClient {
  private config: AiProviderConfig;
  
  constructor(config: AiProviderConfig) {
    this.config = config;
    
    if (!config.apiKey) {
      throw new Error('Mistral API key is required');
    }
  }
  
  async complete(prompt: string, options: CompletionOptions = {}): Promise<string> {
    try {
      logger.debug('Sending request to Mistral', { prompt: prompt.substring(0, 100) + '...' });
      
      // Simulate API call for development purposes
      const response = await this.simulateApiCall(prompt, options);
      
      return response;
    } catch (error) {
      logger.error('Mistral API error', error);
      throw new Error(`Mistral API error: ${error instanceof Error ? error.message : String(error)}`);
    }
  }
  
  // Simulate API call for development
  private async simulateApiCall(prompt: string, options: CompletionOptions): Promise<string> {
    // Add a small delay to simulate network latency
    await new Promise(resolve => setTimeout(resolve, 550));
    
    // Return a mock response
    return `This is a documentation issue where the installation instructions are unclear for Windows users.

The documentation needs to be updated to include Windows-specific commands and requirements.

Files to modify:
- \`docs/installation.md\`
- \`README.md\`

This is a simple fix that involves adding a new section for Windows installation instructions, including how to set up the environment variables correctly and handle path differences.`;
  }
}

/**
 * Ollama client implementation (for local model deployment)
 */
class OllamaClient implements AiClient {
  private config: AiProviderConfig;
  
  constructor(config: AiProviderConfig) {
    this.config = config;
  }
  
  async complete(prompt: string, options: CompletionOptions = {}): Promise<string> {
    try {
      logger.debug('Sending request to Ollama', { prompt: prompt.substring(0, 100) + '...' });
      
      // Simulate API call for development purposes
      const response = await this.simulateApiCall(prompt, options);
      
      return response;
    } catch (error) {
      logger.error('Ollama API error', error);
      throw new Error(`Ollama API error: ${error instanceof Error ? error.message : String(error)}`);
    }
  }
  
  // Simulate API call for development
  private async simulateApiCall(prompt: string, options: CompletionOptions): Promise<string> {
    // Add a small delay to simulate inference time
    await new Promise(resolve => setTimeout(resolve, 1000));
    
    // Return a mock response
    return `I've analyzed the feature request for adding pagination to the API endpoints.

This is a medium complexity task that will require modifying multiple files:
- \`src/controllers/userController.js\`
- \`src/services/queryService.js\`
- \`src/middleware/pagination.js\` (new file needed)

The approach should be to create a reusable pagination middleware that can be applied to all list endpoints. This will require updating the query service to support limit and offset parameters, and updating the controllers to use the new middleware.`;
  }
}