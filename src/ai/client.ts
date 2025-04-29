import { AIClient, AIConfig } from './types';
import { logger } from '../utils/logger';
import { AnthropicClient } from './providers/anthropic';
import { OpenRouterClient } from './providers/openrouter';
import { OllamaClient } from './providers/ollama';

/**
 * Get an AI client based on the configured provider
 */
export function getAIClient(config: AIConfig): AIClient {
  logger.info(`Initializing AI client for provider: ${config.provider}`);
  
  switch (config.provider) {
    case 'anthropic':
      return new AnthropicClient(config);
    
    case 'openrouter':
      return new OpenRouterClient(config);
    
    case 'ollama':
      return new OllamaClient(config);
    
    case 'openai':
    case 'mistral':
      // These will be implemented in the future
      throw new Error(`AI provider ${config.provider} is not yet implemented`);
    
    default:
      throw new Error(`Unknown AI provider: ${config.provider}`);
  }
}