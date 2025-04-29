/**
 * Configuration module for RSOLV Action
 */
import * as core from '@actions/core';
import { ActionConfig } from '../types';
import { AIProvider } from '../ai/types';

/**
 * Load configuration from environment or inputs
 */
export function loadConfig(inputs?: Record<string, string>): ActionConfig {
  // For testing, we can pass in mock inputs
  const getInput = (name: string, required = false): string => {
    if (inputs && inputs[name] !== undefined) {
      return inputs[name];
    }
    
    // Use the actual core.getInput when not testing
    return core.getInput(name, { required });
  };

  const getBooleanInput = (name: string): boolean => {
    if (inputs && inputs[name] !== undefined) {
      return inputs[name].toLowerCase() === 'true';
    }
    
    try {
      // Use the actual core.getBooleanInput when not testing
      return core.getBooleanInput(name);
    } catch (error) {
      // Default to false if the input is not provided or invalid
      return false;
    }
  };

  // Get AI provider config
  const aiProvider = getInput('ai_provider') || 'anthropic';
  const aiConfig: any = {
    provider: aiProvider as AIProvider,
  };

  // Get provider-specific API keys
  if (aiProvider === 'anthropic') {
    aiConfig.apiKey = getInput('anthropic_api_key') || getInput('api_key');
    aiConfig.modelName = getInput('anthropic_model') || 'claude-3-sonnet-20240229';
  } else if (aiProvider === 'openai') {
    aiConfig.apiKey = getInput('openai_api_key') || getInput('api_key');
    aiConfig.modelName = getInput('openai_model') || 'gpt-4';
  }

  // Build config from inputs
  const config: ActionConfig = {
    apiKey: getInput('api_key', true),
    issueTag: getInput('issue_tag') || 'AUTOFIX',
    expertReviewCommand: getInput('expert_review_command') || '/request-expert-review',
    debug: getBooleanInput('debug'),
    skipSecurityCheck: getBooleanInput('skip_security_check'),
    aiConfig,
  };

  // Log config in debug mode (omitting sensitive info)
  if (config.debug) {
    core.debug('Configuration loaded:');
    core.debug(`- Issue tag: ${config.issueTag}`);
    core.debug(`- Expert review command: ${config.expertReviewCommand}`);
    core.debug(`- AI provider: ${config.aiConfig.provider}`);
    core.debug(`- AI model: ${config.aiConfig.modelName}`);
    core.debug(`- Debug mode: ${config.debug}`);
    core.debug(`- Skip security check: ${config.skipSecurityCheck}`);
  }

  return config;
}

/**
 * Validate input values
 */
export function validateInput(name: string, value: string): string | null {
  switch (name) {
    case 'api_key':
      if (!value || value.length < 10) {
        return 'API key must be at least 10 characters long';
      }
      break;
    case 'issue_tag':
      if (value && !/^[a-zA-Z0-9_-]+$/.test(value)) {
        return 'Issue tag must only contain alphanumeric characters, underscores, and hyphens';
      }
      break;
    case 'ai_provider':
      const validProviders = ['anthropic', 'openrouter', 'openai', 'mistral', 'ollama'];
      if (value && !validProviders.includes(value)) {
        return `AI provider must be one of: ${validProviders.join(', ')}`;
      }
      break;
  }
  return null;
}