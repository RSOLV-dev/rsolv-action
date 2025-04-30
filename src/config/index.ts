import * as core from '@actions/core';
import { AIProvider } from '../ai/types';

/**
 * Get an input from GitHub Actions or environment variables
 * 
 * This function tries to get the input from GitHub Actions first,
 * then falls back to environment variables
 */
function getInput(name: string, required: boolean = false): string {
  try {
    // Try to get from GitHub Actions input
    return core.getInput(name, { required });
  } catch (error) {
    // If we're not in a GitHub Actions environment or the input is not set,
    // try to get from environment variables
    const envName = `INPUT_${name.toUpperCase().replace(/-/g, '_')}`;
    const envValue = process.env[envName];
    
    if (required && !envValue) {
      throw new Error(`Input required and not supplied: ${name}`);
    }
    
    return envValue || '';
  }
}

/**
 * Get a boolean input from GitHub Actions or environment variables
 */
function getBooleanInput(name: string): boolean {
  const value = getInput(name);
  return value === 'true';
}

/**
 * Configuration for the RSOLV Action
 */
export interface ActionConfig {
  apiKey: string;
  issueTag: string;
  expertReviewCommand: string;
  debug: boolean;
  skipSecurityCheck: boolean;
  aiConfig: any;
}

/**
 * Load the configuration from GitHub Actions inputs or environment variables
 */
export function loadConfig(inputs: Record<string, string> = {}): ActionConfig {
  // For testing purposes, allow passing inputs directly
  const getInputWrapper = (name: string, required: boolean = false): string => {
    if (name in inputs) {
      return inputs[name];
    }
    return getInput(name, required);
  };
  
  const getBooleanInputWrapper = (name: string): boolean => {
    if (name in inputs) {
      return inputs[name] === 'true';
    }
    return getBooleanInput(name);
  };

  // Validate required inputs
  const apiKey = getInputWrapper('api_key', true);
  if (!apiKey) {
    throw new Error('API key is required');
  }

  // Get AI provider config
  const aiProvider = getInputWrapper('ai_provider') || 'anthropic';
  const aiConfig: any = {
    provider: aiProvider as AIProvider,
  };

  // Get provider-specific API keys
  if (aiProvider === 'anthropic') {
    aiConfig.apiKey = getInputWrapper('anthropic_api_key') || getInputWrapper('api_key');
    aiConfig.modelName = getInputWrapper('anthropic_model') || 'claude-3-sonnet-20240229';
  } else if (aiProvider === 'openai') {
    aiConfig.apiKey = getInputWrapper('openai_api_key') || getInputWrapper('api_key');
    aiConfig.modelName = getInputWrapper('openai_model') || 'gpt-4';
  }
  
  // Check if Claude Code should be used
  aiConfig.useClaudeCode = getBooleanInputWrapper('use_claude_code');

  // Build config from inputs
  const config: ActionConfig = {
    apiKey: getInputWrapper('api_key', true),
    issueTag: getInputWrapper('issue_tag') || 'AUTOFIX',
    expertReviewCommand: getInputWrapper('expert_review_command') || '/request-expert-review',
    debug: getBooleanInputWrapper('debug'),
    skipSecurityCheck: getBooleanInputWrapper('skip_security_check'),
    aiConfig,
  };

  // Log config in debug mode (omitting sensitive info)
  if (config.debug) {
    core.debug('Configuration loaded:');
    core.debug(`- Issue tag: ${config.issueTag}`);
    core.debug(`- Expert review command: ${config.expertReviewCommand}`);
    core.debug(`- AI provider: ${config.aiConfig.provider}`);
    core.debug(`- AI model: ${config.aiConfig.modelName}`);
    core.debug(`- Use Claude Code: ${config.aiConfig.useClaudeCode}`);
    core.debug(`- Debug mode: ${config.debug}`);
    core.debug(`- Skip security check: ${config.skipSecurityCheck}`);
  }

  return config;
}

/**
 * Validate an input value
 * Returns an error message if validation fails, or null if validation passes
 */
export function validateInput(name: string, value: string): string | null {
  switch (name) {
    case 'api_key':
      if (value.length < 10) {
        return 'API key must be at least 10 characters long';
      }
      break;
    
    case 'issue_tag':
      if (!/^[a-zA-Z0-9_-]+$/.test(value)) {
        return 'Issue tag must only contain alphanumeric characters, underscores, and hyphens';
      }
      break;
    
    case 'ai_provider':
      const validProviders = ['anthropic', 'openrouter', 'openai', 'mistral', 'ollama'];
      if (!validProviders.includes(value)) {
        return `AI provider must be one of: ${validProviders.join(', ')}`;
      }
      break;
  }
  
  return null;
}