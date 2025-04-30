import { AIClient, AIConfig } from './types';
import { logger } from '../utils/logger';
import { AnthropicClient } from './providers/anthropic';
import { OpenRouterClient } from './providers/openrouter';
import { OllamaClient } from './providers/ollama';
import { ClaudeCodeAdapter } from './adapters/claude-code';
import { IssueContext } from '../types';

/**
 * Wrapper class to adapt the Claude Code adapter to the AIClient interface
 */
class ClaudeCodeWrapper implements AIClient {
  private adapter: ClaudeCodeAdapter;
  private repoPath: string;
  
  constructor(config: AIConfig, repoPath: string = process.cwd()) {
    this.adapter = new ClaudeCodeAdapter(config, repoPath);
    this.repoPath = repoPath;
  }
  
  async analyzeIssue(
    issueTitle: string,
    issueBody: string,
    repoContext?: any
  ): Promise<IssueAnalysis> {
    // For now, we'll use the Anthropic client for analysis
    // In a future update, we could add analysis capabilities to the Claude Code adapter
    const anthropicClient = new AnthropicClient({
      provider: 'anthropic',
      apiKey: this.adapter['config'].apiKey,
      modelName: this.adapter['config'].modelName
    });
    
    return anthropicClient.analyzeIssue(issueTitle, issueBody, repoContext);
  }
  
  async generateSolution(
    issueTitle: string,
    issueBody: string,
    issueAnalysis: IssueAnalysis,
    repoContext?: any
  ): Promise<PullRequestSolution> {
    // Create an issue context object from the parameters
    const issueContext: IssueContext = {
      id: `issue-${Date.now()}`,
      title: issueTitle,
      body: issueBody,
      repository: {
        owner: repoContext?.owner || 'unknown',
        name: repoContext?.repo || 'unknown',
        branch: repoContext?.branch || 'main'
      },
      source: repoContext?.source || 'github',
      url: repoContext?.url || '',
      labels: repoContext?.labels || []
    };
    
    // Use the Claude Code adapter to generate a solution
    return this.adapter.generateSolution(issueContext, issueAnalysis);
  }
}

/**
 * Get an AI client based on the configured provider
 */
export function getAIClient(config: AIConfig): AIClient {
  logger.info(`Initializing AI client for provider: ${config.provider}`);
  
  // Check if Claude Code is enabled
  if (config.useClaudeCode) {
    logger.info('Using Claude Code for enhanced context-gathering');
    return new ClaudeCodeWrapper(config);
  }
  
  // Otherwise use the standard AI providers
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