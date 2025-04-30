/**
 * AI client factory for the RSOLV system
 * This creates and configures the appropriate AI client based on the configuration
 */
import { AnthropicClient } from './providers/anthropic';
import { OpenRouterClient } from './providers/openrouter';
import { OllamaClient } from './providers/ollama';
import { ClaudeCodeAdapter } from './adapters/claude-code';
import { AIClient, AIConfig, RepoContext } from './types';
import { logger } from '../utils/logger';

/**
 * ClaudeCodeWrapper adapts the ClaudeCodeAdapter to the AIClient interface
 * This allows seamless integration into the existing system
 */
class ClaudeCodeWrapper implements AIClient {
  private adapter: ClaudeCodeAdapter;
  private repoPath: string;
  
  constructor(config: AIConfig, repoPath: string = process.cwd()) {
    this.adapter = new ClaudeCodeAdapter(config, repoPath);
    this.repoPath = repoPath;
  }
  
  async generateSolution(
    issueTitle: string,
    issueBody: string,
    issueAnalysis: any,
    repoContext?: RepoContext
  ): Promise<any> {
    // Map to the adapter's expected interface
    const issueContext = {
      id: 'local',
      title: issueTitle,
      body: issueBody,
      labels: [],
      repository: repoContext?.repository || { owner: 'unknown', name: 'unknown' },
      source: 'github',
      metadata: {}
    };
    
    // Pass the repo context to the adapter
    return this.adapter.generateSolution(issueContext, issueAnalysis);
  }
  
  async analyzeIssue(
    issueTitle: string,
    issueBody: string,
    repoContext?: RepoContext
  ): Promise<any> {
    // For Claude Code, we'll rely on its built-in analysis capabilities
    // but we still need to provide a minimal analysis object for compatibility
    return {
      complexity: 'medium',
      estimatedTime: 30,
      suggestedApproach: 'Determined by Claude Code context gathering',
      relatedFiles: [],
      aiConfidence: 'high',
      issueType: 'bug',
      language: 'unknown'
    };
  }
}

/**
 * Create an AI client based on the provided configuration
 */
export function getAIClient(config: AIConfig): AIClient {
  // Check if Claude Code should be used
  if (config.useClaudeCode) {
    logger.info('Using Claude Code adapter for AI operations');
    return new ClaudeCodeWrapper(config);
  }
  
  // Otherwise, use the standard AI providers
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