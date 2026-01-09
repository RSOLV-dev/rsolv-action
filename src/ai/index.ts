import { analyzeIssue } from './analyzer.js';
import { generateSolution } from './solution.js';
import { generateSolutionWithFeedback } from './feedbackEnhanced.js';
import {
  AIClient,
  AIProvider,
  AIConfig,
  IssueAnalysis,
  PullRequestSolution
} from './types.js';
import { SecurityAwareAnalyzer } from './security-analyzer.js';
import * as SecurityPrompts from './security-prompts.js';

// RFC-095: New unified Claude Agent SDK adapter
import {
  ClaudeAgentSDKAdapter,
  GitSolutionResult,
  createClaudeAgentSDKAdapter
} from './adapters/claude-agent-sdk.js';

// Legacy adapter - deprecated, use ClaudeAgentSDKAdapter instead
// Feature flag: USE_LEGACY_CLAUDE_ADAPTERS=true to use old adapters
// Legacy adapters moved to ./adapters/deprecated/ per RFC-095
const useLegacyAdapters = process.env.USE_LEGACY_CLAUDE_ADAPTERS === 'true';
let ClaudeCodeAdapter: typeof ClaudeAgentSDKAdapter;

if (useLegacyAdapters) {
  // Dynamic import for legacy adapter when feature flag is set
  const legacyModule = await import('./adapters/deprecated/claude-code.js');
  ClaudeCodeAdapter = legacyModule.ClaudeCodeAdapter as unknown as typeof ClaudeAgentSDKAdapter;
} else {
  // Use new unified adapter (default)
  ClaudeCodeAdapter = ClaudeAgentSDKAdapter;
}

export {
  analyzeIssue,
  generateSolution,
  generateSolutionWithFeedback,
  SecurityAwareAnalyzer,
  SecurityPrompts,
  AIClient,
  AIProvider,
  AIConfig,
  IssueAnalysis,
  PullRequestSolution,
  // RFC-095: Export both old name (for compatibility) and new name
  ClaudeCodeAdapter,
  ClaudeAgentSDKAdapter,
  GitSolutionResult,
  createClaudeAgentSDKAdapter
};