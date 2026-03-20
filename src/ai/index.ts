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

// RFC-095: Unified Claude Agent SDK adapter
import {
  ClaudeAgentSDKAdapter,
  GitSolutionResult,
  createClaudeAgentSDKAdapter
} from './adapters/claude-agent-sdk.js';

// Alias for backwards compatibility — the legacy SDK adapter was removed.
// CLI-based fallback is still available via the use_legacy_claude_adapter
// FunWithFlags feature flag in createClaudeAgentSDKAdapter().
const ClaudeCodeAdapter = ClaudeAgentSDKAdapter;

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