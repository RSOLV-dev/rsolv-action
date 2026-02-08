/** Centralized model ID constants. Update here when models change. */
export const MODELS = {
  /** Claude Opus 4.6 -- most capable, for complex analysis */
  CLAUDE_OPUS: 'claude-opus-4-6',
  /** Claude Sonnet 4.5 -- balanced performance/cost, default for RSOLV */
  CLAUDE_SONNET: 'claude-sonnet-4-5-20250929',
  /** Claude Haiku 4.5 -- fast/cheap for simple tasks */
  CLAUDE_HAIKU: 'claude-haiku-4-5-20251001',
} as const;

/** OpenRouter model format (prefixed with provider) */
export const OPENROUTER_MODELS = {
  CLAUDE_OPUS: `anthropic/${MODELS.CLAUDE_OPUS}`,
  CLAUDE_SONNET: `anthropic/${MODELS.CLAUDE_SONNET}`,
} as const;

/** Default model for RSOLV action */
export const DEFAULT_MODEL = MODELS.CLAUDE_SONNET;
