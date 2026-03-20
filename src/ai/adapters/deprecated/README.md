# Deprecated Claude Code Adapters

**Status:** Partially deprecated as of RFC-095. Dead SDK adapters removed March 2026.

## What's Here

CLI-based adapters still reachable via the `use_legacy_claude_adapter` feature flag:

| File | Purpose | Used By |
|------|---------|---------|
| `claude-code-git.ts` | Git-based editing via CLI | `claude-agent-sdk.ts` (feature flag fallback) |
| `claude-code-cli-retry.ts` | Credential vending + retry | `claude-code-git.ts`, `claude-code-cli-dev.ts` |
| `claude-code-cli.ts` | CLI subprocess execution | `claude-code-cli-retry.ts` |
| `claude-code-cli-dev.ts` | Claude Code Max for local dev | `git-based-processor.ts` |

## Removed (March 2026)

The following SDK-based adapters were removed — they imported from `@anthropic-ai/claude-code`
which dropped its SDK exports in v2.x. Recoverable from git history if needed.

- `claude-code.ts` (base SDK integration, ADR-011)
- `claude-code-enhanced.ts` (deep context gathering)
- `claude-code-single-pass.ts` (token optimization)

## Rollback

The `use_legacy_claude_adapter` FunWithFlags flag routes to `GitBasedClaudeCodeAdapter`
(CLI-based, no SDK dependency). See ADR-040 and RFC-095.
