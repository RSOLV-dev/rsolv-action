# Deprecated Claude Code Adapters

**Status:** Deprecated as of RFC-095
**Migration:** All functionality consolidated into `ClaudeAgentSDKAdapter`

## What's Here

These are the 7 legacy Claude Code adapters that were replaced by the unified `ClaudeAgentSDKAdapter`:

| File | Original Purpose | RFC/ADR |
|------|------------------|---------|
| `claude-code.ts` | Base SDK integration | ADR-011 |
| `claude-code-enhanced.ts` | Deep context gathering | ADR-011 |
| `claude-code-git.ts` | Git-based editing | ADR-012 |
| `claude-code-cli.ts` | CLI subprocess execution | RFC-040 |
| `claude-code-cli-retry.ts` | Credential vending + retry | RFC-061 |
| `claude-code-cli-dev.ts` | Claude Code Max for dev | RFC-048 |
| `claude-code-single-pass.ts` | Token optimization | (implicit) |

## Why Deprecated

1. **Fragmentation**: 7 adapters created maintenance burden and inconsistent behavior
2. **No structured outputs**: Legacy adapters relied on regex JSON extraction
3. **Limited observability**: No programmatic hooks (RFC-061 concern)
4. **No session forking**: Could not A/B test different approaches

## Rollback Instructions

If you need to rollback to legacy adapters:

1. Set environment variable: `USE_LEGACY_CLAUDE_ADAPTERS=true`
2. The `ai/index.ts` will dynamically import from this deprecated folder
3. All legacy adapter exports will be available

**Note:** Rollback is temporary. Please report issues with the new adapter.

## Migration Timeline

- **Phase 1 (now):** Adapters moved to deprecated, feature flag for rollback
- **Phase 2 (next release):** Deprecation warnings logged when using legacy adapters
- **Phase 3 (release + 2):** Legacy adapters removed entirely

## Test Files

The `__tests__/` directory contains unit tests for the legacy adapters. These are excluded from the main test run but can be used to verify legacy behavior if needed:

```bash
# Run only deprecated adapter tests
npm run test -- src/ai/adapters/deprecated/__tests__/
```

## Questions?

See RFC-095 for the complete migration plan and ADR-040 for the implementation decision record.
