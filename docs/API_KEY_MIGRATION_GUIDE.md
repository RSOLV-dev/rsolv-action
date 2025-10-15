# API Key Naming Migration Guide

## Summary

This guide helps you migrate from the old ambiguous API key naming to the new clarified naming convention.

## What Changed?

### Type Definitions

**Old (Ambiguous):**
```typescript
interface ActionConfig {
  apiKey: string;  // ❌ Ambiguous - which API key?
  rsolvApiKey?: string;  // Duplicate!
}

interface AiProviderConfig {
  apiKey?: string;  // ❌ Ambiguous - which API key?
}
```

**New (Clear):**
```typescript
interface ActionConfig {
  rsolvApiKey: string;  // ✅ RSOLV platform API key
  apiKey?: string;  // @deprecated - backwards compatibility only
}

interface AiProviderConfig {
  providerApiKey?: string;  // ✅ AI provider API key (Anthropic, OpenAI, etc.)
  apiKey?: string;  // @deprecated - backwards compatibility only
}
```

## Migration Steps

### For Configuration Files

**Option 1: Update to new naming (recommended)**

```yaml
# Old config
rsolvApiKey: "rsolv_sk_..."
aiProvider:
  provider: "anthropic"
  apiKey: "sk-ant-..."  # ❌ Ambiguous

# New config
rsolvApiKey: "rsolv_sk_..."
aiProvider:
  provider: "anthropic"
  providerApiKey: "sk-ant-..."  # ✅ Clear
```

**Option 2: Keep old naming (backwards compatible)**

No changes needed! The old naming still works, but you'll see deprecation warnings:
```
DEPRECATION WARNING: config.apiKey is deprecated. Use config.rsolvApiKey instead.
DEPRECATION WARNING: aiProvider.apiKey is deprecated. Use aiProvider.providerApiKey instead.
```

### For Code

**Old code:**
```typescript
const config: ActionConfig = {
  apiKey: rsolvApiKey,
  aiProvider: {
    provider: 'anthropic',
    apiKey: anthropicKey
  }
};
```

**New code:**
```typescript
const config: ActionConfig = {
  rsolvApiKey: rsolvApiKey,  // Clear: RSOLV platform key
  aiProvider: {
    provider: 'anthropic',
    providerApiKey: anthropicKey  // Clear: Anthropic API key
  }
};
```

**Backwards compatible code (access pattern):**
```typescript
// This pattern works with both old and new configs
const rsolvKey = config.rsolvApiKey || config.apiKey;
const aiKey = config.aiProvider.providerApiKey || config.aiProvider.apiKey;
```

### For Environment Variables

No changes needed! Environment variable names remain the same:
- `RSOLV_API_KEY` - RSOLV platform API key
- `RSOLV_AI_API_KEY` - AI provider API key (optional)

## Deprecation Timeline

### Phase 1: Non-Breaking (Current)
- ✅ New naming available
- ✅ Old naming still works
- ⚠️ Deprecation warnings logged

### Phase 2: Documentation (Next Release)
- Update all documentation to use new naming
- Add migration notices to README
- Update examples and tutorials

### Phase 3: Breaking Change (Future)
- Remove support for old naming
- `apiKey` will no longer work
- Must use `rsolvApiKey` and `providerApiKey`

## Benefits

1. **Clear Separation**: Immediately understand which key is needed
2. **Better Security**: Reduced risk of using wrong key
3. **Type Safety**: TypeScript will help catch errors
4. **Documentation**: Self-documenting configuration

## Examples

### GitHub Action Workflow

```yaml
# Both old and new naming work
- uses: rsolv-ai/rsolv-action@v1
  with:
    # RSOLV platform API key
    rsolvApiKey: ${{ secrets.RSOLV_API_KEY }}

    # Or if providing custom AI provider key
    aiProvider:
      provider: "anthropic"
      providerApiKey: ${{ secrets.ANTHROPIC_API_KEY }}
```

### Programmatic Usage

```typescript
import { loadConfig } from '@rsolv/action';

// New naming
const config = {
  rsolvApiKey: process.env.RSOLV_API_KEY!,
  aiProvider: {
    provider: 'anthropic',
    providerApiKey: process.env.ANTHROPIC_API_KEY,
    model: 'claude-3-5-sonnet-20241022'
  }
};
```

## Questions?

See [API_KEY_NAMING_CLARIFICATION.md](./API_KEY_NAMING_CLARIFICATION.md) for the full technical specification.
