# API Key Naming Clarification

## Problem Statement

The current codebase has ambiguous API key naming that confuses:
1. **Customer authentication keys** (RSOLV API keys - what we provide to customers)
2. **AI provider keys** (Anthropic, OpenAI keys - what customers provide for their own AI usage)

This creates confusion and potential security issues.

## Current State (Confusing)

### In `ActionConfig`:
```typescript
export interface ActionConfig {
  apiKey: string;              // ❌ AMBIGUOUS - actually RSOLV API key
  rsolvApiKey?: string;         // ✅ CLEAR - RSOLV API key (duplicate of above!)
  aiProvider: AiProviderConfig;
  // ...
}
```

### In `AiProviderConfig`:
```typescript
export interface AiProviderConfig {
  provider: 'openai' | 'anthropic' | 'mistral' | 'ollama' | string;
  apiKey?: string;              // ❌ AMBIGUOUS - actually AI provider key
  model: string;
  // ...
}
```

### Problems:
1. **`ActionConfig.apiKey`** - Ambiguous name, actually used for RSOLV API key
2. **`ActionConfig.rsolvApiKey`** - Clear name, but duplicates `apiKey`
3. **`AiProviderConfig.apiKey`** - Ambiguous name, actually used for AI provider key
4. Lines 250-251 in `src/config/index.ts` set BOTH to the same value!

## Proposed Solution

### 1. Remove Ambiguity in Type Definitions

```typescript
export interface ActionConfig {
  rsolvApiKey: string;          // ✅ Customer authentication (REQUIRED)
  // Remove: apiKey                ❌ DELETE THIS
  aiProvider: AiProviderConfig;
  // ...
}

export interface AiProviderConfig {
  provider: 'openai' | 'anthropic' | 'mistral' | 'ollama' | string;
  providerApiKey?: string;      // ✅ AI provider key (Anthropic/OpenAI)
  // Remove: apiKey                ❌ RENAME TO providerApiKey
  model: string;
  useVendedCredentials?: boolean; // If true, use RSOLV vended credentials
  // ...
}
```

### 2. Environment Variable Mapping

```typescript
// RSOLV API Key (customer authentication)
process.env.RSOLV_API_KEY              → config.rsolvApiKey
process.env.INPUT_RSOLV_API_KEY        → config.rsolvApiKey
process.env.INPUT_RSOLVAPIKEY          → config.rsolvApiKey

// AI Provider API Key (Anthropic/OpenAI)
process.env.RSOLV_AI_API_KEY           → config.aiProvider.providerApiKey
process.env.ANTHROPIC_API_KEY          → config.aiProvider.providerApiKey (if provider=anthropic)
process.env.OPENAI_API_KEY             → config.aiProvider.providerApiKey (if provider=openai)
```

### 3. Usage Patterns

#### Customer Authentication (RSOLV API Key)
```typescript
// Pattern API Client (for vulnerability patterns)
this.apiKey = config.rsolvApiKey;
headers: { 'x-api-key': config.rsolvApiKey }

// AST Analyzer (for server-side AST)
headers: { 'x-api-key': config.rsolvApiKey }

// Phase Data Client (for storing phase results)
headers: { 'x-api-key': config.rsolvApiKey }
```

#### AI Provider Authentication
```typescript
// When using customer's own AI key
if (!config.aiProvider.useVendedCredentials) {
  apiKey = config.aiProvider.providerApiKey;
}

// When using RSOLV vended credentials
if (config.aiProvider.useVendedCredentials) {
  apiKey = await getVendedCredential(config.rsolvApiKey);
}
```

## Migration Steps

### Phase 1: Add New Fields (Non-Breaking)
1. Add `AiProviderConfig.providerApiKey` alongside existing `apiKey`
2. Update code to read from `providerApiKey` if present, fall back to `apiKey`
3. Add deprecation warnings when `apiKey` is used

### Phase 2: Update Documentation
1. Update README and setup guides
2. Add migration guide for existing users
3. Update example configurations

### Phase 3: Remove Old Fields (Breaking Change)
1. Remove `ActionConfig.apiKey` (keep only `rsolvApiKey`)
2. Remove `AiProviderConfig.apiKey` (keep only `providerApiKey`)
3. Bump major version

## Files to Update

### Type Definitions
- `src/types/index.ts` - Update interfaces
- `src/config/index.ts` - Update schema and loading logic

### Configuration Loading
- `src/config/index.ts` lines 238-314 - Update env var mapping
- `src/config/index.ts` lines 352-376 - Update validation

### Usage Sites (40+ files)
- `src/ai/client.ts` - AI client initialization
- `src/ai/adapters/claude-code-cli.ts` - Claude Code adapter
- `src/security/pattern-api-client.ts` - Pattern API
- `src/security/analyzers/elixir-ast-analyzer.ts` - AST analyzer
- `src/modes/phase-data-client/index.ts` - Phase data storage
- All test files using these APIs

## Benefits

1. **Clarity**: No confusion about which key is which
2. **Security**: Reduced risk of using wrong key in wrong context
3. **Maintainability**: Easier to understand code intent
4. **Documentation**: Self-documenting code with clear names

## Example Configurations

### Before (Confusing)
```yaml
# .github/rsolv.yml
apiKey: "rsolv_key_abc123"  # Is this RSOLV or AI provider?
aiProvider:
  provider: anthropic
  apiKey: "sk-ant-xyz789"    # Another apiKey!
```

### After (Clear)
```yaml
# .github/rsolv.yml
rsolvApiKey: "rsolv_key_abc123"  # ✅ Clear: RSOLV authentication
aiProvider:
  provider: anthropic
  providerApiKey: "sk-ant-xyz789"  # ✅ Clear: Anthropic API key
  # Or use vended credentials:
  useVendedCredentials: true  # Uses RSOLV vended Anthropic key
```

## Backwards Compatibility

During Phase 1, support both old and new names:
```typescript
const rsolvKey = config.rsolvApiKey || config.apiKey;
const aiKey = config.aiProvider.providerApiKey || config.aiProvider.apiKey;
```

Log warnings when old names are used:
```typescript
if (config.apiKey && !config.rsolvApiKey) {
  console.warn('DEPRECATION: config.apiKey is deprecated, use config.rsolvApiKey');
}
```

## Timeline

- **Week 1**: Implement Phase 1 (non-breaking changes)
- **Week 2**: Update documentation and announce deprecation
- **Week 4**: Implement Phase 2 (remove old fields in next major version)
