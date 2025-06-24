# RFC-022: Universal Test Framework Detection via Claude Code SDK

**Status:** Draft  
**Created:** 2025-06-24  
**Author:** Dylan

## Summary

Replace language-specific test framework detection logic with a universal AI-powered detector using Claude Code SDK, providing better coverage and maintainability.

## Motivation

Current test framework detection has several limitations:

1. **Language-Specific Logic**: We maintain separate detection patterns for each language
2. **Missing Edge Cases**: Can't detect frameworks without package files (e.g., Django without requirements.txt)
3. **Framework Variants**: Difficulty handling framework plugins and extensions
4. **Test Commands**: Can't reliably determine how to run tests
5. **Maintenance Burden**: Constantly updating patterns for new frameworks

## Proposed Solution

### 1. Claude Code SDK Integration

```typescript
interface UniversalFrameworkDetector {
  detect(repoPath: string): Promise<{
    framework: string;
    version: string;
    testCommand: string;
    setupSteps: string[];
    confidence: number;
  }>;
}
```

### 2. Hybrid Approach

```typescript
async function detectTestFramework(repo: string) {
  // 1. Try traditional detection (fast, offline)
  const traditional = await traditionalDetector.detect(repo);
  if (traditional.confidence > 0.8) return traditional;
  
  // 2. Use Claude SDK for complex cases
  const claude = await claudeDetector.detect(repo);
  
  // 3. Cache results
  await cache.set(repo, claude);
  
  return claude;
}
```

### 3. Context Gathering

The Claude detector would analyze:
- Package files (package.json, requirements.txt, Gemfile, etc.)
- Configuration files (pytest.ini, jest.config.js, etc.)
- CI/CD files (.github/workflows/*, etc.)
- Test file patterns and imports
- README and documentation
- Makefile or script files

### 4. Intelligent Prompting

```typescript
const prompt = `
Analyze this codebase to detect test frameworks:

Files found:
${contextFiles}

Determine:
1. Test framework(s) used
2. How to run tests
3. Required setup
4. File patterns

Consider all languages and frameworks.
`;
```

## Benefits

### 1. **Universal Coverage**
- Works for any language: Python, Ruby, JavaScript, Go, Rust, etc.
- Handles new frameworks without code changes

### 2. **Contextual Understanding**
- Infers from documentation and comments
- Understands monorepos and multi-language projects
- Detects custom test runners and scripts

### 3. **Actionable Output**
- Provides exact test commands
- Includes setup instructions
- Suggests missing dependencies

### 4. **Reduced Maintenance**
- Single implementation for all languages
- No need to update patterns for new frameworks
- Self-improving through usage

## Implementation Plan

### Phase 1: Prototype (1-2 days)
- [ ] Create `ClaudeFrameworkDetector` class
- [ ] Implement context file gathering
- [ ] Design prompt structure
- [ ] Add caching layer

### Phase 2: Integration (2-3 days)
- [ ] Integrate with existing `TestFrameworkDetector`
- [ ] Add fallback logic
- [ ] Implement result caching
- [ ] Add configuration options

### Phase 3: Optimization (1-2 days)
- [ ] Minimize token usage
- [ ] Optimize context selection
- [ ] Add confidence thresholds
- [ ] Implement rate limiting

### Phase 4: Testing (2-3 days)
- [ ] Test with 20+ repositories
- [ ] Compare accuracy vs traditional
- [ ] Measure API costs
- [ ] Document edge cases

## Cost Analysis

- **Per Detection**: ~1000 tokens ≈ $0.003
- **With Caching**: Most repos hit cache
- **Monthly Estimate**: 
  - 1000 unique repos = $3
  - 10,000 unique repos = $30

## Risks and Mitigations

### 1. **API Dependency**
- **Risk**: Requires API connectivity
- **Mitigation**: Fallback to traditional detection

### 2. **Latency**
- **Risk**: Slower than pattern matching
- **Mitigation**: Aggressive caching, parallel requests

### 3. **Cost**
- **Risk**: API usage costs
- **Mitigation**: Cache results, use only when needed

### 4. **Accuracy**
- **Risk**: AI hallucination
- **Mitigation**: Validate against known patterns

## Alternative Approaches

### 1. **Expand Traditional Patterns**
- Pro: No API dependency
- Con: Endless maintenance

### 2. **Community Database**
- Pro: Crowdsourced patterns
- Con: Requires infrastructure

### 3. **Static Analysis**
- Pro: Deterministic
- Con: Complex implementation per language

## Success Metrics

1. **Coverage**: Detect 95%+ of frameworks across all languages
2. **Accuracy**: 90%+ correct test commands
3. **Performance**: <2s with cache, <5s without
4. **Cost**: <$50/month for typical usage

## Example Usage

```typescript
const detector = new UniversalTestFrameworkDetector({
  provider: 'claude',
  apiKey: process.env.CLAUDE_API_KEY,
  cache: true,
  fallback: 'traditional'
});

const result = await detector.detect('./my-project');
console.log(`Run tests with: ${result.testCommand}`);
// Output: "Run tests with: pytest --cov=src tests/"
```

## Conclusion

Universal test framework detection via Claude Code SDK would significantly improve RSOLV's ability to generate appropriate tests across all languages and frameworks, while reducing maintenance burden and improving accuracy.

The hybrid approach ensures we maintain fast, offline detection for common cases while leveraging AI for complex scenarios.