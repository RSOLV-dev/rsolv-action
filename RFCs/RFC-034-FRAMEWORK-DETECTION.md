# RFC-034: Framework Detection for Enhanced Pattern Context

**Status**: Draft  
**Created**: 2025-06-29  
**Author**: RSOLV Team

## Summary

Implement framework detection in RSOLV-action to enable framework-specific vulnerability analysis and reduce false positives through context-aware pattern matching.

## Motivation

Enhanced patterns include framework-specific rules that cannot be applied without knowing which frameworks are in use:

1. **React XSS patterns** need to know if React is present
2. **Express.js patterns** require Express detection
3. **Vue.js patterns** need Vue-specific context
4. **Rails patterns** require Ruby on Rails detection

Without framework detection, we either:
- Miss framework-specific vulnerabilities (false negatives)
- Flag safe framework idioms as vulnerabilities (false positives)

## Proposed Solution

### 1. Package Manifest Analysis
```typescript
interface FrameworkDetector {
  detectFromPackageJson(content: string): Framework[];
  detectFromGemfile(content: string): Framework[];
  detectFromRequirementsTxt(content: string): Framework[];
  detectFromPomXml(content: string): Framework[];
}
```

### 2. Import/Require Analysis
```typescript
// Detect from code imports
detectFromImports(fileContent: string, language: string): Framework[] {
  // React: import React from 'react'
  // Vue: import Vue from 'vue'
  // Express: const express = require('express')
}
```

### 3. File Structure Heuristics
```typescript
// Detect from project structure
detectFromStructure(files: string[]): Framework[] {
  // Next.js: pages/ directory
  // Rails: app/controllers, app/models
  // Django: manage.py, settings.py
}
```

### 4. Integration with Pattern Matching
```typescript
interface EnhancedPatternContext {
  frameworks: Framework[];
  applyFrameworkRules: boolean;
}

// In pattern matcher
if (context.frameworks.includes('react') && pattern.framework === 'react') {
  // Apply React-specific rules
}
```

## Implementation Plan

### Phase 1: Core Detection (Week 1)
- Package.json parser for Node.js frameworks
- Gemfile parser for Ruby frameworks
- Basic import detection

### Phase 2: Advanced Detection (Week 2)
- File structure analysis
- Framework version detection
- Confidence scoring for detection

### Phase 3: Pattern Integration (Week 3)
- Update AST interpreter to use framework context
- Test false positive reduction
- Performance optimization

## Alternatives Considered

1. **User-Specified Frameworks**: Require users to specify frameworks
   - Pro: Simple, accurate
   - Con: Extra configuration burden

2. **Runtime Detection**: Detect at scan time from running process
   - Pro: Most accurate
   - Con: Requires runtime access, security concerns

3. **ML-Based Detection**: Train model to detect frameworks
   - Pro: Could handle edge cases
   - Con: Complexity, training data needs

## Success Metrics

1. **Detection Accuracy**: >95% framework detection rate
2. **False Positive Reduction**: 20-30% reduction in framework-specific patterns
3. **Performance Impact**: <100ms added to scan time
4. **Framework Coverage**: Top 20 frameworks supported

## Security Considerations

- Don't execute code to detect frameworks
- Handle malformed package files gracefully
- Avoid exposing framework versions unnecessarily

## Open Questions

1. Should we cache framework detection results?
2. How to handle monorepos with multiple frameworks?
3. Should framework detection be optional or mandatory?
4. How to handle custom/internal frameworks?

## References

- Enhanced pattern examples showing framework-specific rules
- Common framework detection patterns
- Similar tools: npm audit, bundler-audit, safety