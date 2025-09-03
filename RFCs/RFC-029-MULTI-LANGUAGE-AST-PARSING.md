# RFC-029: Multi-Language AST Parsing Architecture

**Status**: Implemented  
**Created**: 2025-06-12  
**Author**: RSOLV Team

## Summary

Implement language-specific AST parsers to enable precise vulnerability detection across all supported languages, addressing the current limitation where AST-based pattern matching only works for JavaScript/TypeScript.

## Problem Statement

During Phase 6C validation, we discovered that RSOLV-action's AST pattern interpreter only supports JavaScript/TypeScript because it uses Babel parser exclusively. This causes:

1. **Zero detection rate** for Java/PHP vulnerabilities in real-world applications (WebGoat, DVWA)
2. **Fallback to regex-only detection** which misses vulnerabilities due to overly narrow patterns
3. **Loss of precision** - AST rules designed to reduce false positives cannot be applied
4. **Inconsistent detection quality** across languages

### Current Architecture Limitation

```typescript
// ast-pattern-interpreter.ts
ast = parse(content, {
  sourceType: 'module',
  plugins: ['jsx', 'typescript'],  // Only JS/TS support
  errorRecovery: true
});
```

When parsing fails for non-JS languages, the system falls back to regex-only detection, but the regex patterns were designed to work WITH AST filtering, making them too specific to catch real vulnerabilities.

## Proposed Solution

Implement a multi-language AST parsing system that uses language-specific parsers:

### 1. Parser Registry Architecture

```typescript
interface LanguageParser {
  canParse(filePath: string, content: string): boolean;
  parse(content: string, options?: ParseOptions): AST;
  traverse(ast: AST, visitor: ASTVisitor): void;
  getNodeType(node: ASTNode): string;
}

class ParserRegistry {
  private parsers: Map<string, LanguageParser> = new Map();
  
  register(language: string, parser: LanguageParser): void {
    this.parsers.set(language, parser);
  }
  
  getParser(language: string): LanguageParser | null {
    return this.parsers.get(language) || null;
  }
}
```

### 2. Language-Specific Implementations

#### JavaScript/TypeScript (existing)
- **Parser**: Babel
- **Status**: ✅ Already implemented
- **Coverage**: ES6+, JSX, TypeScript, Flow

#### Java
- **Parser**: [java-parser](https://github.com/jhipster/prettier-java)
- **Features**: Full Java 8-17 support, annotations, generics
- **AST Format**: Similar to Eclipse JDT

#### PHP
- **Parser**: [php-parser](https://github.com/nikic/PHP-Parser)
- **Features**: PHP 5.2 - 8.3, attributes, typed properties
- **AST Format**: Node-based with visitors

#### Python
- **Parser**: Native `ast` module
- **Features**: Python 2.7 - 3.12, type hints, async/await
- **AST Format**: Standard Python AST

#### Ruby
- **Parser**: [parser](https://github.com/whitequark/parser) gem
- **Features**: Ruby 1.8 - 3.3, pattern matching, endless methods
- **AST Format**: S-expression based

#### Elixir
- **Parser**: Native metaprogramming via `Code.string_to_quoted/1`
- **Features**: Full Elixir syntax, macros, protocols
- **AST Format**: Elixir AST (3-tuple format)
- **Example**:
  ```elixir
  {:ok, ast} = Code.string_to_quoted(source_code)
  # AST format: {atom, metadata, arguments}
  ```

#### Go
- **Parser**: Native `go/parser` package
- **Features**: Full Go syntax, generics (1.18+)
- **AST Format**: go/ast nodes

#### Rust
- **Parser**: [syn](https://github.com/dtolnay/syn)
- **Features**: Full Rust syntax, macros, async
- **AST Format**: syn AST types

### 3. Unified AST Visitor Pattern

Create a unified visitor pattern that works across different AST formats:

```typescript
interface UnifiedASTVisitor {
  visitFunctionCall(node: FunctionCallNode, context: VisitorContext): void;
  visitStringConcatenation(node: ConcatNode, context: VisitorContext): void;
  visitVariableAssignment(node: AssignmentNode, context: VisitorContext): void;
  visitConditional(node: ConditionalNode, context: VisitorContext): void;
  // ... other common patterns
}

// Language-specific adapters translate native AST to unified format
class JavaASTAdapter implements LanguageParser {
  traverse(ast: JavaAST, visitor: UnifiedASTVisitor): void {
    // Translate Java AST nodes to unified visitor calls
  }
}
```

### 4. Pattern Rule Enhancement

Enhance pattern rules to be language-aware:

```typescript
interface ASTRule {
  nodeType: string;
  languages: string[];  // Languages this rule applies to
  
  // Language-specific matchers
  matchers: {
    javascript?: (node: any) => boolean;
    java?: (node: any) => boolean;
    php?: (node: any) => boolean;
    // ...
  };
}
```

## Implementation Plan

### Phase 1: Core Architecture (2 weeks)
1. Design and implement ParserRegistry
2. Create UnifiedASTVisitor interface
3. Update AST pattern interpreter to use registry
4. Add language detection logic

### Phase 2: Priority Languages (4 weeks)
1. **Java** - Critical for enterprise (WebGoat validation failed)
2. **PHP** - High usage, DVWA validation failed
3. **Python** - Growing security concerns
4. **Ruby** - Rails applications

### Phase 3: Additional Languages (3 weeks)
1. **Elixir** - Native AST support makes it straightforward
2. **Go** - Increasing adoption
3. **Rust** - Security-critical applications
4. **C#** - Enterprise Windows applications

### Phase 4: Testing & Optimization (2 weeks)
1. Comprehensive test suite for each parser
2. Performance optimization
3. Memory usage profiling
4. Integration testing with real vulnerabilities

## Benefits

1. **Accurate Detection**: AST-based detection for all languages, not just JS/TS
2. **Reduced False Positives**: Context-aware analysis instead of broad regex
3. **Consistent Quality**: Same detection precision across all languages
4. **Future-Proof**: Easy to add new languages
5. **Better Fix Suggestions**: Understanding code structure enables better fixes

## Drawbacks

1. **Increased Complexity**: Multiple parsers to maintain
2. **Larger Bundle Size**: Each parser adds dependencies
3. **Performance Overhead**: Parsing is computationally expensive
4. **Version Compatibility**: Need to track language version changes

## Alternatives Considered

1. **Regex-Only Approach**: Simpler but too many false positives
2. **Universal Parser**: No single parser handles all languages well
3. **External Service**: Latency and security concerns
4. **Tree-sitter**: Promising but lacks semantic understanding

## Migration Strategy

1. **Gradual Rollout**: Enable per-language as parsers are ready
2. **Fallback Mechanism**: Continue using regex when parser unavailable
3. **A/B Testing**: Compare detection rates between approaches
4. **Monitoring**: Track parser performance and accuracy

## Success Metrics

1. **Detection Rate**: >90% of known vulnerabilities detected
2. **False Positive Rate**: <10% false positives
3. **Performance**: <2s parsing for average file
4. **Coverage**: All major languages supported within 6 months

## Security Considerations

1. **Parser Vulnerabilities**: Regular updates for parser dependencies
2. **Resource Limits**: Prevent DoS via complex files
3. **Sandboxing**: Run parsers in isolated environments
4. **Input Validation**: Sanitize code before parsing

## Open Questions

1. Should we support language version detection?
2. How to handle mixed-language files (e.g., PHP + HTML)?
3. Should parsers run in Web Workers for performance?
4. What's the strategy for parser version updates?

## References

- [WebGoat Phase 6C Validation Results](../TEST-GENERATION-METHODOLOGY.md#phase-6c-critical-discovery)
- [Pattern Detection Analysis](../PATTERN-DETECTION-ANALYSIS.md)
- [AST Pattern Interpreter Source](../src/security/ast-pattern-interpreter.ts)
- Language Parser Projects:
  - [Java Parser](https://github.com/jhipster/prettier-java)
  - [PHP Parser](https://github.com/nikic/PHP-Parser)
  - [Ruby Parser](https://github.com/whitequark/parser)
  - [Elixir AST Docs](https://hexdocs.pm/elixir/Code.html#string_to_quoted/2)