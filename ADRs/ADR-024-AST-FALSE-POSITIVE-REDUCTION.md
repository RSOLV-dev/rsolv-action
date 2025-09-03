# ADR-012: AST False Positive Reduction Strategy

## Status
Proposed (2025-08-14)

## Context
Our current AST validation reduces false positives by 45% in the SCAN phase, but we still see 50% of validated issues having 0 specific vulnerabilities in the VALIDATE phase. Analysis of NodeGoat demo results reveals specific patterns of false positives that can be addressed.

## Current False Positive Patterns

### 1. Vendor Library False Positives
- **Example**: Information disclosure timing attacks in bootstrap.js, morris charts
- **Pattern**: `e.code === DOMException.QUOTA_EXCEEDED_ERR`
- **Issue**: Flagging normal JavaScript comparisons as timing attack vulnerabilities
- **Files**: `/vendor/`, `/node_modules/`, `*.min.js`

### 2. Test File False Positives  
- **Example**: Issue #241 in test files
- **Pattern**: Intentionally vulnerable code for testing
- **Issue**: Test files contain patterns that look vulnerable but are for testing
- **Files**: `/test/`, `/spec/`, `*.test.js`, `*.spec.js`

### 3. Context-Blind Detection
- **Current Gap**: No understanding of:
  - File path context (vendor vs application code)
  - Code reachability from user input
  - Framework-specific safe patterns
  - Presence of nearby sanitization

## Decision

Implement a multi-layered AST enhancement strategy with prioritized rollout:

### Phase 1: Quick Wins (1-2 days)
1. **File Path Intelligence**
   - Filter vendor directories: `/vendor/`, `/node_modules/`, `/bower_components/`
   - Filter test directories: `/test/`, `/tests/`, `/spec/`, `/__tests__/`
   - Filter minified files: `*.min.js`
   - Expected impact: 30% reduction in false positives

2. **Safe Pattern Recognition**
   - Constant comparisons: `=== CONSTANT_NAME`
   - Framework safe patterns: parameterized queries, template auto-escaping
   - Expected impact: 10% reduction in false positives

### Phase 2: Enhanced Analysis (3-5 days)
3. **Multi-Level Taint Analysis**
   - Direct user input detection (high confidence)
   - Variable name analysis (medium confidence)
   - Data flow backward tracing (variable confidence)
   - Expected impact: 20% better accuracy in validation

4. **Smart Caching System**
   - Cache parsed ASTs by file hash
   - Cache pattern results by file
   - Cache directory classifications
   - Expected impact: 3-5x performance improvement

### Phase 3: Advanced Features (1-2 weeks)
5. **Control Flow Analysis**
   - Determine code reachability from entry points
   - Track data flow through function calls
   - Build dependency graphs
   - Expected impact: 40% reduction in remaining false positives

## Implementation Details

### File Path Filter (Immediate Implementation)
```elixir
defp filter_by_file_path(vulnerabilities) do
  Enum.reject(vulnerabilities, fn vuln ->
    is_vendor_or_test_file?(vuln["filePath"])
  end)
end

defp is_vendor_or_test_file?(file_path) do
  patterns = [
    ~r|/vendor/|, ~r|/node_modules/|, ~r|/bower_components/|,
    ~r|/test/|, ~r|/tests/|, ~r|/spec/|,
    ~r|\.min\.js$|
  ]
  Enum.any?(patterns, &Regex.match?(&1, file_path))
end
```

### Enhanced Validation Response
```elixir
%{
  "id" => vuln["id"],
  "isValid" => is_valid,
  "confidence" => confidence,
  "reason" => reason,
  "astContext" => %{
    "inUserInputFlow" => taint_analysis.direct_input,
    "hasValidation" => has_sanitization,
    "isVendorCode" => is_vendor,
    "isTestCode" => is_test,
    "reachableFromEntry" => is_reachable
  }
}
```

## Validation Against NodeGoat

NodeGoat has 5 documented vulnerability categories:
1. **A1-1**: Server Side JS Injection (eval, setTimeout)
2. **A1-2**: SQL/NoSQL Injection ($where operator)
3. **A1-3**: Log Injection
4. **A2-1**: Session Management
5. **A2-2**: Password Guessing

Our enhanced AST should correctly identify these while filtering false positives.

## Consequences

### Positive
- **Immediate Impact**: 30-40% reduction in false positives with minimal effort
- **Better UX**: Users see fewer irrelevant issues
- **Performance**: Smarter caching reduces API load
- **Confidence**: Multi-level scoring provides nuanced results
- **Demo Quality**: NodeGoat demo shows accurate vulnerability detection

### Negative
- **Complexity**: More sophisticated analysis requires more code
- **Maintenance**: Need to update patterns for new frameworks
- **Testing**: Requires comprehensive test suite for each enhancement
- **False Negatives**: Risk of filtering real issues if patterns too aggressive

## Metrics for Success

### Current State
- SCAN Phase: 45% false positive reduction
- VALIDATE Phase: 50% show 0 vulnerabilities
- Performance: ~1 second per vulnerability validation

### Target State (After Implementation)
- SCAN Phase: 70% false positive reduction
- VALIDATE Phase: <20% show 0 vulnerabilities
- Performance: <500ms per vulnerability with caching
- NodeGoat: 100% detection of documented vulnerabilities

## References
- RFC-036: Server-Side AST Validation
- RFC-041: Three-Phase Architecture
- ADR-011: Three-Phase Security Architecture
- NodeGoat Documentation: https://github.com/OWASP/NodeGoat