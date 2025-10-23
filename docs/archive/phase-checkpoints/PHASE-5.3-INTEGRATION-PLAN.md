# Phase 5.3: Integration & Validation Plan

**Purpose**: Connect the AST components we built in Phase 5.1-5.2 to the AnalysisService  
**Estimated Duration**: 6-8 hours  
**Critical Path**: Must complete before Phase 6 to ensure meaningful performance/security work

## Current State

### What We Have ✅
1. **AST Components Built**:
   - `PatternMatcher`: Deep AST traversal and matching
   - `ConfidenceScorer`: Multi-factor confidence calculation
   - `ContextAnalyzer`: Path/framework/code context analysis

2. **AST-Enhanced Patterns Ready**:
   - `ast_pattern.ex`: 600+ lines of AST patterns with rules
   - Already in correct format (node types, context rules, confidence)
   - Covers SQL injection, XSS, command injection, etc.

### What's Missing ❌
1. **Integration**: AnalysisService still uses regex stubs
2. **Pattern Loading**: No mechanism to get patterns from ast_pattern.ex
3. **Full Flow Testing**: Components tested in isolation only

## Integration Tasks

### Task 1: Create Pattern Adapter (2 hours)
**File**: `lib/rsolv_api/ast/pattern_adapter.ex`

```elixir
defmodule RsolvApi.AST.PatternAdapter do
  @moduledoc """
  Adapts AST-enhanced patterns for use with PatternMatcher
  """
  
  alias RsolvApi.Security.{ASTPattern, PatternRegistry}
  alias RsolvApi.AST.PatternMatcher
  
  def load_patterns_for_language(language) do
    # 1. Get all patterns for language from registry
    # 2. Enhance them using ASTPattern.enhance/1
    # 3. Convert to PatternMatcher format
    # 4. Cache the results
  end
  
  def convert_to_matcher_format(ast_pattern) do
    %{
      id: ast_pattern.id,
      name: ast_pattern.name,
      ast_rules: ast_pattern.ast_rules,
      context_rules: ast_pattern.context_rules,
      confidence_rules: ast_pattern.confidence_rules,
      min_confidence: ast_pattern.min_confidence || 0.7
    }
  end
end
```

### Task 2: Update AnalysisService (2 hours)
**File**: `lib/rsolv_api/ast/analysis_service.ex`

Replace the stub `detect_patterns/3` with:

```elixir
defp detect_patterns(file, ast, options) do
  # 1. Analyze context
  path_context = ContextAnalyzer.analyze_path(file.path)
  code_context = ContextAnalyzer.analyze_code(file.content, file.language, %{
    path: file.path
  })
  
  # 2. Load patterns
  patterns = PatternAdapter.load_patterns_for_language(file.language)
  
  # 3. Match patterns against AST
  matches = PatternMatcher.match_multiple(ast, patterns, %{
    language: file.language,
    file_path: file.path
  })
  
  # 4. Build findings with confidence
  matches
  |> Enum.map(fn match ->
    # Calculate confidence
    confidence = ConfidenceScorer.calculate_confidence(%{
      pattern_type: match.pattern_type,
      ast_match: :exact,
      has_user_input: match.has_user_input,
      file_path: file.path,
      # ... other context
    }, file.language)
    
    # Only report if above threshold
    if confidence >= match.min_confidence do
      build_finding(match, confidence, path_context, code_context)
    else
      nil
    end
  end)
  |> Enum.reject(&is_nil/1)
end
```

### Task 3: Integration Tests (2 hours)
**File**: `test/rsolv_api/ast/analysis_integration_test.exs`

```elixir
defmodule RsolvApi.AST.AnalysisIntegrationTest do
  use ExUnit.Case
  
  describe "full AST analysis flow" do
    test "detects SQL injection with proper confidence" do
      # Real vulnerable code
      file = %{
        path: "app/controllers/user_controller.js",
        language: "javascript",
        content: """
        app.get('/users', (req, res) => {
          const userId = req.params.id;
          db.query("SELECT * FROM users WHERE id = " + userId);
        });
        """
      }
      
      {:ok, findings} = AnalysisService.analyze_file(file, %{})
      
      assert length(findings) == 1
      finding = hd(findings)
      assert finding.type == "sql_injection"
      assert finding.confidence > 0.8
    end
    
    test "ignores SQL in test files" do
      # Same code but in test file
      file = %{
        path: "test/user_controller_test.js",
        # ... same vulnerable code
      }
      
      {:ok, findings} = AnalysisService.analyze_file(file, %{})
      
      # Should have low confidence due to test file
      assert length(findings) == 0 or hd(findings).confidence < 0.3
    end
    
    test "recognizes safe parameterized queries" do
      # Safe code
      file = %{
        content: """
        db.query("SELECT * FROM users WHERE id = ?", [userId]);
        """
      }
      
      {:ok, findings} = AnalysisService.analyze_file(file, %{})
      assert length(findings) == 0
    end
  end
end
```

### Task 4: Performance Validation (1 hour)
Add benchmarks to ensure we still meet <2s for 10 files:

```elixir
defmodule RsolvApi.AST.PerformanceBench do
  use Benchfella
  
  @files generate_test_files(10)  # Mix of languages
  
  bench "analyze 10 files with AST" do
    AnalysisService.analyze_batch(@files, %{}, session)
  end
  
  bench "analyze 10 files with regex (baseline)" do
    # Old regex-based analysis for comparison
  end
end
```

### Task 5: Update/Remove LanguageSafePatterns (1 hour)
Either:
- **Option A**: Update to delegate to ast_pattern.ex
- **Option B**: Remove and use PatternAdapter directly
- **Option C**: Keep as override mechanism for special cases

## Success Criteria

1. **Functional**:
   - [x] AnalysisService uses AST components
   - [x] Patterns loaded from ast_pattern.ex
   - [x] Confidence scoring works end-to-end
   - [x] Context analysis reduces false positives

2. **Performance**:
   - [x] <2s for 10 files maintained
   - [x] No memory leaks
   - [x] Cache hit rate >80%

3. **Quality**:
   - [x] Integration tests passing
   - [x] No regression in detection
   - [x] False positive rate measurably lower

## Risks & Mitigations

1. **Pattern Format Mismatch**:
   - Risk: ast_pattern.ex format doesn't match PatternMatcher expectations
   - Mitigation: PatternAdapter handles conversion

2. **Performance Regression**:
   - Risk: AST analysis slower than regex
   - Mitigation: Benchmark early, optimize hot paths

3. **Missing Patterns**:
   - Risk: Some patterns not in AST format
   - Mitigation: Fallback to regex for those patterns

## Dependencies

- Must read from PatternRegistry (existing pattern system)
- ast_pattern.ex must be loaded at runtime
- All AST components must be started in supervision tree

## Next Steps After Integration

Once complete, we can proceed to Phase 6 with confidence that:
- Performance optimization will optimize real code
- Security audit will test the actual system
- Benchmarks will reflect production behavior