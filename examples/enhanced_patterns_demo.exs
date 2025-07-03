#!/usr/bin/env elixir

# Demo script showing how to use enhanced patterns with AST rules
# Run with: elixir examples/enhanced_patterns_demo.exs

# Ensure we're in the right directory
File.cd!("/Users/dylan/dev/rsolv/RSOLV-api")

# Load the application
Mix.install([
  {:jason, "~> 1.4"}
])

# Require our modules
Code.require_file("lib/rsolv_api/security/pattern.ex")
Code.require_file("lib/rsolv_api/security/enhanced_pattern.ex")
Code.require_file("lib/rsolv_api/security/patterns/javascript_enhanced.ex")

alias Rsolv.Security.EnhancedPattern
alias Rsolv.Security.Patterns.JavascriptEnhanced

IO.puts("=== Enhanced Pattern Demo ===\n")

# Get the enhanced SQL injection pattern
sql_pattern = JavascriptEnhanced.sql_injection_enhanced()

IO.puts("Pattern: #{sql_pattern.name}")
IO.puts("ID: #{sql_pattern.id}")
IO.puts("Severity: #{sql_pattern.severity}")
IO.puts("\nDescription: #{sql_pattern.description}")

# Show AST rules
IO.puts("\n--- AST Rules ---")
Enum.each(sql_pattern.ast_rules, fn rule ->
  IO.puts("Node Type: #{rule.node_type}")
  IO.puts("Properties: #{inspect(rule.properties, pretty: true)}")
  IO.puts("")
end)

# Show context rules
IO.puts("--- Context Rules ---")
IO.puts("Exclude Paths: #{inspect(sql_pattern.context_rules.exclude_paths)}")
IO.puts("Exclude If Contains: #{inspect(sql_pattern.context_rules.exclude_if_contains)}")

# Show confidence scoring
IO.puts("\n--- Confidence Scoring ---")
IO.puts("Base Confidence: #{sql_pattern.confidence_rules.base_confidence}")
IO.puts("Increase Conditions:")
Enum.each(sql_pattern.confidence_rules.increase_if, fn rule ->
  IO.puts("  - #{rule.description}: +#{rule.amount}")
end)
IO.puts("Decrease Conditions:")
Enum.each(sql_pattern.confidence_rules.decrease_if, fn rule ->
  IO.puts("  - #{rule.description}: -#{rule.amount}")
end)

# Show enhanced recommendations
IO.puts("\n--- Enhanced Recommendations ---")
IO.puts("Quick Fix: #{sql_pattern.enhanced_recommendation.quick_fix}")
IO.puts("\nDetailed Steps:")
Enum.each(sql_pattern.enhanced_recommendation.detailed_steps, fn step ->
  IO.puts("  #{step}")
end)

# Convert to API format
IO.puts("\n--- API Format ---")
api_format = EnhancedPattern.to_enhanced_api_format(sql_pattern)
IO.puts("Supports AST: #{api_format[:supports_ast]}")
IO.puts("Total Test Cases: #{length(api_format[:examples][:vulnerable]) + length(api_format[:examples][:safe])}")

# Show example vulnerable code
IO.puts("\n--- Example Vulnerable Code ---")
Enum.take(sql_pattern.test_cases.vulnerable, 2) |> Enum.each(fn example ->
  IO.puts("  #{example}")
end)

IO.puts("\n--- Example Safe Code ---")
Enum.take(sql_pattern.test_cases.safe, 2) |> Enum.each(fn example ->
  IO.puts("  #{example}")
end)

# Demonstrate missing error logging pattern
IO.puts("\n\n=== Missing Error Logging Pattern ===\n")

logging_pattern = JavascriptEnhanced.missing_error_logging_enhanced()
IO.puts("Pattern: #{logging_pattern.name}")
IO.puts("Severity: #{logging_pattern.severity}")

IO.puts("\n--- AST Rules for Error Detection ---")
Enum.each(logging_pattern.ast_rules, fn rule ->
  case rule.node_type do
    :try_statement ->
      IO.puts("• Detects try-catch blocks without logging")
    :call_expression ->
      IO.puts("• Detects promise .catch() handlers without logging")
    _ ->
      IO.puts("• Detects #{rule.node_type} patterns")
  end
end)

# Show metadata
IO.puts("\n--- Pattern Metadata ---")
IO.puts("Last Updated: #{logging_pattern.metadata["last_updated"]}")
IO.puts("Tags: #{inspect(logging_pattern.metadata["tags"])}")

IO.puts("\n=== Demo Complete ===")

# Sample output showing how AST patterns would be used by a scanner
IO.puts("\n--- How AST Scanner Would Use These Patterns ---")
IO.puts("""
1. Parse JavaScript code into AST using a parser (e.g., Babel, Esprima)
2. For each AST node, check if it matches any pattern's node_type
3. If matched, validate the node properties against the pattern
4. Apply context rules to filter out false positives
5. Calculate confidence score based on surrounding code
6. Generate findings with enhanced recommendations
""")

# Example API endpoint usage
IO.puts("--- Example API Usage ---")
IO.puts("""
# Get enhanced patterns for JavaScript
curl -H "Authorization: Bearer YOUR_API_KEY" \\
  https://api.rsolv.dev/api/v1/patterns/enhanced/javascript

# Response includes AST rules for precise detection:
{
  "patterns": [
    {
      "id": "js-sql-injection-enhanced",
      "supports_ast": true,
      "ast_rules": [...],
      "context_rules": {...},
      "confidence_rules": {...}
    }
  ],
  "format": "enhanced",
  "enhanced_count": 2
}
""")

IO.puts("\n✅ Enhanced patterns ready for AST-based security scanning!")