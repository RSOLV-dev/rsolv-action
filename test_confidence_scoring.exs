#!/usr/bin/env elixir

# Test confidence scoring for SQL injection pattern

alias RsolvApi.AST.{ConfidenceScorer}

# Create confidence context matching what AnalysisService builds
confidence_context = %{
  pattern_type: "sql_injection",
  ast_match: :exact,
  has_user_input: true,
  file_path: "test.js",
  framework_protection: false,
  code_complexity: :high,
  function_name: "test",
  in_database_call: true
}

# Calculate confidence
confidence = ConfidenceScorer.calculate_confidence(
  confidence_context,
  "javascript",
  %{}
)

IO.puts("Confidence score: #{confidence}")
IO.puts("Threshold: 0.7")
IO.puts("Would be reported: #{confidence >= 0.7}")