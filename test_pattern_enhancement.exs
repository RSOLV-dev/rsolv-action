# Test pattern enhancement flow
alias RsolvApi.Security.{Pattern, PatternRegistry}
alias RsolvApi.AST.PatternAdapter

# Get the Python SQL injection pattern
patterns = PatternRegistry.get_patterns_for_language("python")
sql_pattern = Enum.find(patterns, fn p -> String.contains?(p.id || "", "sql") end)

if sql_pattern do
  IO.puts("Found SQL pattern: #{sql_pattern.id}")
  IO.puts("Pattern type: #{sql_pattern.type}")
  IO.puts("Pattern struct: #{inspect(sql_pattern.__struct__)}")
  
  # Try to enhance it
  enhanced = PatternAdapter.enhance_pattern(sql_pattern)
  IO.puts("\nEnhanced pattern struct: #{inspect(enhanced.__struct__)}")
  IO.puts("Has ast_rules? #{not is_nil(Map.get(enhanced, :ast_rules))}")
  
  if enhanced.ast_rules do
    IO.puts("AST rules: #{inspect(enhanced.ast_rules)}")
  end
  
  # Try to convert to matcher format
  matcher_format = PatternAdapter.convert_to_matcher_format(enhanced)
  IO.puts("\nMatcher format keys: #{inspect(Map.keys(matcher_format))}")
  IO.puts("Has ast_pattern? #{not is_nil(matcher_format[:ast_pattern])}")
  
  if matcher_format[:ast_pattern] do
    IO.puts("AST pattern: #{inspect(matcher_format[:ast_pattern])}")
  end
else
  IO.puts("No SQL pattern found")
end
EOF < /dev/null