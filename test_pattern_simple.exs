# Simple test to check pattern structure
IO.puts("🔍 Testing Pattern Enhancement")
IO.puts("=" <> String.duplicate("=", 60))

# Try to create a simple pattern and enhance it
defmodule TestPattern do
  def test_sql_pattern do
    %RsolvApi.Security.Pattern{
      id: "python-sql-injection-concat",
      name: "SQL Injection via String Concatenation",
      type: :sql_injection,
      severity: :high,
      languages: ["python"],
      regex: ~r/concat/,
      description: "Test pattern",
      cwe_id: "CWE-89",
      owasp_category: "A03:2021",
      recommendation: "Use parameterized queries",
      test_cases: %{
        vulnerable: ["cursor.execute('SELECT * FROM users WHERE id = ' + user_id)"],
        safe: ["cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))"]
      }
    }
  end
end

# Test AST pattern enhance
pattern = TestPattern.test_sql_pattern()
IO.puts("\nOriginal pattern type: #{pattern.type}")

# Try using ASTPattern.enhance directly
try do
  enhanced = RsolvApi.Security.ASTPattern.enhance(pattern)
  IO.puts("Enhanced pattern struct: #{inspect(enhanced.__struct__)}")
  IO.puts("Has ast_rules? #{not is_nil(Map.get(enhanced, :ast_rules))}")
  
  if enhanced.ast_rules do
    IO.puts("\nAST rules:")
    IO.inspect(enhanced.ast_rules, pretty: true)
  end
  
  # Now test PatternAdapter conversion
  IO.puts("\n--- Testing PatternAdapter Conversion ---")
  
  # Method 1: Direct conversion of enhanced pattern
  matcher_format = RsolvApi.AST.PatternAdapter.convert_to_matcher_format(enhanced)
  IO.puts("Matcher format keys: #{inspect(Map.keys(matcher_format))}")
  IO.puts("Has ast_pattern? #{not is_nil(matcher_format[:ast_pattern])}")
  
  if matcher_format[:ast_pattern] do
    IO.puts("\nAST pattern generated:")
    IO.inspect(matcher_format[:ast_pattern], pretty: true)
  end
  
  # Method 2: Load patterns through adapter
  IO.puts("\n--- Testing Full Pattern Loading ---")
  patterns = RsolvApi.AST.PatternAdapter.load_patterns_for_language("python")
  IO.puts("Loaded #{length(patterns)} patterns")
  
  sql_pattern = Enum.find(patterns, fn p -> String.contains?(p.id || "", "sql") end)
  if sql_pattern do
    IO.puts("Found SQL pattern in loaded patterns")
    IO.puts("Has ast_pattern? #{not is_nil(sql_pattern[:ast_pattern])}")
  end
rescue
  e ->
    IO.puts("Error: #{Exception.message(e)}")
    IO.puts("Stack trace:")
    IO.inspect(__STACKTRACE__, pretty: true)
end