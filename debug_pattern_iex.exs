# TDD GREEN Phase: Pattern Debug in IEx
# Run with: docker-compose exec rsolv-api iex -S mix run debug_pattern_iex.exs

IO.puts("🟢 TDD GREEN Phase: Pattern Structure Analysis")
IO.puts("=" |> String.duplicate(50))

# Get Python patterns
patterns = RsolvApi.Security.PatternRegistry.get_patterns_for_language("python")
IO.puts("Python patterns loaded: #{length(patterns)}")

# Find SQL injection patterns
sql_patterns = Enum.filter(patterns, fn p ->
  String.contains?(String.downcase(p.name || ""), "sql")
end)

IO.puts("SQL-related patterns: #{length(sql_patterns)}")

if length(sql_patterns) > 0 do
  pattern = hd(sql_patterns)
  IO.puts("\n🔍 First SQL Pattern:")
  IO.puts("ID: #{pattern.id}")
  IO.puts("Name: #{pattern.name}")
  IO.puts("\nAST Rules:")
  IO.inspect(pattern.ast_rules, pretty: true, limit: :infinity)
  
  if pattern.context_rules do
    IO.puts("\nContext Rules:")
    IO.inspect(pattern.context_rules, pretty: true, limit: :infinity)
  end
end

# Test AST matching with actual pattern
IO.puts("\n🧪 Testing AST Matching:")

test_ast = %{
  "type" => "BinOp",
  "op" => %{"type" => "Add"},
  "left" => %{
    "type" => "Constant",
    "value" => "SELECT * FROM users WHERE id = "
  },
  "right" => %{
    "type" => "Name",
    "id" => "user_id"
  }
}

IO.puts("Test AST:")
IO.inspect(test_ast, pretty: true, limit: 3)

# Now test the matcher
alias RsolvApi.AST.ASTPatternMatcher

# Create a simple file analysis result
file_result = %{
  id: "test-file",
  path: "test.py",
  language: "python",
  ast: [test_ast]
}

# Try to match patterns
IO.puts("\n🔍 Running pattern matcher...")
try do
  matches = ASTPatternMatcher.match_patterns(file_result, patterns)
  IO.puts("Matches found: #{length(matches)}")
  
  if length(matches) > 0 do
    IO.puts("\n✅ SUCCESS! Found matches:")
    Enum.each(matches, fn match ->
      IO.puts("  - Pattern: #{match.pattern_id}")
      IO.puts("    Confidence: #{match.confidence}")
    end)
  else
    IO.puts("\n❌ No matches found. Debugging why...")
    
    # Let's manually check the first SQL pattern
    if length(sql_patterns) > 0 do
      pattern = hd(sql_patterns)
      IO.puts("\nChecking pattern: #{pattern.id}")
      IO.puts("Pattern expects:")
      IO.puts("  - node_type: #{inspect(pattern.ast_rules[:node_type])}")
      IO.puts("  - op: #{inspect(pattern.ast_rules[:op])}")
      IO.puts("AST provides:")
      IO.puts("  - type: #{inspect(test_ast["type"])}")
      IO.puts("  - op: #{inspect(test_ast["op"])}")
    end
  end
rescue
  error ->
    IO.puts("❌ Error during matching: #{inspect(error)}")
    IO.puts(Exception.format(:error, error, __STACKTRACE__))
end