#!/usr/bin/env elixir

# Test if patterns are being enhanced
# Run with: docker-compose exec rsolv-api elixir test_pattern_enhancement.exs

# Force compile first
IO.puts("Compiling patterns...")
System.shell("cd /app && mix compile --force", stderr_to_stdout: true)

IO.puts("\n🔍 Testing Pattern Enhancement")
IO.puts("=" |> String.duplicate(60))

# Get raw patterns from registry
patterns = RsolvApi.Security.PatternRegistry.get_patterns_for_language("python")
IO.puts("\nPatterns from registry: #{length(patterns)}")

# Find SQL injection pattern
sql_pattern = Enum.find(patterns, fn p ->
  String.contains?(p.id || "", "sql") && String.contains?(p.id || "", "concat")
end)

if sql_pattern do
  IO.puts("\n✅ Found SQL injection pattern:")
  IO.puts("ID: #{sql_pattern.id}")
  IO.puts("Type: #{inspect(sql_pattern.__struct__)}")
  IO.puts("Has regex? #{not is_nil(sql_pattern.regex)}")
  
  # Check if it's already enhanced
  if sql_pattern.__struct__ == RsolvApi.Security.ASTPattern do
    IO.puts("Already enhanced? YES")
    IO.puts("Has ast_rules? #{not is_nil(Map.get(sql_pattern, :ast_rules))}")
  else
    IO.puts("Already enhanced? NO (still a Pattern)")
  end
end

# Now test what PatternAdapter does
IO.puts("\n🔧 Testing PatternAdapter:")
adapter_patterns = RsolvApi.AST.PatternAdapter.load_patterns_for_language("python")
IO.puts("Patterns from adapter: #{length(adapter_patterns)}")

# Find SQL pattern from adapter
adapter_sql = Enum.find(adapter_patterns, fn p ->
  String.contains?(p.id || "", "sql") && String.contains?(p.id || "", "concat") 
end)

if adapter_sql do
  IO.puts("\n✅ Found SQL pattern from adapter:")
  IO.puts("ID: #{adapter_sql.id}")
  IO.puts("Has ast_pattern? #{not is_nil(Map.get(adapter_sql, :ast_pattern))}")
  
  if ast_pattern = Map.get(adapter_sql, :ast_pattern) do
    IO.puts("\nast_pattern structure:")
    IO.inspect(ast_pattern, pretty: true, limit: :infinity)
  else
    IO.puts("\n❌ No ast_pattern field! This is the problem.")
  end
else
  IO.puts("\n❌ SQL pattern not found in adapter output!")
end

IO.puts("\n💡 Summary:")
IO.puts("If ast_pattern is nil, the matcher will skip the pattern")
IO.puts("This explains why we get 0 vulnerabilities")