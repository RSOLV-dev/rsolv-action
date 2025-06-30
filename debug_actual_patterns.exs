#!/usr/bin/env elixir

# Debug actual pattern structure
# Run with: docker-compose exec rsolv-api /bin/sh -c "cd /app && iex -S mix run debug_actual_patterns.exs"

IO.puts("🔍 Debugging Actual Pattern Structure")
IO.puts("=" |> String.duplicate(60))

# Load patterns through the adapter
alias RsolvApi.AST.PatternAdapter
patterns = PatternAdapter.load_patterns_for_language("python")

IO.puts("\nTotal Python patterns loaded: #{length(patterns)}")

# Find SQL injection pattern
sql_pattern = Enum.find(patterns, fn p -> 
  String.contains?(p.id || "", "sql")
end)

if sql_pattern do
  IO.puts("\n✅ Found SQL injection pattern: #{sql_pattern.id}")
  IO.puts("\n🔍 Pattern structure:")
  IO.puts("ast_pattern:")
  IO.inspect(sql_pattern.ast_pattern, pretty: true, limit: :infinity)
  
  IO.puts("\ncontext_rules:")
  IO.inspect(sql_pattern.context_rules, pretty: true, limit: :infinity)
  
  IO.puts("\n📋 Key observations:")
  if sql_pattern.ast_pattern do
    IO.puts("- ast_pattern has type: #{sql_pattern.ast_pattern["type"]}")
    IO.puts("- ast_pattern has op: #{sql_pattern.ast_pattern["op"]}")
    IO.puts("- ast_pattern has sql_context: #{Map.has_key?(sql_pattern.ast_pattern, "sql_context")}")
    IO.puts("- ast_pattern has _contains_sql_pattern: #{Map.has_key?(sql_pattern.ast_pattern, "_contains_sql_pattern")}")
  end
else
  IO.puts("\n❌ No SQL injection pattern found!")
end

# Now test what the matcher would do
IO.puts("\n🧪 Testing pattern matching logic:")
test_node = %{
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

if sql_pattern && sql_pattern.ast_pattern do
  pattern = sql_pattern.ast_pattern
  IO.puts("\nChecking node against pattern:")
  IO.puts("Node type matches? #{test_node["type"] == pattern["type"]}")
  IO.puts("Op matches? #{test_node["op"] == pattern["op"] || test_node["op"]["type"] == pattern["op"]}")
  
  # The issue might be that sql_context is in the pattern but not in the node
  if pattern["sql_context"] do
    IO.puts("\n⚠️  Pattern has 'sql_context' field which is not in AST nodes!")
    IO.puts("This would cause the pattern to never match.")
  end
end