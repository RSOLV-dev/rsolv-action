#!/usr/bin/env elixir

# Final pattern debug - identify the exact issue
# Run with: docker-compose exec rsolv-api elixir final_pattern_debug.exs

IO.puts("🎯 Final Pattern Debug")
IO.puts("=" |> String.duplicate(60))

# The issue is that when patterns are loaded by PatternAdapter,
# they might not have the ast_pattern field set correctly.

# Check the pattern module directly
pattern_module = RsolvApi.Security.Patterns.Python.SqlInjectionConcat

IO.puts("\n1. Pattern module check:")
IO.puts("Module exists? #{Code.ensure_loaded?(pattern_module)}")
IO.puts("Has pattern/0? #{function_exported?(pattern_module, :pattern, 0)}")
IO.puts("Has ast_enhancement/0? #{function_exported?(pattern_module, :ast_enhancement, 0)}")

if function_exported?(pattern_module, :pattern, 0) do
  base_pattern = pattern_module.pattern()
  IO.puts("\nBase pattern type: #{base_pattern.__struct__}")
  IO.puts("Has regex? #{not is_nil(base_pattern.regex)}")
end

if function_exported?(pattern_module, :ast_enhancement, 0) do
  enhancement = pattern_module.ast_enhancement()
  IO.puts("\nEnhancement keys: #{inspect(Map.keys(enhancement))}")
  if enhancement[:ast_rules] do
    IO.puts("AST rules: #{inspect(enhancement.ast_rules, pretty: true, limit: 2)}")
  end
end

# The key issue: PatternAdapter needs to convert the enhancement
# into a structure with ast_pattern field

IO.puts("\n2. Pattern conversion simulation:")

# This is what should happen in PatternAdapter
ast_rules = %{
  node_type: "BinOp",
  op: "Add",
  sql_context: %{
    left_or_right_is_string: true,
    contains_sql_pattern: true
  }
}

# Convert to ast_pattern format
ast_pattern = %{
  "type" => to_string(ast_rules.node_type),
  "op" => ast_rules.op
}

# Extract sql_context as special fields
if sql_context = ast_rules[:sql_context] do
  ast_pattern = ast_pattern
    |> Map.put("_contains_sql_pattern", sql_context[:contains_sql_pattern])
    |> Map.put("_left_or_right_is_string", sql_context[:left_or_right_is_string])
end

IO.puts("\nConverted ast_pattern:")
IO.inspect(ast_pattern, pretty: true)

# The final pattern structure needed by the matcher
final_pattern = %{
  id: "python-sql-injection-concat",
  ast_pattern: ast_pattern,  # THIS IS CRITICAL!
  context_rules: %{},
  min_confidence: 0.7
}

IO.puts("\n3. Final pattern structure for matcher:")
IO.puts("Has ast_pattern field? #{not is_nil(final_pattern.ast_pattern)}")
IO.puts("ast_pattern type: #{final_pattern.ast_pattern["type"]}")
IO.puts("ast_pattern op: #{final_pattern.ast_pattern["op"]}")

IO.puts("\n💡 ROOT CAUSE:")
IO.puts("The PatternAdapter must ensure the final pattern has:")
IO.puts("1. ast_pattern field (not nil)")
IO.puts("2. Correctly converted AST rules")
IO.puts("3. sql_context extracted as _-prefixed fields")

IO.puts("\n🔧 SOLUTION:")
IO.puts("Check PatternAdapter.convert_to_matcher_format/1")
IO.puts("Ensure it sets ast_pattern from convert_ast_rules_to_pattern/1")