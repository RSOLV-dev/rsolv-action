#!/usr/bin/env elixir

# Test pattern conversion issue
# Run with: docker-compose exec rsolv-api elixir test_pattern_conversion.exs

IO.puts("🔍 Testing Pattern Conversion Issue")
IO.puts("=" |> String.duplicate(60))

# Simulate what the pattern adapter does
ast_rules = %{
  node_type: "BinOp",
  op: "Add",
  sql_context: %{
    left_or_right_is_string: true,
    contains_sql_pattern: true
  }
}

IO.puts("\n1. Original AST rules:")
IO.inspect(ast_rules, pretty: true)

# Simulate the conversion
base_pattern = %{
  "type" => to_string(ast_rules.node_type),
  "op" => ast_rules.op
}

# The problem: sql_context is added as a field
base_pattern_wrong = Map.put(base_pattern, "sql_context", ast_rules.sql_context)

IO.puts("\n2. Wrong conversion (adds sql_context as field):")
IO.inspect(base_pattern_wrong, pretty: true)

# The correct way: extract checks from sql_context
base_pattern_correct = base_pattern
if sql_context = ast_rules[:sql_context] do
  base_pattern_correct = if sql_context[:contains_sql_pattern] do
    Map.put(base_pattern_correct, "_contains_sql_pattern", true)
  else
    base_pattern_correct
  end
  
  base_pattern_correct = if sql_context[:left_or_right_is_string] do
    Map.put(base_pattern_correct, "_left_or_right_is_string", true)
  else
    base_pattern_correct
  end
end

IO.puts("\n3. Correct conversion (extracts sql_context as checks):")
IO.inspect(base_pattern_correct, pretty: true)

# Test matching
test_node = %{
  "type" => "BinOp",
  "op" => %{"type" => "Add"},
  "left" => %{
    "type" => "Constant",
    "value" => "SELECT * FROM users WHERE id = "
  }
}

IO.puts("\n4. Test AST node:")
IO.inspect(test_node, pretty: true)

# Wrong pattern won't match because node doesn't have sql_context field
IO.puts("\n5. Matching results:")
IO.puts("Wrong pattern matches? #{PatternTest.matches_all_fields?(test_node, base_pattern_wrong)}")
IO.puts("Correct pattern matches? #{PatternTest.matches_all_fields?(test_node, base_pattern_correct)}")

IO.puts("\n💡 The issue:")
IO.puts("Pattern adapter is likely adding sql_context as a literal field")
IO.puts("instead of converting it to context check flags (_contains_sql_pattern, etc)")

# Helper function
defmodule PatternTest do
  def matches_all_fields?(node, pattern) do
  Enum.all?(pattern, fn {key, expected} ->
    if String.starts_with?(key, "_") do
      true  # Skip context checks for this test
    else
      actual = node[key]
      case {actual, expected} do
        {%{"type" => op_type}, expected_op} when is_binary(expected_op) ->
          op_type == expected_op
        {actual, expected} ->
          actual == expected
      end
    end
  end)
  end
end