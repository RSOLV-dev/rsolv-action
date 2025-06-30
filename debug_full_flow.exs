#!/usr/bin/env elixir

# Debug the full AST pattern matching flow
# Run with: docker-compose exec rsolv-api elixir debug_full_flow.exs

IO.puts("🔍 Debugging Full AST Pattern Matching Flow")
IO.puts("=" |> String.duplicate(60))

# Step 1: Check what the AST looks like
IO.puts("\n1. Python AST structure:")
test_code = ~s(query = "SELECT * FROM users WHERE id = " + user_id)
parser_request = JSON.encode!(%{
  "id" => "test",
  "command" => test_code,
  "options" => %{}
})

{output, 0} = System.shell("echo '#{parser_request}' | python3 /app/priv/parsers/python/parser.py")
{:ok, parse_result} = JSON.decode(output)
ast = parse_result["ast"]

# Find the BinOp node
find_binop = fn ast, find_binop ->
  case ast do
    %{"type" => "BinOp"} = node -> node
    %{"body" => [stmt | _]} -> find_binop.(stmt, find_binop)
    %{"value" => value} -> find_binop.(value, find_binop)
    _ -> nil
  end
end

binop_node = find_binop.(ast, find_binop)
if binop_node do
  IO.puts("✅ Found BinOp node:")
  IO.inspect(binop_node, pretty: true, limit: 3)
end

# Step 2: Check pattern structure
IO.puts("\n2. Pattern structure investigation:")

# The pattern should have this structure when loaded by PatternAdapter
expected_pattern_structure = %{
  id: "python-sql-injection-concat",
  ast_pattern: %{
    "type" => "BinOp",
    "op" => "Add",
    "_contains_sql_pattern" => true,
    "_left_or_right_is_string" => true
  },
  context_rules: %{
    # ... various rules
  }
}

IO.puts("Expected pattern structure:")
IO.inspect(expected_pattern_structure, pretty: true, limit: 2)

# Step 3: Simulate pattern matching
IO.puts("\n3. Simulating pattern matching:")

if binop_node do
  # Check basic field matching
  pattern = expected_pattern_structure.ast_pattern
  
  type_matches = binop_node["type"] == pattern["type"]
  IO.puts("Type matches? #{type_matches}")
  
  # Special handling for Python operators
  op_matches = case {binop_node["op"], pattern["op"]} do
    {%{"type" => op_type}, expected_op} -> op_type == expected_op
    _ -> false
  end
  IO.puts("Op matches? #{op_matches}")
  
  IO.puts("\n✅ Basic pattern should match!")
  IO.puts("The issue is likely that:")
  IO.puts("1. Patterns aren't being enhanced with ast_pattern field")
  IO.puts("2. OR context checks are too strict")
  IO.puts("3. OR confidence scoring filters out the match")
end

IO.puts("\n4. Key debugging points:")
IO.puts("- Check if PatternAdapter is actually enhancing patterns")
IO.puts("- Verify ast_pattern field is not nil") 
IO.puts("- Check context requirements in passes_context_requirements?")
IO.puts("- Verify confidence threshold (default 0.7)")