#!/usr/bin/env elixir

# Complete Pattern Debug - Run with: docker-compose exec rsolv-api bash -c "cd /app && iex -S mix run debug_pattern_complete.exs"

IO.puts("🔍 Complete Pattern Matching Debug")
IO.puts("=" |> String.duplicate(60))
IO.puts("Elixir: #{System.version()}")

# Get patterns
patterns = RsolvApi.Security.PatternRegistry.get_patterns_for_language("python")
sql_patterns = Enum.filter(patterns, &String.contains?(String.downcase(&1.name || ""), "sql"))

IO.puts("\n📋 Pattern Status:")
IO.puts("Total Python patterns: #{length(patterns)}")
IO.puts("SQL-related patterns: #{length(sql_patterns)}")

if length(sql_patterns) > 0 do
  pattern = hd(sql_patterns)
  IO.puts("\n🎯 SQL Injection Pattern:")
  IO.puts("ID: #{pattern.id}")
  IO.puts("Name: #{pattern.name}")
  
  IO.puts("\nAST Rules:")
  Enum.each(Map.to_list(pattern.ast_rules || %{}), fn {k, v} ->
    IO.puts("  #{k}: #{inspect(v)}")
  end)
end

# Test Python parser
IO.puts("\n🐍 Testing Python Parser:")
test_code = ~s(query = "SELECT * FROM users WHERE id = " + user_id)
parser_path = "/app/priv/parsers/python/parser.py"

input = JSON.encode!(%{
  "id" => "test",
  "source" => test_code,
  "language" => "python"
})

case System.cmd("python3", [parser_path], input: input, stderr_to_stdout: true) do
  {output, 0} ->
    case JSON.decode(output) do
      {:ok, result} ->
        ast = result["ast"] || []
        IO.puts("✅ Parser worked! AST nodes: #{length(ast)}")
        
        if length(ast) > 0 do
          binop_nodes = Enum.filter(ast, &(&1["type"] == "BinOp"))
          IO.puts("BinOp nodes found: #{length(binop_nodes)}")
          
          if length(binop_nodes) > 0 do
            node = hd(binop_nodes)
            IO.puts("\n🔍 BinOp Node Structure:")
            IO.puts("Type: #{node["type"]}")
            IO.puts("Op: #{inspect(node["op"])}")
            IO.puts("Left type: #{node["left"]["type"]}")
            if node["left"]["type"] == "Constant" do
              IO.puts("Left value: #{inspect(node["left"]["value"])}")
            end
          end
        end
      {:error, _} ->
        IO.puts("❌ Parser output not JSON")
    end
  {_, code} ->
    IO.puts("❌ Parser failed with code #{code}")
end

# Now test the actual pattern matching
IO.puts("\n🧪 Testing Pattern Matching:")

# Create a test AST that should match
test_ast = [%{
  "type" => "BinOp",
  "op" => %{"type" => "Add"},
  "left" => %{
    "type" => "Constant",
    "value" => "SELECT * FROM users WHERE id = "
  },
  "right" => %{
    "type" => "Name",
    "id" => "user_id"
  },
  "line" => 1,
  "column" => 0
}]

file_result = %{
  id: "test-file",
  path: "test.py", 
  language: "python",
  ast: test_ast
}

IO.puts("Test AST created with #{length(test_ast)} nodes")

# Run pattern matcher
alias RsolvApi.AST.ASTPatternMatcher

IO.puts("\n🎲 Running pattern matcher...")
try do
  matches = ASTPatternMatcher.match_patterns(file_result, patterns)
  IO.puts("Matches found: #{length(matches)}")
  
  if length(matches) > 0 do
    IO.puts("\n✅ SUCCESS! Matches:")
    Enum.each(matches, fn match ->
      IO.puts("  Pattern: #{match.pattern_id}")
      IO.puts("  Confidence: #{match.confidence}")
      IO.puts("  Line: #{match.line}")
    end)
  else
    IO.puts("\n❌ No matches found")
    
    # Debug why not matching
    if length(sql_patterns) > 0 do
      pattern = hd(sql_patterns)
      node = hd(test_ast)
      
      IO.puts("\n🔍 Debug matching logic:")
      IO.puts("Pattern expects:")
      IO.puts("  node_type: #{inspect(pattern.ast_rules[:node_type])}")
      IO.puts("  op: #{inspect(pattern.ast_rules[:op])}")
      
      IO.puts("Node provides:")
      IO.puts("  type: #{inspect(node["type"])}")
      IO.puts("  op: #{inspect(node["op"])}")
      
      # Check node type match
      node_match = node["type"] == pattern.ast_rules[:node_type]
      IO.puts("\nNode type matches? #{node_match}")
      
      # Check operator match
      op_match = case {node["op"], pattern.ast_rules[:op]} do
        {%{"type" => op_type}, expected} -> op_type == expected
        {actual, expected} -> actual == expected
      end
      IO.puts("Operator matches? #{op_match}")
      
      # Check SQL context
      if pattern.ast_rules[:sql_context] do
        IO.puts("\nSQL context rules:")
        IO.inspect(pattern.ast_rules[:sql_context], pretty: true)
        
        left_value = node["left"]["value"] || ""
        has_sql = String.contains?(String.downcase(left_value), "select")
        IO.puts("Left contains SQL? #{has_sql}")
      end
    end
  end
rescue
  error ->
    IO.puts("❌ Error: #{inspect(error)}")
    IO.puts(Exception.format(:error, error, __STACKTRACE__))
end

IO.puts("\n📝 Conclusion:")
IO.puts("If patterns are loaded but not matching, check:")
IO.puts("1. Pattern structure expectations vs actual AST")
IO.puts("2. Context rules that might be filtering matches")
IO.puts("3. Confidence scoring thresholds")
IO.puts("4. Any additional validation in the matcher")