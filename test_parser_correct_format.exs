#!/usr/bin/env elixir

# Test parser with correct format
# Run with: docker-compose exec rsolv-api elixir test_parser_correct_format.exs

IO.puts("🔍 Testing Parser with Correct Format")
IO.puts("=" |> String.duplicate(60))

# Test 1: Simple addition
test1 = JSON.encode!(%{
  "id" => "test-simple",
  "command" => "x = 1 + 2",
  "options" => %{"include_security_patterns" => true}
})

IO.puts("\n1. Simple test:")
{output, code} = System.shell("echo '#{test1}' | python3 /app/priv/parsers/python/parser.py")

if code == 0 do
  case JSON.decode(output) do
    {:ok, result} ->
      IO.puts("✅ Success!")
      IO.puts("AST type: #{result["ast"]["type"]}")
      IO.puts("Status: #{result["status"]}")
    {:error, _} -> 
      IO.puts("❌ Parse error: #{output}")
  end
else
  IO.puts("❌ Error: #{output}")
end

# Test 2: SQL injection pattern
test2 = JSON.encode!(%{
  "id" => "test-sql",
  "command" => ~s(query = "SELECT * FROM users WHERE id = " + user_id),
  "options" => %{"include_security_patterns" => true}
})

IO.puts("\n2. SQL injection test:")
{output, code} = System.shell("echo '#{test2}' | python3 /app/priv/parsers/python/parser.py")

if code == 0 do
  case JSON.decode(output) do
    {:ok, result} ->
      IO.puts("✅ Success!")
      IO.puts("Status: #{result["status"]}")
      IO.puts("AST nodes: #{count_nodes(result["ast"])}")
      IO.puts("Security patterns: #{length(result["security_patterns"] || [])}")
      
      # Look for BinOp in AST
      binops = find_nodes_by_type(result["ast"], "BinOp")
      IO.puts("BinOp nodes found: #{length(binops)}")
      
      if length(binops) > 0 do
        binop = hd(binops)
        IO.puts("\nFirst BinOp:")
        IO.puts("  Op type: #{binop["op"]["type"]}")
        IO.puts("  Left type: #{binop["left"]["type"]}")
        if binop["left"]["value"] do
          IO.puts("  Left value: #{inspect(binop["left"]["value"])}")
        end
        IO.puts("  Line: #{binop["_lineno"]}")
      end
      
    {:error, _} -> 
      IO.puts("❌ Parse error: #{output}")
  end
else
  IO.puts("❌ Error: #{output}")
end

# Helper functions
defp count_nodes(nil), do: 0
defp count_nodes(node) when is_map(node) do
  1 + Enum.reduce(node, 0, fn
    {_key, value}, acc -> acc + count_nodes(value)
  end)
end
defp count_nodes(nodes) when is_list(nodes) do
  Enum.reduce(nodes, 0, &(&2 + count_nodes(&1)))
end
defp count_nodes(_), do: 0

defp find_nodes_by_type(nil, _type), do: []
defp find_nodes_by_type(node, type) when is_map(node) do
  current = if node["type"] == type, do: [node], else: []
  children = Enum.flat_map(node, fn
    {_key, value} -> find_nodes_by_type(value, type)
  end)
  current ++ children
end
defp find_nodes_by_type(nodes, type) when is_list(nodes) do
  Enum.flat_map(nodes, &find_nodes_by_type(&1, type))
end
defp find_nodes_by_type(_, _), do: []

IO.puts("\n📊 Summary:")
IO.puts("The parser expects 'command' field, not 'source'")
IO.puts("This explains why we were getting 0 AST nodes!")