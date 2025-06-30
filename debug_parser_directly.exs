#!/usr/bin/env elixir

# Debug parser directly
# Run with: docker-compose exec rsolv-api elixir debug_parser_directly.exs

IO.puts("🔍 Direct Parser Debug")
IO.puts("=" |> String.duplicate(60))

# Test the parser with a simple command
IO.puts("\n1. Testing parser existence:")
{output, code} = System.shell("ls -la /app/priv/parsers/python/parser.py")
IO.puts("Exit code: #{code}")
IO.puts(output)

IO.puts("\n2. Testing Python:")
{output, code} = System.shell("python3 --version")
IO.puts("Python version: #{output}")

IO.puts("\n3. Running parser with test input:")
# Create a very simple test
test_json = """
{"id": "test", "source": "x = 1 + 2", "language": "python"}
"""
File.write!("/tmp/simple_test.json", test_json)

{output, code} = System.shell("cd /app && python3 priv/parsers/python/parser.py < /tmp/simple_test.json")
IO.puts("Exit code: #{code}")
IO.puts("Output length: #{String.length(output)} bytes")

if code == 0 do
  case JSON.decode(output) do
    {:ok, result} ->
      IO.puts("✅ Parser returned valid JSON")
      IO.puts("AST nodes: #{length(result["ast"] || [])}")
      if length(result["ast"] || []) > 0 do
        IO.puts("\nFirst node:")
        IO.inspect(hd(result["ast"]), pretty: true, limit: :infinity)
      end
    {:error, err} ->
      IO.puts("❌ Invalid JSON: #{inspect(err)}")
      IO.puts("First 500 chars: #{String.slice(output, 0, 500)}")
  end
else
  IO.puts("❌ Parser failed")
  IO.puts("Error: #{output}")
end

# Now test with SQL injection code
IO.puts("\n4. Testing with SQL injection code:")
sql_test = """
{"id": "test-sql", "source": "query = \\"SELECT * FROM users WHERE id = \\" + user_id", "language": "python"}
"""
File.write!("/tmp/sql_test.json", sql_test)

{output, code} = System.shell("cd /app && python3 priv/parsers/python/parser.py < /tmp/sql_test.json")
IO.puts("Exit code: #{code}")

if code == 0 do
  case JSON.decode(output) do
    {:ok, result} ->
      ast = result["ast"] || []
      IO.puts("✅ AST nodes: #{length(ast)}")
      
      # Find BinOp nodes
      binop_nodes = Enum.filter(ast, &(&1["type"] == "BinOp"))
      IO.puts("BinOp nodes: #{length(binop_nodes)}")
      
      if length(binop_nodes) > 0 do
        IO.puts("\nBinOp node details:")
        IO.inspect(hd(binop_nodes), pretty: true, limit: :infinity)
      end
    {:error, _} ->
      IO.puts("❌ Parse error")
      IO.puts("Output: #{String.slice(output, 0, 200)}")
  end
else
  IO.puts("❌ Parser error: #{output}")
end