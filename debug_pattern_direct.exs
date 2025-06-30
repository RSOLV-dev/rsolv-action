#!/usr/bin/env elixir

# Direct pattern debug - connects to running app
# Run with: docker-compose exec rsolv-api elixir debug_pattern_direct.exs

IO.puts("🔍 Direct Pattern Debug (Connecting to Running App)")
IO.puts("=" |> String.duplicate(60))
IO.puts("Elixir: #{System.version()}")

# Since the app is already running, we can use remote shell
# But for now, let's just test the parser directly

IO.puts("\n🐍 Testing Python Parser Directly:")
test_code = ~s(query = "SELECT * FROM users WHERE id = " + user_id)
parser_path = "/app/priv/parsers/python/parser.py"

input = JSON.encode!(%{
  "id" => "test",
  "source" => test_code,
  "language" => "python"
})

case System.cmd("python3", [parser_path], stdin: IO.iodata_to_binary(input), stderr_to_stdout: true) do
  {output, 0} ->
    case JSON.decode(output) do
      {:ok, result} ->
        ast = result["ast"] || []
        IO.puts("✅ Parser worked! AST nodes: #{length(ast)}")
        
        if length(ast) > 0 do
          IO.puts("\n📋 Full AST:")
          Enum.each(ast, fn node ->
            IO.puts("\nNode #{node["id"] || "?"}:")
            IO.puts("  Type: #{node["type"]}")
            if node["type"] == "BinOp" do
              IO.puts("  Op: #{inspect(node["op"])}")
              IO.puts("  Left: #{inspect(node["left"]["type"])}")
              if node["left"]["value"], do: IO.puts("  Left value: #{inspect(node["left"]["value"])}")
              IO.puts("  Right: #{inspect(node["right"]["type"])}")
            end
          end)
        end
      {:error, err} ->
        IO.puts("❌ Parser output not JSON: #{inspect(err)}")
        IO.puts("Raw output: #{output}")
    end
  {output, code} ->
    IO.puts("❌ Parser failed with code #{code}")
    IO.puts("Output: #{output}")
end

# Now let's check what the API would see
IO.puts("\n🔧 Creating test payload for API:")
test_files = [
  %{
    "id" => "test-file",
    "path" => "test.py",
    "language" => "python", 
    "source" => test_code
  }
]

IO.puts("Test file:")
IO.inspect(test_files, pretty: true)

IO.puts("\n📡 To test the API:")
IO.puts("curl -X POST http://localhost:4001/api/v1/ast/analyze \\")
IO.puts("  -H 'Content-Type: application/json' \\")
IO.puts("  -H 'X-API-Key: rsolv_test_abc123' \\")
IO.puts("  -d '#{JSON.encode!(%{"files" => test_files})}'")

IO.puts("\n💡 Next debugging steps:")
IO.puts("1. Check if patterns are evaluating context rules")
IO.puts("2. Verify confidence scoring isn't filtering matches")
IO.puts("3. Add logging to ASTPatternMatcher module")
IO.puts("4. Test with a minimal pattern (no context rules)")