#!/usr/bin/env elixir

# Shell-based pattern debug
# Run with: docker-compose exec rsolv-api elixir debug_pattern_shell.exs

IO.puts("🔍 Shell-based Pattern Debug")
IO.puts("=" |> String.duplicate(60))
IO.puts("Elixir: #{System.version()}")

# Write test code to a file
test_code = ~s(query = "SELECT * FROM users WHERE id = " + user_id)
File.write!("/tmp/test_sql.py", test_code)
IO.puts("\n📝 Test code written to /tmp/test_sql.py")

# Create input JSON
input_json = JSON.encode!(%{
  "id" => "test",
  "source" => test_code,
  "language" => "python"
})
File.write!("/tmp/input.json", input_json)

# Run parser
IO.puts("\n🐍 Running Python parser...")
parser_path = "/app/priv/parsers/python/parser.py"

# Use shell redirection
{output, exit_code} = System.shell("python3 #{parser_path} < /tmp/input.json 2>&1")

IO.puts("Exit code: #{exit_code}")

if exit_code == 0 do
  case JSON.decode(output) do
    {:ok, result} ->
      ast = result["ast"] || []
      IO.puts("✅ Parser worked! AST nodes: #{length(ast)}")
      
      if length(ast) > 0 do
        IO.puts("\n🔍 AST Structure:")
        Enum.each(ast, fn node ->
          if node["type"] == "BinOp" do
            IO.puts("\n✅ Found BinOp node!")
            IO.puts("  ID: #{node["id"]}")
            IO.puts("  Op: #{inspect(node["op"])}")
            IO.puts("  Left type: #{node["left"]["type"]}")
            IO.puts("  Left value: #{inspect(node["left"]["value"])}")
            IO.puts("  Right type: #{node["right"]["type"]}")
            IO.puts("  Line: #{node["line"]}")
            
            # Check if this should match pattern
            is_add = case node["op"] do
              %{"type" => "Add"} -> true
              _ -> false
            end
            
            has_sql = node["left"]["value"] && String.contains?(String.downcase(node["left"]["value"]), "select")
            
            IO.puts("\n🎯 Pattern matching check:")
            IO.puts("  Is Add operator? #{is_add}")
            IO.puts("  Has SQL in left? #{has_sql}")
            IO.puts("  Should match SQL injection pattern? #{is_add && has_sql}")
          end
        end)
      end
      
      # Save for inspection
      File.write!("/tmp/ast_output.json", JSON.encode!(result, pretty: true))
      IO.puts("\n💾 Full AST saved to /tmp/ast_output.json")
      
    {:error, err} ->
      IO.puts("❌ Failed to decode JSON: #{inspect(err)}")
      IO.puts("Raw output: #{output}")
  end
else
  IO.puts("❌ Parser failed!")
  IO.puts("Output: #{output}")
end

IO.puts("\n📊 Summary:")
IO.puts("If the parser produces correct AST with BinOp + Add + SQL,")
IO.puts("but pattern matching returns 0 vulnerabilities, then:")
IO.puts("1. Context rules might be too strict")
IO.puts("2. Confidence scoring might filter out matches")
IO.puts("3. Pattern structure might not match AST structure")