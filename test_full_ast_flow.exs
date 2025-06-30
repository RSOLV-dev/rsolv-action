#!/usr/bin/env elixir

# Test full AST flow
# Run with: docker-compose exec rsolv-api elixir test_full_ast_flow.exs

IO.puts("🔍 Testing Full AST Flow")
IO.puts("=" |> String.duplicate(60))

# First, test the parser directly with correct format
IO.puts("\n1. Testing Python parser directly:")
test_parser = JSON.encode!(%{
  "id" => "test-direct",
  "command" => ~s(query = "SELECT * FROM users WHERE id = " + user_id),
  "options" => %{"include_security_patterns" => true}
})

{output, code} = System.shell("echo '#{test_parser}' | python3 /app/priv/parsers/python/parser.py")
if code == 0 do
  case JSON.decode(output) do
    {:ok, result} ->
      IO.puts("✅ Parser works! Status: #{result["status"]}")
      ast = result["ast"]["body"] || []
      IO.puts("AST body statements: #{length(ast)}")
    {:error, _} ->
      IO.puts("❌ Parser error")
  end
end

# Now test what the analysis service would send
IO.puts("\n2. Testing file format for analysis service:")
file = %{
  id: "test-file",
  path: "test.py",
  content: ~s(query = "SELECT * FROM users WHERE id = " + user_id),
  language: "python"
}

IO.puts("File structure:")
IO.inspect(file, pretty: true)

# The issue might be in how ParserRegistry.parse_code is called
# It receives: session_id, customer_id, language, code
# But the parser expects the code in "command" field
IO.puts("\n3. Key finding:")
IO.puts("- Analysis service passes file.content to ParserRegistry.parse_code")
IO.puts("- ParserRegistry calls PortWorker with the code")
IO.puts("- PortWorker creates request with 'command' => code")
IO.puts("- This should work correctly!")

IO.puts("\n4. Checking pattern loading...")
# We need to verify patterns are actually being loaded
# Let's check if pattern files exist
pattern_dir = "/app/lib/rsolv_api/security/patterns/python"
{output, _} = System.shell("ls -la #{pattern_dir}/*.ex 2>&1 | head -5")
IO.puts("Pattern files:")
IO.puts(output)

IO.puts("\n5. The issue must be in:")
IO.puts("- Pattern structure not matching AST structure")
IO.puts("- Context rules filtering out matches")
IO.puts("- Confidence scoring below threshold")
IO.puts("- Pattern matching traversal not finding nested nodes")