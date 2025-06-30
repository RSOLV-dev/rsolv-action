#!/usr/bin/env elixir

# Simple pattern debug - run with: docker-compose exec rsolv-api elixir debug_pattern_simple.exs

IO.puts("🔍 Simple Pattern Debug")
IO.puts("=" |> String.duplicate(50))

# Start the application manually
{:ok, _} = Application.ensure_all_started(:rsolv_api)

# Check patterns are loaded
patterns = RsolvApi.Security.PatternRegistry.get_patterns_for_language("python")
IO.puts("Python patterns: #{length(patterns)}")

# Find SQL injection pattern
sql_pattern = Enum.find(patterns, fn p -> 
  p.id == "python-sql-injection-format"
end)

if sql_pattern do
  IO.puts("\n✅ Found SQL injection pattern!")
  IO.puts("AST Rules:")
  IO.inspect(sql_pattern.ast_rules, pretty: true, limit: :infinity)
else
  IO.puts("\n❌ SQL injection pattern not found!")
end

# Test the AST parser directly
IO.puts("\n🔧 Testing Python parser...")
parser_path = "/app/priv/parsers/python/parser.py"
test_code = ~s(query = "SELECT * FROM users WHERE id = " + user_id)

input = JSON.encode!(%{
  "id" => "test",
  "source" => test_code,
  "language" => "python"
})

case System.cmd("python3", [parser_path], input: input, stderr_to_stdout: true) do
  {output, 0} ->
    case JSON.decode(output) do
      {:ok, result} ->
        IO.puts("✅ Parser worked!")
        IO.puts("AST nodes: #{length(result["ast"] || [])}")
        if length(result["ast"] || []) > 0 do
          IO.puts("\nFirst AST node:")
          IO.inspect(hd(result["ast"]), pretty: true, limit: :infinity)
        end
      {:error, _} ->
        IO.puts("❌ Parser output not JSON: #{output}")
    end
  {output, code} ->
    IO.puts("❌ Parser failed (#{code}): #{output}")
end