#!/usr/bin/env elixir

# Live System Debug - Run in Container
# This script will inspect the actual pattern matching process

IO.puts("🔍 Live System Debug - Pattern Matching Investigation")
IO.puts("=" |> String.duplicate(60))

# Test the actual Python parser
IO.puts("\n1. Testing Python Parser...")
python_code = """
query = "SELECT * FROM users WHERE id = " + user_id
"""

python_parser_path = Path.join([
  "/app/priv/parsers/python/parser.py"
])

IO.puts("Parser path: #{python_parser_path}")
IO.puts("Parser exists: #{File.exists?(python_parser_path)}")

# Test running the parser directly
IO.puts("\n2. Running Python Parser...")
input_json = JSON.encode!(%{
  "id" => "test-1",
  "source" => python_code,
  "language" => "python"
})

case System.cmd("python3", [python_parser_path], input: input_json, stderr_to_stdout: true) do
  {output, 0} ->
    IO.puts("✅ Parser succeeded:")
    case JSON.decode(output) do
      {:ok, parsed} ->
        IO.puts("AST nodes found: #{length(parsed["ast"] || [])}")
        if parsed["ast"] && length(parsed["ast"]) > 0 do
          first_node = hd(parsed["ast"])
          IO.puts("First node type: #{first_node["type"]}")
          IO.puts("First node: #{inspect(first_node, pretty: true, limit: 3)}")
        end
      {:error, _} ->
        IO.puts("Raw output: #{output}")
    end
  {output, exit_code} ->
    IO.puts("❌ Parser failed (exit code #{exit_code}):")
    IO.puts(output)
end

IO.puts("\n3. Testing Pattern Loading...")
# We can't easily test this without the full application context
IO.puts("Pattern loading requires full Phoenix app context")

IO.puts("\n4. Key Investigation Points:")
IO.puts("- Check if AST nodes match expected pattern structure")
IO.puts("- Verify pattern rules are being applied correctly")
IO.puts("- Confirm confidence thresholds aren't filtering matches")
IO.puts("- Check context analysis logic")

IO.puts("\n📋 Next Steps:")
IO.puts("1. Compare actual AST structure with pattern expectations")
IO.puts("2. Enable debug logging in AST pattern matcher")
IO.puts("3. Check pattern loading and structure")
IO.puts("4. Verify context analysis rules")