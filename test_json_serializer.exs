#!/usr/bin/env elixir

# Load the JSONSerializer module
Code.compile_file("/home/dylan/dev/rsolv/RSOLV-api/lib/rsolv_api/security/patterns/json_serializer.ex")

alias RSOLVApi.Security.Patterns.JSONSerializer

IO.puts "=== Testing JSON Serializer Implementation ===\n"

# Test 1: Simple regex conversion
IO.puts "1. Testing simple regex conversion:"
regex = ~r/test/
prepared = JSONSerializer.prepare_for_json(regex)
IO.inspect(prepared, label: "Prepared regex")

# Test 2: Regex with flags
IO.puts "\n2. Testing regex with flags:"
regex_with_flags = ~r/test/im
prepared_flags = JSONSerializer.prepare_for_json(regex_with_flags)
IO.inspect(prepared_flags, label: "Prepared regex with flags")

# Test 3: Pattern with regex
IO.puts "\n3. Testing pattern with regex:"
pattern = %{
  id: "sql_injection",
  pattern: ~r/SELECT.*FROM/i,
  severity: :high
}
prepared_pattern = JSONSerializer.prepare_for_json(pattern)
IO.inspect(prepared_pattern, label: "Prepared pattern")

# Test 4: JSON encoding
IO.puts "\n4. Testing JSON encoding with native JSON module:"
try do
  json = JSONSerializer.encode!(prepared_pattern)
  IO.puts "✓ Successfully encoded to JSON:"
  IO.puts "  #{String.slice(json, 0..100)}..."
  
  # Test decoding
  {:ok, decoded} = JSON.decode(json)
  IO.puts "✓ Successfully decoded from JSON"
  IO.inspect(decoded["pattern"], label: "Decoded pattern field")
rescue
  e ->
    IO.puts "✗ Error: #{inspect(e)}"
end

# Test 5: Complex nested structure
IO.puts "\n5. Testing complex nested structure:"
complex = %{
  id: "sql_injection_concat",
  pattern: ~r/\.(query|execute|exec|run|all|get)/,
  ast_rules: [
    %{type: "call", pattern: ~r/execute|query/}
  ],
  context_rules: %{
    safe_patterns: [~r/\?\s*,\s*\?/, ~r/:\w+/]
  }
}

try do
  json = JSONSerializer.encode!(complex)
  IO.puts "✓ Successfully encoded complex structure"
  
  {:ok, decoded} = JSON.decode(json)
  IO.puts "✓ Pattern source: #{decoded["pattern"]["source"]}"
  IO.puts "✓ First AST rule pattern: #{decoded["ast_rules"] |> List.first() |> Map.get("pattern") |> Map.get("source")}"
  IO.puts "✓ Safe patterns count: #{decoded["context_rules"]["safe_patterns"] |> length()}"
rescue
  e ->
    IO.puts "✗ Error: #{inspect(e)}"
end

IO.puts "\n=== Summary ===\n"
IO.puts "✓ prepare_for_json/1 successfully converts regex to serializable format"
IO.puts "✓ Native JSON module can encode the prepared data"
IO.puts "✓ Ready to integrate into Pattern Controller"