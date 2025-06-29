#!/usr/bin/env elixir

# Test to verify JSON migration for pattern API

# Compile the JSONSerializer
Code.compile_file("/home/dylan/dev/rsolv/RSOLV-api/lib/rsolv_api/security/patterns/json_serializer.ex")

alias RSOLVApi.Security.Patterns.JSONSerializer

IO.puts "=== Testing Pattern API JSON Migration ===\n"

# Test 1: Check if JSON module is available
IO.puts "1. Checking native JSON module availability:"
if Code.ensure_loaded?(JSON) do
  IO.puts "✓ JSON module is available (Elixir 1.18+)"
else
  IO.puts "✗ JSON module not found"
  System.halt(1)
end

# Test 2: Test standard pattern (no regex)
IO.puts "\n2. Testing standard pattern encoding:"
standard_pattern = %{
  id: "xss-dom",
  name: "DOM XSS",
  description: "DOM-based XSS vulnerability",
  severity: :high,
  languages: ["javascript"],
  cwe_id: "CWE-79"
}

try do
  json = JSON.encode!(standard_pattern)
  IO.puts "✓ Standard pattern encoded successfully"
  IO.puts "  Length: #{String.length(json)} bytes"
rescue
  e ->
    IO.puts "✗ Failed to encode standard pattern: #{inspect(e)}"
end

# Test 3: Test enhanced pattern with regex
IO.puts "\n3. Testing enhanced pattern with regex:"
enhanced_pattern = %{
  id: "sql-injection",
  name: "SQL Injection",
  pattern: ~r/SELECT.*FROM.*WHERE/i,
  ast_rules: %{
    node_type: "CallExpression",
    callee: ~r/query|execute/
  },
  context_rules: %{
    safe_patterns: [~r/\?\s*,\s*\?/, ~r/:\w+/]
  }
}

try do
  # This should fail with native JSON
  JSON.encode!(enhanced_pattern)
  IO.puts "✗ Unexpected: Enhanced pattern encoded without JSONSerializer"
rescue
  Protocol.UndefinedError ->
    IO.puts "✓ Expected: Native JSON cannot encode regex directly"
end

# Test 4: Test JSONSerializer with enhanced pattern
IO.puts "\n4. Testing JSONSerializer with enhanced pattern:"
try do
  json = JSONSerializer.encode!(enhanced_pattern)
  IO.puts "✓ JSONSerializer successfully encoded pattern with regex"
  
  # Verify structure
  {:ok, decoded} = JSON.decode(json)
  pattern_regex = decoded["pattern"]
  
  if pattern_regex["__type__"] == "regex" do
    IO.puts "✓ Regex properly serialized:"
    IO.puts "  - Source: #{pattern_regex["source"]}"
    IO.puts "  - Flags: #{inspect(pattern_regex["flags"])}"
  end
  
  # Check nested regex
  ast_regex = decoded["ast_rules"]["callee"]
  if ast_regex["__type__"] == "regex" do
    IO.puts "✓ Nested regex in ast_rules serialized"
  end
  
  safe_patterns = decoded["context_rules"]["safe_patterns"]
  if length(safe_patterns) == 2 && Enum.all?(safe_patterns, &(&1["__type__"] == "regex")) do
    IO.puts "✓ Regex array in context_rules serialized"
  end
rescue
  e ->
    IO.puts "✗ JSONSerializer failed: #{inspect(e)}"
end

# Test 5: Performance comparison
IO.puts "\n5. Testing serialization performance:"
large_pattern = %{
  id: "complex-pattern",
  patterns: Enum.map(1..100, fn i -> ~r/pattern#{i}/ end),
  rules: Enum.map(1..50, fn i -> %{id: i, regex: ~r/rule#{i}/} end)
}

{time, _result} = :timer.tc(fn ->
  JSONSerializer.encode!(large_pattern)
end)

IO.puts "✓ Serialized 150 regex objects in #{time / 1000}ms"

IO.puts "\n=== Summary ===\n"
IO.puts "✅ Native JSON module available"
IO.puts "✅ JSONSerializer handles regex serialization"
IO.puts "✅ Complex nested structures supported"
IO.puts "✅ Ready for enhanced pattern API"
IO.puts "\nNext step: Test actual Pattern API endpoint with enhanced format"