#!/usr/bin/env elixir

# Test to demonstrate Jason encoding failure with regex
IO.puts "=== TDD Red Phase: Demonstrating regex encoding failure ==="

# Test 1: Simple regex encoding
IO.puts "\n1. Testing simple regex encoding with Jason:"
try do
  regex = ~r/test_pattern/
  result = Jason.encode!(regex)
  IO.puts "UNEXPECTED: Encoding succeeded: #{result}"
rescue
  e in Protocol.UndefinedError ->
    IO.puts "✓ Expected failure: #{inspect(e.protocol)} not implemented for #{inspect(e.value)}"
end

# Test 2: Pattern with regex
IO.puts "\n2. Testing pattern with regex:"
try do
  pattern = %{
    id: "sql_injection",
    pattern: ~r/SELECT.*FROM.*WHERE/i,
    severity: :high
  }
  result = Jason.encode!(pattern)
  IO.puts "UNEXPECTED: Encoding succeeded: #{result}"
rescue
  e in Protocol.UndefinedError ->
    IO.puts "✓ Expected failure: Cannot encode pattern containing regex"
end

# Test 3: Native JSON encoding (if available)
IO.puts "\n3. Testing native JSON encoding (Elixir 1.18+):"
if Code.ensure_loaded?(JSON) do
  # Test with prepared data (what we want to achieve)
  prepared = %{
    id: "sql_injection",
    pattern: %{
      "__type__" => "regex",
      "source" => "SELECT.*FROM.*WHERE",
      "flags" => ["i"]
    }
  }
  
  case JSON.encode(prepared) do
    {:ok, json} ->
      IO.puts "✓ Native JSON encoding works with prepared data"
      IO.puts "  Encoded: #{String.slice(json, 0..60)}..."
    {:error, reason} ->
      IO.puts "✗ Native JSON encoding failed: #{inspect(reason)}"
  end
else
  IO.puts "✗ JSON module not available (need Elixir >= 1.18)"
end

IO.puts "\n=== Summary ==="
IO.puts "Current state: Jason cannot encode regex objects"
IO.puts "Solution needed: Implement prepare_for_json/1 to convert regex to serializable format"
IO.puts "Target: Use native JSON.encode! instead of Jason.encode!"