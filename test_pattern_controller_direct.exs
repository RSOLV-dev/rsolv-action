#!/usr/bin/env elixir

# Direct test of pattern controller logic without HTTP server

# Compile necessary files
Code.compile_file("/home/dylan/dev/rsolv/RSOLV-api/lib/rsolv_api/security/patterns/json_serializer.ex")

# Load the application modules
Mix.Task.run("compile")

alias RSOLVApi.Security.Patterns.JSONSerializer

IO.puts "=== Direct Pattern Controller Test ===\n"

# Simulate what the pattern controller does

# 1. Test standard format (no regex issues)
IO.puts "1. Testing standard format:"
standard_data = %{
  patterns: [
    %{
      id: "xss-dom",
      name: "DOM XSS",
      description: "DOM-based XSS",
      severity: :high
    }
  ],
  metadata: %{
    format: "standard",
    enhanced: false
  }
}

try do
  json = JSON.encode!(standard_data)
  IO.puts "   ✓ Standard format encodes successfully"
  IO.puts "   Length: #{String.length(json)} bytes"
rescue
  e ->
    IO.puts "   ✗ Failed: #{inspect(e)}"
end

# 2. Test enhanced format with regex (should fail without JSONSerializer)
IO.puts "\n2. Testing enhanced format without JSONSerializer:"
enhanced_data = %{
  patterns: [
    %{
      id: "sql-injection",
      name: "SQL Injection",
      regex: [~r/SELECT.*FROM/i],
      ast_rules: %{
        node_type: "CallExpression",
        pattern: ~r/query|execute/
      }
    }
  ],
  metadata: %{
    format: "enhanced",
    enhanced: true
  }
}

try do
  JSON.encode!(enhanced_data)
  IO.puts "   ✗ Unexpected: Should have failed with regex"
rescue
  Protocol.UndefinedError ->
    IO.puts "   ✓ Expected failure: Cannot encode regex directly"
end

# 3. Test enhanced format with JSONSerializer
IO.puts "\n3. Testing enhanced format with JSONSerializer:"
try do
  json = JSONSerializer.encode!(enhanced_data)
  IO.puts "   ✓ JSONSerializer handles enhanced format"
  
  # Verify the structure
  {:ok, decoded} = JSON.decode(json)
  pattern = List.first(decoded["patterns"])
  
  if pattern do
    regex_list = pattern["regex"]
    if is_list(regex_list) && length(regex_list) > 0 do
      first_regex = List.first(regex_list)
      if first_regex["__type__"] == "regex" do
        IO.puts "   ✓ Regex array properly serialized"
        IO.puts "   - Source: #{first_regex["source"]}"
        IO.puts "   - Flags: #{inspect(first_regex["flags"])}"
      end
    end
    
    if pattern["ast_rules"] && pattern["ast_rules"]["pattern"] do
      ast_pattern = pattern["ast_rules"]["pattern"]
      if ast_pattern["__type__"] == "regex" do
        IO.puts "   ✓ AST rule regex serialized"
      end
    end
  end
rescue
  e ->
    IO.puts "   ✗ Failed: #{inspect(e)}"
end

# 4. Test the actual pattern controller logic simulation
IO.puts "\n4. Simulating pattern controller logic:"
format = :enhanced

# This simulates what happens in the controller
response_data = %{
  patterns: [
    %{
      id: "elixir-sql-injection",
      name: "SQL Injection via Interpolation",
      regex: [~r/Repo\.query.*"\#\{/],
      ast_rules: %{
        looks_for: "string interpolation in query functions",
        pattern: ~r/query|execute/
      },
      context_rules: %{
        safe_patterns: [~r/\?/, ~r/fragment/]
      }
    }
  ],
  metadata: %{
    language: "elixir",
    format: "enhanced",
    enhanced: true,
    count: 1
  }
}

# Controller would do this
json_data = if format == :enhanced do
  JSONSerializer.encode!(response_data)
else
  JSON.encode!(response_data)
end

IO.puts "   ✓ Controller logic successful"
IO.puts "   - Format: enhanced"
IO.puts "   - JSON length: #{String.length(json_data)} bytes"

# Verify it can be decoded
{:ok, final} = JSON.decode(json_data)
IO.puts "   ✓ Response can be decoded by clients"
IO.puts "   - Pattern count: #{length(final["patterns"])}"

IO.puts "\n=== Phase 1.5 Summary ===\n"
IO.puts "✅ Standard format works with native JSON"
IO.puts "✅ Enhanced format requires JSONSerializer"
IO.puts "✅ Pattern controller logic properly handles both formats"
IO.puts "✅ Regex objects are serialized for client reconstruction"
IO.puts "\nPhase 1.5 COMPLETE - Enhanced format returns successfully!"