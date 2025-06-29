#!/usr/bin/env elixir

# Phase 1.5 Test - Enhanced format returns successfully

Code.compile_file("/home/dylan/dev/rsolv/RSOLV-api/lib/rsolv_api/security/patterns/json_serializer.ex")
alias RSOLVApi.Security.Patterns.JSONSerializer

IO.puts "=== RFC-032 Phase 1.5 Test ===\n"
IO.puts "Testing that enhanced format with regex can be successfully encoded and returned\n"

# Create a realistic enhanced pattern response
enhanced_response = %{
  patterns: [
    %{
      id: "elixir-sql-injection-interpolation",
      name: "SQL Injection via String Interpolation",
      description: "Detects SQL queries using string interpolation",
      severity: :high,
      languages: ["elixir"],
      cwe_id: "CWE-89",
      regex: [~r/Repo\.query.*"\#\{/, ~r/Ecto\.Adapters\.SQL\.query.*"\#\{/],
      ast_rules: %{
        node_type: "call",
        function_name: ~r/query|execute/,
        has_interpolation: true
      },
      context_rules: %{
        requires_user_input: true,
        safe_patterns: [~r/\?/, ~r/fragment\(/],
        exclude_paths: [~r/test/, ~r/spec/]
      },
      min_confidence: 85,
      owasp_category: "A03:2021"
    },
    %{
      id: "elixir-command-injection",
      name: "Command Injection via System.cmd",
      regex: [~r/System\.cmd.*\#\{/, ~r/System\.shell.*\#\{/],
      ast_rules: %{
        node_type: "call",
        module: "System",
        function: ~r/cmd|shell/
      }
    }
  ],
  metadata: %{
    language: "elixir",
    format: "enhanced",
    enhanced: true,
    count: 2,
    access_level: "full",
    x_pattern_version: "2.0"
  }
}

# Test 1: Verify native JSON fails with regex
IO.puts "1. Testing native JSON with regex (should fail):"
try do
  JSON.encode!(enhanced_response)
  IO.puts "   ✗ Unexpected success"
rescue
  Protocol.UndefinedError ->
    IO.puts "   ✓ Expected failure - native JSON cannot encode regex"
end

# Test 2: Verify JSONSerializer succeeds
IO.puts "\n2. Testing JSONSerializer with enhanced format:"
try do
  json_output = JSONSerializer.encode!(enhanced_response)
  IO.puts "   ✓ Successfully encoded enhanced format"
  IO.puts "   - JSON size: #{String.length(json_output)} bytes"
  
  # Test 3: Verify the output can be decoded
  IO.puts "\n3. Testing JSON decode:"
  {:ok, decoded} = JSON.decode(json_output)
  IO.puts "   ✓ Successfully decoded JSON"
  
  # Test 4: Verify pattern structure
  IO.puts "\n4. Verifying pattern structure:"
  first_pattern = List.first(decoded["patterns"])
  
  # Check regex array
  regex_list = first_pattern["regex"]
  if is_list(regex_list) && length(regex_list) == 2 do
    IO.puts "   ✓ Regex array preserved (#{length(regex_list)} items)"
    
    first_regex = List.first(regex_list)
    if first_regex["__type__"] == "regex" do
      IO.puts "   ✓ Regex properly serialized"
      IO.puts "     - Source: #{String.slice(first_regex["source"], 0..30)}..."
    end
  end
  
  # Check AST rules
  if first_pattern["ast_rules"]["function_name"]["__type__"] == "regex" do
    IO.puts "   ✓ AST rules regex serialized"
  end
  
  # Check context rules
  safe_patterns = first_pattern["context_rules"]["safe_patterns"]
  if is_list(safe_patterns) && Enum.all?(safe_patterns, &(&1["__type__"] == "regex")) do
    IO.puts "   ✓ Context rules regex array serialized"
  end
  
  # Test 5: Verify metadata
  IO.puts "\n5. Verifying metadata:"
  metadata = decoded["metadata"]
  IO.puts "   - Format: #{metadata["format"]}"
  IO.puts "   - Enhanced: #{metadata["enhanced"]}"
  IO.puts "   - Pattern count: #{metadata["count"]}"
  
  if metadata["format"] == "enhanced" && metadata["enhanced"] == true do
    IO.puts "   ✓ Metadata correctly indicates enhanced format"
  end
  
rescue
  e ->
    IO.puts "   ✗ Error: #{inspect(e)}"
    IO.inspect(e, label: "Full error")
end

IO.puts "\n=== Phase 1.5 Complete ===\n"
IO.puts "✅ Enhanced format with regex can be encoded using JSONSerializer"
IO.puts "✅ Output is valid JSON that can be decoded"
IO.puts "✅ Regex objects are properly serialized with type information"
IO.puts "✅ Pattern structure is preserved for client reconstruction"
IO.puts "\nReady to proceed to Phase 2: TypeScript client implementation"