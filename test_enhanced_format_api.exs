#!/usr/bin/env elixir

# Test the enhanced format API endpoint

IO.puts "=== Testing Enhanced Format API ===\n"

# Use HTTPoison or curl to test the API
{output, exit_code} = System.cmd("curl", [
  "-s",
  "-H", "Content-Type: application/json",
  "http://localhost:4000/api/v1/patterns?language=javascript&format=enhanced"
], stderr_to_stdout: true)

IO.puts "1. Testing enhanced format without API key:"
if exit_code == 0 do
  try do
    response = JSON.decode!(output)
    
    if response["error"] do
      IO.puts "   ✗ Error response: #{response["error"]}"
    else
      patterns = response["patterns"] || []
      metadata = response["metadata"] || %{}
      
      IO.puts "   ✓ Successfully retrieved patterns"
      IO.puts "   - Pattern count: #{length(patterns)}"
      IO.puts "   - Format: #{metadata["format"]}"
      IO.puts "   - Enhanced: #{metadata["enhanced"]}"
      
      # Check if patterns have enhanced fields
      if length(patterns) > 0 do
        first_pattern = List.first(patterns)
        has_ast_rules = Map.has_key?(first_pattern, "astRules") || Map.has_key?(first_pattern, "ast_rules")
        has_context_rules = Map.has_key?(first_pattern, "contextRules") || Map.has_key?(first_pattern, "context_rules")
        
        IO.puts "   - First pattern has AST rules: #{has_ast_rules}"
        IO.puts "   - First pattern has context rules: #{has_context_rules}"
        
        # Check for regex serialization
        if first_pattern["pattern"] && is_map(first_pattern["pattern"]) do
          IO.puts "   - Pattern field is serialized: #{first_pattern["pattern"]["__type__"] == "regex"}"
        end
      end
    end
  rescue
    e ->
      IO.puts "   ✗ Failed to parse response: #{inspect(e)}"
      IO.puts "   Response: #{String.slice(output, 0..200)}..."
  end
else
  IO.puts "   ✗ Failed to connect to API (exit code: #{exit_code})"
  IO.puts "   Error: #{output}"
end

# Test with API key
IO.puts "\n2. Testing enhanced format with API key:"
test_api_key = "rsolv_test_abc123"

{output2, exit_code2} = System.cmd("curl", [
  "-s",
  "-H", "Content-Type: application/json",
  "-H", "Authorization: Bearer #{test_api_key}",
  "http://localhost:4000/api/v1/patterns?language=elixir&format=enhanced"
], stderr_to_stdout: true)

if exit_code2 == 0 do
  try do
    response2 = JSON.decode!(output2)
    
    if response2["error"] do
      IO.puts "   ✗ Error response: #{response2["error"]}"
    else
      patterns2 = response2["patterns"] || []
      metadata2 = response2["metadata"] || %{}
      
      IO.puts "   ✓ Successfully retrieved patterns"
      IO.puts "   - Pattern count: #{length(patterns2)}"
      IO.puts "   - Access level: #{metadata2["access_level"]}"
      IO.puts "   - Language: #{metadata2["language"]}"
      
      # Check a pattern that likely has regex
      sql_pattern = Enum.find(patterns2, fn p -> 
        String.contains?(p["id"] || "", "sql") 
      end)
      
      if sql_pattern do
        IO.puts "   - Found SQL pattern: #{sql_pattern["id"]}"
        if sql_pattern["regex"] && is_list(sql_pattern["regex"]) && length(sql_pattern["regex"]) > 0 do
          first_regex = List.first(sql_pattern["regex"])
          if is_map(first_regex) && first_regex["__type__"] == "regex" do
            IO.puts "   ✓ Regex properly serialized with JSONSerializer"
          else
            IO.puts "   - Regex format: #{inspect(first_regex)}"
          end
        end
      end
    end
  rescue
    e ->
      IO.puts "   ✗ Failed to parse response: #{inspect(e)}"
  end
else
  IO.puts "   ✗ Failed to connect to API"
end

IO.puts "\n=== Summary ===\n"
IO.puts "Note: If the API is not running, start it with: mix phx.server"
IO.puts "Expected behavior:"
IO.puts "- Enhanced format should return successfully (no 500 error)"
IO.puts "- Patterns should include astRules and contextRules"
IO.puts "- Regex fields should be serialized as maps with __type__: 'regex'"