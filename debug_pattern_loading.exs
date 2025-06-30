#!/usr/bin/env mix run

# Debug script to test pattern loading for AST analysis
# Run with: mix run debug_pattern_loading.exs

require Logger

alias RsolvApi.AST.PatternAdapter

IO.puts "🔍 Debug: Testing Pattern Loading for AST Analysis"
IO.puts String.duplicate("=", 60)

# Test pattern loading for Python
IO.puts "\n📊 Testing Python pattern loading..."

try do
  patterns = PatternAdapter.load_patterns_for_language("python")
  IO.puts "   ✅ Successfully loaded #{length(patterns)} Python patterns"
  
  # Look for SQL injection patterns specifically
  sql_patterns = Enum.filter(patterns, fn pattern ->
    String.contains?(pattern.id || "", "sql") || 
    String.contains?(String.downcase(pattern.title || ""), "sql")
  end)
  
  IO.puts "   📋 Found #{length(sql_patterns)} SQL-related patterns:"
  
  for pattern <- Enum.take(sql_patterns, 5) do
    IO.puts "      - #{pattern.id}: #{pattern.title}"
    IO.puts "        Severity: #{pattern.severity}"
    
    if Map.has_key?(pattern, :ast_rules) && pattern.ast_rules do
      IO.puts "        AST Rules: #{inspect(Map.keys(pattern.ast_rules))}"
    end
    
    if Map.has_key?(pattern, :context_rules) && pattern.context_rules do
      IO.puts "        Context Rules: #{inspect(Map.keys(pattern.context_rules))}"
    end
  end
  
  # Test a specific pattern that should detect SQL concatenation
  concat_patterns = Enum.filter(patterns, fn pattern ->
    pattern.id == "py-sql-injection-concat" || 
    String.contains?(pattern.id || "", "concat") ||
    String.contains?(String.downcase(pattern.title || ""), "concat")
  end)
  
  IO.puts "\n🎯 SQL concatenation patterns: #{length(concat_patterns)}"
  for pattern <- concat_patterns do
    IO.puts "   - #{pattern.id}: #{pattern.title}"
    if pattern.ast_rules do
      IO.puts "     AST Rules Keys: #{inspect(Map.keys(pattern.ast_rules))}"
    end
  end
  
rescue
  error ->
    IO.puts "   ❌ Error loading Python patterns: #{inspect(error)}"
    IO.puts "   Stack trace:"
    IO.puts Exception.format_stacktrace(__STACKTRACE__)
end

# Test the enhanced pattern API directly
IO.puts "\n🔧 Testing Enhanced Pattern API directly..."

try do
  # This is what the AST controller should use
  case RsolvApi.Security.PatternServer.list_patterns("python", "enhanced") do
    {:ok, api_patterns} ->
      IO.puts "   ✅ Pattern API returned #{length(api_patterns)} patterns"
      
      # Check if we have the right format
      sample = List.first(api_patterns)
      if sample do
        IO.puts "   📋 Sample pattern structure:"
        IO.puts "      ID: #{sample[:id]}"
        IO.puts "      Title: #{sample[:title]}"
        IO.puts "      Has AST rules: #{Map.has_key?(sample, :ast_rules)}"
        IO.puts "      Has context rules: #{Map.has_key?(sample, :context_rules)}"
      end
      
    {:error, reason} ->
      IO.puts "   ❌ Pattern API error: #{inspect(reason)}"
  end
rescue
  error ->
    IO.puts "   ❌ Error calling Pattern API: #{inspect(error)}"
    IO.puts "   Stack trace:"
    IO.puts Exception.format_stacktrace(__STACKTRACE__)
end

# Test AST pattern matcher directly
IO.puts "\n🧪 Testing AST Pattern Matcher directly..."

try do
  # Create a simple AST for our test case
  test_ast = %{
    "type" => "Module",
    "body" => [
      %{
        "type" => "Assign",
        "targets" => [%{"type" => "Name", "id" => "query"}],
        "value" => %{
          "type" => "BinOp",
          "left" => %{"type" => "Constant", "value" => "SELECT * FROM users WHERE id = "},
          "op" => %{"type" => "Add"},
          "right" => %{"type" => "Name", "id" => "user_id"}
        }
      }
    ]
  }
  
  patterns = PatternAdapter.load_patterns_for_language("python")
  
  if length(patterns) > 0 do
    alias RsolvApi.AST.ASTPatternMatcher
    
    IO.puts "   🎯 Testing pattern matching against sample AST..."
    
    case ASTPatternMatcher.match_multiple(test_ast, patterns, "python") do
      {:ok, matches} ->
        IO.puts "   ✅ Pattern matching completed successfully"
        IO.puts "   🔍 Found #{length(matches)} matches:"
        
        for match <- matches do
          IO.puts "      - Type: #{match.type}"
          IO.puts "        Pattern ID: #{match.pattern_id || 'N/A'}"
          IO.puts "        Location: Line #{match.line || 'N/A'}, Col #{match.column || 'N/A'}"
          if match.context do
            IO.puts "        Context: #{inspect(match.context)}"
          end
        end
        
      {:error, reason} ->
        IO.puts "   ❌ Pattern matching failed: #{inspect(reason)}"
    end
  else
    IO.puts "   ⚠️  No patterns loaded for testing"
  end
  
rescue
  error ->
    IO.puts "   ❌ Error testing AST matcher: #{inspect(error)}"
    IO.puts "   Stack trace:"
    IO.puts Exception.format_stacktrace(__STACKTRACE__)
end

IO.puts "\n✅ Debug script completed!"
IO.puts "\nNext steps:"
IO.puts "1. Check if pattern loading is working correctly"
IO.puts "2. Verify AST pattern matcher can find vulnerabilities"
IO.puts "3. Test the full AST analysis pipeline"