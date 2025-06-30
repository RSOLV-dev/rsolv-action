#!/usr/bin/env elixir

# Debug script to understand why AST service isn't detecting vulnerabilities

# Start required services
{:ok, _} = Application.ensure_all_started(:rsolv_api)

alias RsolvApi.AST.{AnalysisService, SessionManager, ParserRegistry, PatternAdapter, ASTPatternMatcher}
alias RsolvApi.Security.PatternRegistry

# Ensure services are started
unless GenServer.whereis(SessionManager), do: SessionManager.start_link()
unless GenServer.whereis(ParserRegistry), do: ParserRegistry.start_link()
unless GenServer.whereis(AnalysisService), do: AnalysisService.start_link()

IO.puts("\n=== DEBUG: AST Vulnerability Detection ===\n")

# Test code with SQL injection
test_code = """
function handleRequest(userInput) {
  const query = "SELECT * FROM users WHERE id = " + userInput;
  db.query(query);
}
"""

IO.puts("Test code:")
IO.puts(test_code)

# 1. Test pattern loading
IO.puts("\n1. Testing pattern loading...")
patterns = PatternRegistry.get_patterns_for_language("javascript")
IO.puts("  Loaded #{length(patterns)} JavaScript patterns")

sql_patterns = Enum.filter(patterns, &String.contains?(&1.id, "sql"))
IO.puts("  SQL patterns: #{Enum.map(sql_patterns, & &1.id) |> inspect()}")

# 2. Test pattern adapter
IO.puts("\n2. Testing pattern adapter...")
adapted_patterns = PatternAdapter.load_patterns_for_language("javascript")
IO.puts("  Adapted #{length(adapted_patterns)} patterns")

sql_adapted = Enum.filter(adapted_patterns, &String.contains?(&1.id, "sql"))
IO.puts("  SQL adapted patterns: #{length(sql_adapted)}")

if length(sql_adapted) > 0 do
  first_sql = List.first(sql_adapted)
  IO.puts("  First SQL pattern structure:")
  IO.inspect(first_sql, pretty: true, limit: :infinity)
end

# 3. Test AST parsing
IO.puts("\n3. Testing AST parsing...")
{:ok, session} = SessionManager.create_session("debug")
result = ParserRegistry.parse_code(session.id, "debug", "javascript", test_code)

case result do
  {:ok, parse_result} ->
    IO.puts("  ✅ Parse successful")
    IO.puts("  AST node count: #{inspect(parse_result.ast |> inspect() |> String.length())} chars")
    
    # Show first few nodes
    IO.puts("\n  AST structure preview:")
    ast_str = inspect(parse_result.ast, pretty: true, limit: 10)
    IO.puts(String.slice(ast_str, 0, 1000) <> "...")
    
    # Look for BinaryExpression nodes
    ast_json = Jason.encode!(parse_result.ast)
    if String.contains?(ast_json, "BinaryExpression") do
      IO.puts("  ✅ Found BinaryExpression nodes")
    else
      IO.puts("  ❌ No BinaryExpression nodes found")
      # Check what concatenation looks like
      if String.contains?(ast_json, "+") do
        IO.puts("  ℹ️  Found + operator in AST")
      end
    end
    
    # 4. Test pattern matching directly
    IO.puts("\n4. Testing pattern matching...")
    
    if length(adapted_patterns) > 0 do
      {:ok, matches} = ASTPatternMatcher.match_multiple(parse_result.ast, adapted_patterns, "javascript")
      IO.puts("  Matches found: #{length(matches)}")
      
      if length(matches) > 0 do
        IO.puts("  ✅ Vulnerabilities detected!")
        Enum.each(matches, fn match ->
          IO.puts("    - #{match.pattern_id}: #{match.pattern_name}")
        end)
      else
        IO.puts("  ❌ No vulnerabilities detected")
        
        # Debug: Try matching with just the SQL pattern
        sql_pattern = Enum.find(adapted_patterns, &String.contains?(&1.id, "sql-injection-concat"))
        if sql_pattern do
          IO.puts("\n  Debugging SQL injection pattern specifically...")
          IO.puts("  Pattern AST rules:")
          IO.inspect(sql_pattern.ast_pattern, pretty: true)
          
          # Check if pattern would match anything
          {:ok, sql_matches} = ASTPatternMatcher.match(parse_result.ast, sql_pattern, "javascript")
          IO.puts("  SQL pattern matches: #{length(sql_matches)}")
        end
      end
    end
    
  {:error, reason} ->
    IO.puts("  ❌ Parse failed: #{inspect(reason)}")
end

# 5. Test full analysis service
IO.puts("\n5. Testing full analysis service...")
file = %{
  path: "test.js",
  content: test_code,
  language: "javascript",
  metadata: %{}
}

options = %{
  "patternFormat" => "enhanced",
  "includeSecurityPatterns" => true
}

{:ok, findings} = AnalysisService.analyze_file(file, options)
IO.puts("  Analysis findings: #{length(findings)}")

if length(findings) > 0 do
  IO.puts("  ✅ Analysis service detected vulnerabilities!")
  Enum.each(findings, fn finding ->
    IO.puts("    - #{finding.patternId}: #{finding.patternName} (#{finding.confidence} confidence)")
  end)
else
  IO.puts("  ❌ Analysis service found no vulnerabilities")
end

IO.puts("\n=== DEBUG COMPLETE ===")