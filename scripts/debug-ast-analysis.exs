#!/usr/bin/env elixir

# Debug script to test AST analysis directly

require Logger

# Start necessary applications
Application.ensure_all_started(:rsolv)

# Test vulnerable JavaScript code
vulnerable_js = """
const userId = req.params.id;
const query = "SELECT * FROM users WHERE id = " + userId;
db.query(query, (err, results) => {
  res.json(results);
});
"""

# Create a test file structure
test_file = %{
  path: "test.js",
  content: vulnerable_js,
  language: "javascript",
  metadata: %{}
}

# Test the analysis service directly
alias Rsolv.AST.AnalysisService

IO.puts("Testing AST Analysis Service...\n")

# Start the analysis service if not running
case Process.whereis(Rsolv.AST.AnalysisService) do
  nil -> 
    IO.puts("Starting AnalysisService...")
    {:ok, _} = Rsolv.AST.AnalysisService.start_link()
  _ -> 
    IO.puts("AnalysisService already running")
end

# Test pattern loading
alias Rsolv.AST.PatternAdapter
patterns = PatternAdapter.load_patterns_for_language("javascript")
IO.puts("Loaded #{length(patterns)} patterns for JavaScript")

# Show a sample pattern
if length(patterns) > 0 do
  pattern = hd(patterns)
  IO.puts("\nSample pattern:")
  IO.inspect(pattern, pretty: true, limit: 5)
end

# Test file analysis
IO.puts("\n\nAnalyzing vulnerable code...")
case AnalysisService.analyze_file(test_file, %{"includeSecurityPatterns" => true}) do
  {:ok, findings} ->
    IO.puts("Analysis completed!")
    IO.puts("Found #{length(findings)} vulnerabilities:\n")
    
    Enum.each(findings, fn finding ->
      IO.puts("- #{finding.patternName} (#{finding.severity})")
      IO.puts("  Type: #{finding.type}")
      IO.puts("  Confidence: #{finding.confidence}")
      IO.puts("  Location: Line #{finding.location.startLine}")
      IO.puts("  Recommendation: #{finding.recommendation}")
      IO.puts("")
    end)
    
  {:error, reason} ->
    IO.puts("Analysis failed: #{inspect(reason)}")
end

# Test with safe code
IO.puts("\n\nTesting safe code...")
safe_js = """
const userId = req.params.id;
const query = "SELECT * FROM users WHERE id = ?";
db.query(query, [userId], (err, results) => {
  res.json(results);
});
"""

safe_file = %{
  path: "safe.js",
  content: safe_js,
  language: "javascript",
  metadata: %{}
}

case AnalysisService.analyze_file(safe_file, %{"includeSecurityPatterns" => true}) do
  {:ok, findings} ->
    if length(findings) == 0 do
      IO.puts("✅ Correctly identified safe code (no vulnerabilities)")
    else
      IO.puts("⚠️  Found #{length(findings)} false positives")
    end
    
  {:error, reason} ->
    IO.puts("Analysis failed: #{inspect(reason)}")
end

# Test AST parsing directly
IO.puts("\n\nTesting AST parsing...")
alias Rsolv.AST.ParserRegistry
alias Rsolv.AST.SessionManager

{:ok, session} = SessionManager.create_session("debug-test")

case ParserRegistry.parse_code(session.id, "debug", "javascript", vulnerable_js) do
  {:ok, parse_result} ->
    if parse_result.error do
      IO.puts("Parse error: #{parse_result.error}")
    else
      IO.puts("✅ Successfully parsed JavaScript code")
      IO.puts("AST nodes: #{inspect(Map.keys(parse_result.ast), pretty: true)}")
    end
  {:error, reason} ->
    IO.puts("❌ Parser failed: #{inspect(reason)}")
end

# Test pattern matching directly
IO.puts("\n\nTesting pattern matching...")
alias Rsolv.AST.ASTPatternMatcher

if length(patterns) > 0 do
  # Get a SQL injection pattern
  sql_pattern = Enum.find(patterns, fn p -> 
    String.contains?(to_string(p.id), "sql") 
  end)
  
  if sql_pattern do
    IO.puts("Testing with pattern: #{sql_pattern.id}")
    
    # Parse the code first
    case ParserRegistry.parse_code(session.id, "debug", "javascript", vulnerable_js) do
      {:ok, %{ast: ast}} when not is_nil(ast) ->
        # Match the pattern
        case ASTPatternMatcher.match_multiple(ast, [sql_pattern], "javascript") do
          {:ok, matches} ->
            IO.puts("Pattern matching completed!")
            IO.puts("Found #{length(matches)} matches")
            
            Enum.each(matches, fn match ->
              IO.puts("\nMatch details:")
              IO.inspect(match, pretty: true, limit: 5)
            end)
            
          error ->
            IO.puts("Pattern matching failed: #{inspect(error)}")
        end
        
      _ ->
        IO.puts("Failed to parse code for pattern matching")
    end
  else
    IO.puts("No SQL injection pattern found")
  end
end