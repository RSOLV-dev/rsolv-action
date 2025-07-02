#!/usr/bin/env elixir

# Test pattern detection for SQL injection

alias RsolvApi.AST.{ParserRegistry, SessionManager, AnalysisService, PatternAdapter}

# Start required services
Application.ensure_all_started(:rsolv_api)

# Wait for services to start
Process.sleep(1000)

# Create session
{:ok, session} = SessionManager.create_session("test-customer")

# Test SQL injection code
code = """
function test() {
  const query = "SELECT * FROM users WHERE id = " + userId;
  db.query(query);
}
"""

file = %{
  path: "test.js",
  content: code,
  language: "javascript",
  metadata: %{}
}

options = %{
  "includeSecurityPatterns" => true,
  "patternFormat" => "enhanced"
}

# First check if patterns are loaded
patterns = PatternAdapter.load_patterns_for_language("javascript")
IO.puts("Loaded #{length(patterns)} JavaScript patterns")

# Look for SQL injection patterns
sql_patterns = Enum.filter(patterns, fn p -> 
  Map.get(p, :type) == "sql_injection" || 
  Map.get(p, :pattern_type) == "sql_injection" || 
  String.contains?(to_string(Map.get(p, :id, "")), "sql")
end)
IO.puts("\nFound #{length(sql_patterns)} SQL injection patterns:")
Enum.each(sql_patterns, fn p ->
  IO.puts("  - #{p.id}: #{p.name}")
end)

# Analyze the file
{:ok, results} = AnalysisService.analyze_batch([file], options, session)
result = hd(results)

IO.puts("\nAnalysis result:")
IO.inspect(result, pretty: true)

# Check findings
IO.puts("\nFindings: #{length(result.findings)}")
Enum.each(result.findings, fn finding ->
  IO.puts("  - #{finding.type}: #{finding.patternName} (confidence: #{finding.confidence})")
end)

# Cleanup
SessionManager.delete_session(session.id, "test-customer")