#!/usr/bin/env elixir

# Test script to verify tier field is included in all pattern API responses

IO.puts "Testing tier field inclusion in pattern API responses..."
IO.puts "=" |> String.duplicate(60)

# Compile the necessary modules
Code.require_file("lib/rsolv_api/security/pattern.ex")
Code.require_file("lib/rsolv_api/security.ex")

# Create test patterns
test_patterns = [
  %RsolvApi.Security.Pattern{
    id: "test-sql-injection",
    name: "SQL Injection Test",
    description: "Test pattern for SQL injection",
    type: :sql_injection,
    severity: :high,
    languages: ["javascript"],
    regex: ~r/query.*concat/,
    default_tier: :protected,
    cwe_id: "CWE-89",
    owasp_category: "A03:2021",
    recommendation: "Use parameterized queries",
    test_cases: %{
      vulnerable: ["query + userInput"],
      safe: ["query.prepare(userInput)"]
    }
  },
  %RsolvApi.Security.Pattern{
    id: "test-xss",
    name: "XSS Test",
    description: "Test pattern for XSS",
    type: :xss,
    severity: :medium,
    languages: ["javascript"],
    regex: ~r/innerHTML.*=/,
    default_tier: :public,
    cwe_id: "CWE-79",
    owasp_category: "A03:2021",
    recommendation: "Use textContent instead",
    test_cases: %{
      vulnerable: ["elem.innerHTML = userInput"],
      safe: ["elem.textContent = userInput"]
    }
  }
]

# Test format_patterns_for_api
IO.puts "\n1. Testing Security.format_patterns_for_api/1:"
formatted = RsolvApi.Security.format_patterns_for_api(test_patterns)

Enum.each(formatted, fn pattern ->
  IO.puts "\nPattern: #{pattern.id}"
  IO.puts "  Name: #{pattern.name}"
  IO.puts "  Severity: #{pattern.severity}"
  IO.puts "  Tier: #{inspect(pattern[:tier])}"
  
  if pattern[:tier] do
    IO.puts "  ✓ Tier field is present!"
  else
    IO.puts "  ✗ Tier field is MISSING!"
  end
end)

# Test Pattern.to_api_format
IO.puts "\n\n2. Testing Pattern.to_api_format/1:"
Enum.each(test_patterns, fn pattern ->
  api_format = RsolvApi.Security.Pattern.to_api_format(pattern)
  IO.puts "\nPattern: #{api_format.id}"
  IO.puts "  Tier: #{inspect(api_format[:tier])}"
  
  if api_format[:tier] do
    IO.puts "  ✓ Tier field is present!"
  else
    IO.puts "  ✗ Tier field is MISSING!"
  end
end)

IO.puts "\n" <> ("=" |> String.duplicate(60))
IO.puts "Test complete!"