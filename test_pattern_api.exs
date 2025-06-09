#!/usr/bin/env elixir

# Test script to verify the pattern API works with compiled modules
# Run with: elixir test_pattern_api.exs

defmodule PatternApiTester do
  alias RsolvApi.Security
  
  def test_api do
    IO.puts("Testing Pattern API with Compiled Modules")
    IO.puts("=" |> String.duplicate(50))
    
    # Test 1: Get public JavaScript patterns
    IO.puts("\n1. Testing public JavaScript patterns:")
    public_js = Security.list_patterns_by_language_and_tier("javascript", "public")
    IO.puts("   Found #{length(public_js)} public JavaScript patterns")
    
    # Test 2: Get protected Python patterns
    IO.puts("\n2. Testing protected Python patterns:")
    protected_py = Security.list_patterns_by_language_and_tier("python", "protected")
    IO.puts("   Found #{length(protected_py)} protected Python patterns")
    
    # Test 3: Get all accessible patterns for a language
    IO.puts("\n3. Testing accessible patterns with different tiers:")
    all_php = Security.list_patterns_by_language("php", ["public", "protected", "ai"])
    IO.puts("   Found #{length(all_php)} total PHP patterns")
    
    # Test 4: Format patterns for API
    IO.puts("\n4. Testing API formatting:")
    formatted = Security.format_patterns_for_api(Enum.take(public_js, 2))
    IO.puts("   Formatted #{length(formatted)} patterns")
    
    if first = List.first(formatted) do
      IO.puts("   First pattern:")
      IO.puts("     - ID: #{first.id}")
      IO.puts("     - Name: #{first.name}")
      IO.puts("     - Type: #{first.type}")
      IO.puts("     - Severity: #{first.severity}")
      IO.puts("     - CWE: #{first.cweId}")
      IO.puts("     - OWASP: #{first.owaspCategory}")
    end
    
    # Test 5: Count patterns by severity
    IO.puts("\n5. Testing pattern counts by severity:")
    all_js = Security.list_patterns_by_language("javascript", ["public", "protected", "ai", "enterprise"])
    
    severity_counts = all_js
    |> Enum.group_by(& &1.severity)
    |> Enum.map(fn {severity, patterns} -> {severity, length(patterns)} end)
    |> Enum.into(%{})
    
    IO.puts("   JavaScript patterns by severity:")
    Enum.each(severity_counts, fn {severity, count} ->
      IO.puts("     - #{severity}: #{count} patterns")
    end)
    
    IO.puts("\n✅ Pattern API test complete!")
  end
end

# Load required modules
Code.require_file("lib/rsolv_api/security/pattern.ex")
Code.require_file("lib/rsolv_api/security/patterns/javascript.ex")
Code.require_file("lib/rsolv_api/security/patterns/python.ex")
Code.require_file("lib/rsolv_api/security/patterns/java.ex")
Code.require_file("lib/rsolv_api/security/patterns/elixir.ex")
Code.require_file("lib/rsolv_api/security/patterns/php.ex")
Code.require_file("lib/rsolv_api/security/patterns/cve.ex")
Code.require_file("lib/rsolv_api/security.ex")

PatternApiTester.test_api()