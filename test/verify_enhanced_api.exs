#!/usr/bin/env elixir

# Test the enhanced format API endpoint
# This verifies that AST enhancement data from pattern modules is properly included

defmodule VerifyEnhancedAPI do
  def run do
    IO.puts("\n🔍 Testing Enhanced Format API Endpoint\n")

    # Start with a simple curl request to test the API
    IO.puts("1️⃣ Testing API without authentication (demo patterns):")

    cmd = """
    curl -s -X GET \
      'http://localhost:4000/api/v1/patterns?language=javascript&format=enhanced' \
      -H 'Accept: application/json'
    """

    case System.cmd("sh", ["-c", cmd]) do
      {output, 0} ->
        case JSON.decode(output) do
          {:ok, data} ->
            IO.puts("   ✅ API responded successfully")
            IO.puts("   Pattern count: #{data["metadata"]["count"]}")
            IO.puts("   Format: #{data["metadata"]["format"]}")
            IO.puts("   Access level: #{data["metadata"]["access_level"]}")

            # Check if patterns have AST enhancement data
            if patterns = data["patterns"] do
              check_patterns_for_ast_data(patterns)
            end

          {:error, reason} ->
            IO.puts("   ❌ Failed to parse JSON: #{inspect(reason)}")
            IO.puts("   Raw output: #{String.slice(output, 0, 200)}...")
        end

      {output, code} ->
        IO.puts("   ❌ API request failed with code #{code}")
        IO.puts("   Output: #{output}")
    end

    IO.puts("\n2️⃣ Testing with API key (full patterns):")

    # Try to find an API key from environment or use a test key
    api_key = System.get_env("RSOLV_API_KEY") || "test-api-key"

    cmd_with_auth = """
    curl -s -X GET \
      'http://localhost:4000/api/v1/patterns?language=javascript&format=enhanced' \
      -H 'Accept: application/json' \
      -H 'Authorization: Bearer #{api_key}'
    """

    case System.cmd("sh", ["-c", cmd_with_auth]) do
      {output, 0} ->
        case JSON.decode(output) do
          {:ok, data} ->
            IO.puts("   ✅ API responded successfully")
            IO.puts("   Pattern count: #{data["metadata"]["count"]}")
            IO.puts("   Access level: #{data["metadata"]["access_level"]}")

            if patterns = data["patterns"] do
              check_patterns_for_ast_data(patterns)
            end

          {:error, _} ->
            IO.puts("   ❌ Failed to parse JSON response")
        end

      {_, code} ->
        IO.puts("   ❌ API request failed with code #{code}")
    end
  end

  defp check_patterns_for_ast_data(patterns) do
    IO.puts("\n   Checking patterns for AST enhancement data:")

    # Look for specific patterns we know have AST enhancement
    known_enhanced = ["js-eval-user-input", "js-sql-injection-concat", "js-xss-dom-manipulation"]

    enhanced_count = 0

    Enum.each(patterns, fn pattern ->
      if pattern["id"] in known_enhanced do
        IO.puts("\n   Pattern: #{pattern["id"]}")

        has_ast_rules = Map.has_key?(pattern, "ast_rules") && pattern["ast_rules"] != nil

        has_context_rules =
          Map.has_key?(pattern, "context_rules") && pattern["context_rules"] != nil

        has_confidence_rules =
          Map.has_key?(pattern, "confidence_rules") && pattern["confidence_rules"] != nil

        has_min_confidence =
          Map.has_key?(pattern, "min_confidence") && pattern["min_confidence"] != nil

        if has_ast_rules || has_context_rules || has_confidence_rules do
          enhanced_count = enhanced_count + 1
          IO.puts("     ✅ Has AST enhancement data!")

          if has_ast_rules,
            do: IO.puts("     - ast_rules: #{inspect(Map.keys(pattern["ast_rules"]))}")

          if has_context_rules,
            do: IO.puts("     - context_rules: #{inspect(Map.keys(pattern["context_rules"]))}")

          if has_confidence_rules, do: IO.puts("     - confidence_rules: present")

          if has_min_confidence,
            do: IO.puts("     - min_confidence: #{pattern["min_confidence"]}")
        else
          IO.puts("     ❌ Missing AST enhancement data")
        end
      end
    end)

    IO.puts("\n   Total patterns with AST enhancement: #{enhanced_count}")
  end
end

# Run the test
VerifyEnhancedAPI.run()
