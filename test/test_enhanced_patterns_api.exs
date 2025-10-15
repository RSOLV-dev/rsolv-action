#!/usr/bin/env elixir

# RFC-032 Phase 3: Test enhanced patterns are returned correctly
# This script tests that enhanced patterns include AST rules, context rules, and confidence rules

Mix.install([
  {:hackney, "~> 1.18"},
  {:json, "~> 1.4"}
])

defmodule TestEnhancedPatternsAPI do
  def run do
    IO.puts("\n🔍 Testing Enhanced Patterns API...\n")

    # Test API endpoints
    base_url = System.get_env("RSOLV_API_URL", "http://localhost:4000")
    api_key = System.get_env("RSOLV_API_KEY", "demo-key")

    # Test 1: Request patterns with enhanced format
    IO.puts("📡 Testing enhanced format request...")

    case request_patterns(base_url, api_key, "javascript", "enhanced") do
      {:ok, response} ->
        IO.puts("   ✅ Got response from API")
        analyze_enhanced_response(response)

      {:error, reason} ->
        IO.puts("   ❌ API request failed: #{inspect(reason)}")
    end

    # Test 2: Compare with standard format
    IO.puts("\n📊 Comparing standard vs enhanced format...")

    with {:ok, standard} <- request_patterns(base_url, api_key, "javascript", "standard"),
         {:ok, enhanced} <- request_patterns(base_url, api_key, "javascript", "enhanced") do
      compare_formats(standard, enhanced)
    else
      error ->
        IO.puts("   ❌ Comparison failed: #{inspect(error)}")
    end
  end

  defp request_patterns(base_url, api_key, language, format) do
    url = "#{base_url}/api/v1/patterns?language=#{language}&format=#{format}"

    headers = [
      {"Content-Type", "application/json"},
      {"Authorization", "Bearer #{api_key}"}
    ]

    case :hackney.request(:get, url, headers, "", []) do
      {:ok, 200, _headers, body_ref} ->
        {:ok, body} = :hackney.body(body_ref)
        {:ok, JSON.decode!(body)}

      {:ok, status, _headers, body_ref} ->
        {:ok, body} = :hackney.body(body_ref)
        {:error, "HTTP #{status}: #{body}"}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp analyze_enhanced_response(response) do
    patterns = response["patterns"] || []

    IO.puts("   Found #{length(patterns)} patterns")

    # Count patterns with enhanced features
    enhanced_count =
      Enum.count(patterns, fn p ->
        Map.has_key?(p, "ast_rules") or
          Map.has_key?(p, "context_rules") or
          Map.has_key?(p, "confidence_rules")
      end)

    IO.puts("   Patterns with enhanced features: #{enhanced_count}")

    # Analyze a specific pattern
    if eval_pattern =
         Enum.find(patterns, fn p ->
           String.contains?(p["name"] || "", "eval") or
             String.contains?(p["id"] || "", "eval")
         end) do
      IO.puts("\n   📋 Analyzing pattern: #{eval_pattern["name"]}")
      IO.puts("   ID: #{eval_pattern["id"]}")

      # Check for enhanced fields
      if eval_pattern["ast_rules"] do
        IO.puts("   ✅ Has AST rules")
        IO.inspect(eval_pattern["ast_rules"], label: "   AST Rules", limit: 3)
      else
        IO.puts("   ❌ No AST rules")
      end

      if eval_pattern["context_rules"] do
        IO.puts("   ✅ Has context rules")
        IO.inspect(eval_pattern["context_rules"], label: "   Context Rules", limit: 3)
      else
        IO.puts("   ❌ No context rules")
      end

      if eval_pattern["confidence_rules"] do
        IO.puts("   ✅ Has confidence rules")
        IO.puts("   Base confidence: #{eval_pattern["confidence_rules"]["base"]}")
      else
        IO.puts("   ❌ No confidence rules")
      end

      if eval_pattern["min_confidence"] do
        IO.puts("   Min confidence threshold: #{eval_pattern["min_confidence"]}")
      end
    end

    # Check for regex serialization
    IO.puts("\n   🔍 Checking regex serialization...")

    patterns_with_serialized_regex =
      Enum.count(patterns, fn pattern ->
        has_serialized_regex?(pattern)
      end)

    IO.puts("   Patterns with serialized regex: #{patterns_with_serialized_regex}")
  end

  defp has_serialized_regex?(data) when is_map(data) do
    if Map.get(data, "__type__") == "regex" do
      true
    else
      Enum.any?(data, fn {_k, v} -> has_serialized_regex?(v) end)
    end
  end

  defp has_serialized_regex?(data) when is_list(data) do
    Enum.any?(data, &has_serialized_regex?/1)
  end

  defp has_serialized_regex?(_), do: false

  defp compare_formats(standard, enhanced) do
    standard_patterns = standard["patterns"] || []
    enhanced_patterns = enhanced["patterns"] || []

    IO.puts("   Standard format: #{length(standard_patterns)} patterns")
    IO.puts("   Enhanced format: #{length(enhanced_patterns)} patterns")

    # Check if enhanced has additional fields
    sample_standard = List.first(standard_patterns) || %{}
    sample_enhanced = List.first(enhanced_patterns) || %{}

    standard_keys = Map.keys(sample_standard) |> Enum.sort()
    enhanced_keys = Map.keys(sample_enhanced) |> Enum.sort()

    additional_keys = enhanced_keys -- standard_keys

    if length(additional_keys) > 0 do
      IO.puts("   ✅ Enhanced format has additional fields: #{inspect(additional_keys)}")
    else
      IO.puts("   ⚠️  No additional fields in enhanced format")
    end
  end
end

# Run the test
TestEnhancedPatternsAPI.run()
