#!/usr/bin/env elixir

# Stress test patterns against known vulnerable and secure code
# This script tests all patterns to ensure they correctly identify vulnerabilities

Mix.install([
  {:httpoison, "~> 2.0"},
  {:jason, "~> 1.4"}
])

defmodule PatternStressTest do
  @api_url "https://api.rsolv.dev/api/v1/patterns"
  
  def run do
    IO.puts("Starting pattern stress test...\n")
    
    languages = ["javascript", "python", "ruby", "java", "php", "elixir"]
    
    results = Enum.map(languages, fn lang ->
      IO.puts("Testing #{lang} patterns...")
      test_language_patterns(lang)
    end)
    
    # Also test cross-language patterns
    IO.puts("Testing cross-language patterns...")
    cross_results = test_language_patterns("cross-language")
    
    all_results = results ++ [cross_results]
    
    # Print summary
    print_summary(all_results)
  end
  
  def test_language_patterns(language) do
    case fetch_patterns(language) do
      {:ok, patterns} ->
        results = Enum.map(patterns, &test_pattern/1)
        {language, results}
      {:error, reason} ->
        IO.puts("  ERROR: Failed to fetch #{language} patterns: #{reason}")
        {language, []}
    end
  end
  
  def fetch_patterns(language) do
    url = "#{@api_url}/#{language}"
    
    case HTTPoison.get(url) do
      {:ok, %{status_code: 200, body: body}} ->
        case Jason.decode(body) do
          {:ok, %{"patterns" => patterns}} -> {:ok, patterns}
          {:error, _} -> {:error, "Failed to parse JSON"}
        end
      {:ok, %{status_code: code}} ->
        {:error, "HTTP #{code}"}
      {:error, %{reason: reason}} ->
        {:error, reason}
    end
  end
  
  def test_pattern(pattern) do
    id = pattern["id"]
    # Handle nested patterns.regex structure from API
    regex_source = case pattern do
      %{"patterns" => %{"regex" => regex}} -> regex
      %{"regex" => regex} -> regex
      _ -> nil
    end
    
    # Also check for testCases (camelCase) vs test_cases (snake_case)
    test_cases = pattern["testCases"] || pattern["test_cases"] || %{}
    vulnerable_cases = test_cases["vulnerable"] || []
    safe_cases = test_cases["safe"] || []
    
    # Compile the regex
    regex = case regex_source do
      list when is_list(list) ->
        # For patterns with multiple regexes (like CVE patterns)
        Enum.map(list, &compile_regex/1)
      str when is_binary(str) ->
        compile_regex(str)
      nil ->
        IO.puts("  ⚠ #{id} - No regex found")
        nil
    end
    
    if regex do
      vulnerable_results = test_cases_against_regex(regex, vulnerable_cases, true)
      safe_results = test_cases_against_regex(regex, safe_cases, false)
      
      all_passed = Enum.all?(vulnerable_results ++ safe_results)
      
      if all_passed do
        IO.puts("  ✓ #{id}")
      else
        IO.puts("  ✗ #{id}")
        print_failures(vulnerable_results, safe_results, vulnerable_cases, safe_cases)
      end
      
      %{
        id: id,
        passed: all_passed,
        vulnerable_passed: Enum.count(vulnerable_results, & &1),
        vulnerable_total: length(vulnerable_results),
        safe_passed: Enum.count(safe_results, & &1),
        safe_total: length(safe_results)
      }
    else
      IO.puts("  ✗ #{id} - Failed to compile regex")
      %{
        id: id,
        passed: false,
        vulnerable_passed: 0,
        vulnerable_total: length(vulnerable_cases),
        safe_passed: 0,
        safe_total: length(safe_cases)
      }
    end
  end
  
  def compile_regex(source) when is_binary(source) do
    # The API returns raw regex patterns, not JavaScript-style
    # Try to compile directly first
    case Regex.compile(source) do
      {:ok, regex} -> regex
      {:error, _} -> 
        # Try with case insensitive flag
        case Regex.compile(source, "i") do
          {:ok, regex} -> regex
          {:error, reason} -> 
            IO.puts("    Failed to compile regex: #{inspect(reason)}")
            nil
        end
    end
  end
  
  def compile_regex(_), do: nil
  
  def test_cases_against_regex(regex, cases, should_match) when is_list(regex) do
    # For multiple regexes, any match counts
    Enum.map(cases, fn test_case ->
      matches = Enum.any?(regex, fn r -> 
        r && Regex.match?(r, test_case)
      end)
      matches == should_match
    end)
  end
  
  def test_cases_against_regex(regex, cases, should_match) do
    Enum.map(cases, fn test_case ->
      matches = regex && Regex.match?(regex, test_case)
      matches == should_match
    end)
  end
  
  def print_failures(vulnerable_results, safe_results, vulnerable_cases, safe_cases) do
    Enum.zip(vulnerable_results, vulnerable_cases)
    |> Enum.each(fn {passed, test_case} ->
      unless passed do
        IO.puts("    - Should match (vulnerable): #{inspect(test_case)}")
      end
    end)
    
    Enum.zip(safe_results, safe_cases)
    |> Enum.each(fn {passed, test_case} ->
      unless passed do
        IO.puts("    - Should NOT match (safe): #{inspect(test_case)}")
      end
    end)
  end
  
  def print_summary(results) do
    IO.puts("\n=== SUMMARY ===\n")
    
    {summary_stats, _} = Enum.reduce(results, {%{
      total_patterns: 0,
      total_passed: 0,
      total_vulnerable_tests: 0,
      total_vulnerable_passed: 0,
      total_safe_tests: 0,
      total_safe_passed: 0
    }, []}, fn {language, patterns}, {stats, acc} ->
      lang_total = length(patterns)
      lang_passed = Enum.count(patterns, & &1.passed)
      
      lang_vulnerable_tests = Enum.sum(Enum.map(patterns, & &1.vulnerable_total))
      lang_vulnerable_passed = Enum.sum(Enum.map(patterns, & &1.vulnerable_passed))
      lang_safe_tests = Enum.sum(Enum.map(patterns, & &1.safe_total))
      lang_safe_passed = Enum.sum(Enum.map(patterns, & &1.safe_passed))
      
      new_stats = %{
        total_patterns: stats.total_patterns + lang_total,
        total_passed: stats.total_passed + lang_passed,
        total_vulnerable_tests: stats.total_vulnerable_tests + lang_vulnerable_tests,
        total_vulnerable_passed: stats.total_vulnerable_passed + lang_vulnerable_passed,
        total_safe_tests: stats.total_safe_tests + lang_safe_tests,
        total_safe_passed: stats.total_safe_passed + lang_safe_passed
      }
      
      percentage = if lang_total > 0, do: Float.round(lang_passed / lang_total * 100, 1), else: 0
      
      IO.puts("#{String.pad_trailing(language, 15)} #{lang_passed}/#{lang_total} patterns passed (#{percentage}%)")
      
      if lang_vulnerable_tests + lang_safe_tests > 0 do
        vuln_rate = Float.round(lang_vulnerable_passed / max(lang_vulnerable_tests, 1) * 100, 1)
        safe_rate = Float.round(lang_safe_passed / max(lang_safe_tests, 1) * 100, 1)
        IO.puts("                Vulnerable detection: #{lang_vulnerable_passed}/#{lang_vulnerable_tests} (#{vuln_rate}%)")
        IO.puts("                Safe code rejection: #{lang_safe_passed}/#{lang_safe_tests} (#{safe_rate}%)")
      end
      
      {new_stats, acc}
    end)
    
    IO.puts("\nOVERALL:")
    overall_percentage = if summary_stats.total_patterns > 0, do: Float.round(summary_stats.total_passed / summary_stats.total_patterns * 100, 1), else: 0
    IO.puts("#{summary_stats.total_passed}/#{summary_stats.total_patterns} patterns passed (#{overall_percentage}%)")
    
    if summary_stats.total_vulnerable_tests + summary_stats.total_safe_tests > 0 do
      vuln_rate = Float.round(summary_stats.total_vulnerable_passed / max(summary_stats.total_vulnerable_tests, 1) * 100, 1)
      safe_rate = Float.round(summary_stats.total_safe_passed / max(summary_stats.total_safe_tests, 1) * 100, 1)
      IO.puts("Vulnerable detection rate: #{summary_stats.total_vulnerable_passed}/#{summary_stats.total_vulnerable_tests} (#{vuln_rate}%)")
      IO.puts("Safe code rejection rate: #{summary_stats.total_safe_passed}/#{summary_stats.total_safe_tests} (#{safe_rate}%)")
    end
  end
end

PatternStressTest.run()