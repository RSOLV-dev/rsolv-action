#\!/usr/bin/env elixir

# Analyze pattern failures and generate a report

Mix.install([
  {:httpoison, "~> 2.0"},
  {:jason, "~> 1.4"}
])

defmodule FailureAnalyzer do
  @api_url "https://api.rsolv.dev/api/v1/patterns"
  
  def analyze do
    languages = ["javascript", "python", "ruby", "java", "php", "elixir", "cross-language"]
    
    all_failures = Enum.flat_map(languages, fn lang ->
      case fetch_patterns(lang) do
        {:ok, patterns} ->
          patterns
          |> Enum.map(&test_pattern/1)
          |> Enum.filter(fn result -> not result.passed end)
          |> Enum.map(fn result -> Map.put(result, :language, lang) end)
        {:error, _} -> []
      end
    end)
    
    # Group failures by type
    critical_failures = Enum.filter(all_failures, fn f -> f.severity == "critical" end)
    high_failures = Enum.filter(all_failures, fn f -> f.severity == "high" end)
    
    IO.puts("\n=== CRITICAL PATTERN FAILURES ===\n")
    Enum.each(critical_failures, &print_failure/1)
    
    IO.puts("\n=== HIGH SEVERITY PATTERN FAILURES ===\n")
    Enum.each(high_failures, &print_failure/1)
    
    IO.puts("\n=== SUMMARY ===")
    IO.puts("Critical failures: #{length(critical_failures)}")
    IO.puts("High severity failures: #{length(high_failures)}")
    IO.puts("Total failures: #{length(all_failures)}")
  end
  
  def fetch_patterns(language) do
    url = "#{@api_url}/#{language}"
    
    case HTTPoison.get(url) do
      {:ok, %{status_code: 200, body: body}} ->
        case Jason.decode(body) do
          {:ok, %{"patterns" => patterns}} -> {:ok, patterns}
          {:error, _} -> {:error, "Failed to parse JSON"}
        end
      _ -> {:error, "Failed to fetch"}
    end
  end
  
  def test_pattern(pattern) do
    id = pattern["id"]
    severity = pattern["severity"]
    regex_source = case pattern do
      %{"patterns" => %{"regex" => regex}} -> regex
      %{"regex" => regex} -> regex
      _ -> nil
    end
    
    test_cases = pattern["testCases"] || pattern["test_cases"] || %{}
    vulnerable_cases = test_cases["vulnerable"] || []
    safe_cases = test_cases["safe"] || []
    
    regex = compile_regex(regex_source)
    
    if regex do
      vulnerable_results = test_cases_against_regex(regex, vulnerable_cases, true)
      safe_results = test_cases_against_regex(regex, safe_cases, false)
      
      vulnerable_failures = Enum.zip(vulnerable_results, vulnerable_cases)
        |> Enum.filter(fn {passed, _} -> not passed end)
        |> Enum.map(fn {_, test_case} -> {:vulnerable, test_case} end)
        
      safe_failures = Enum.zip(safe_results, safe_cases)
        |> Enum.filter(fn {passed, _} -> not passed end)
        |> Enum.map(fn {_, test_case} -> {:safe, test_case} end)
      
      all_failures = vulnerable_failures ++ safe_failures
      
      %{
        id: id,
        severity: severity,
        passed: Enum.empty?(all_failures),
        failures: all_failures,
        regex_source: regex_source
      }
    else
      %{
        id: id,
        severity: severity,
        passed: false,
        failures: [{:regex_compile, "Failed to compile regex"}],
        regex_source: regex_source
      }
    end
  end
  
  def compile_regex(source) when is_list(source) do
    compiled = Enum.map(source, &compile_single_regex/1)
    if Enum.all?(compiled, & &1), do: compiled, else: nil
  end
  
  def compile_regex(source), do: compile_single_regex(source)
  
  def compile_single_regex(source) when is_binary(source) do
    case Regex.compile(source) do
      {:ok, regex} -> regex
      {:error, _} -> 
        case Regex.compile(source, "i") do
          {:ok, regex} -> regex
          {:error, _} -> nil
        end
    end
  end
  
  def compile_single_regex(_), do: nil
  
  def test_cases_against_regex(regex, cases, should_match) when is_list(regex) do
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
  
  def print_failure(failure) do
    IO.puts("Pattern: #{failure.id} (#{failure.language})")
    IO.puts("Severity: #{failure.severity}")
    IO.puts("Regex: #{inspect(failure.regex_source)}")
    IO.puts("Failures:")
    Enum.each(failure.failures, fn
      {:vulnerable, test_case} ->
        IO.puts("  - Should match (vulnerable): #{inspect(test_case)}")
      {:safe, test_case} ->
        IO.puts("  - Should NOT match (safe): #{inspect(test_case)}")
      {:regex_compile, msg} ->
        IO.puts("  - #{msg}")
    end)
    IO.puts("")
  end
end

FailureAnalyzer.analyze()
