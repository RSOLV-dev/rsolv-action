#!/usr/bin/env elixir

# Comprehensive Pattern System Verification Script
# This script audits and validates the entire pattern system

Mix.install([
  {:jason, "~> 1.4"},
  {:httpoison, "~> 2.2"}
])

defmodule PatternSystemVerifier do
  @moduledoc """
  Comprehensive verification of the RSOLV pattern system.
  
  This script:
  1. Counts actual patterns across all modules
  2. Validates pattern structure and completeness
  3. Tests pattern detection with vulnerable/safe code
  4. Verifies API endpoints work correctly
  5. Generates accurate metrics for documentation
  """

  def run do
    IO.puts("🔍 RSOLV Pattern System Verification")
    IO.puts("===================================")
    
    results = %{
      pattern_audit: audit_patterns(),
      structure_validation: validate_structure(),
      detection_testing: test_detection(),
      api_verification: verify_api(),
      summary: %{}
    }
    
    summary = generate_summary(results)
    save_results(Map.put(results, :summary, summary))
    
    IO.puts("\n✅ Verification complete!")
    IO.puts("📊 Results saved to verification_results.json")
    
    summary
  end

  defp audit_patterns do
    IO.puts("\n📊 Phase 1: Pattern Count Audit")
    IO.puts("------------------------------")
    
    pattern_modules = [
      {Rsolv.Security.Patterns.Javascript, "javascript"},
      {Rsolv.Security.Patterns.Python, "python"},
      {Rsolv.Security.Patterns.Ruby, "ruby"},
      {Rsolv.Security.Patterns.Java, "java"},
      {Rsolv.Security.Patterns.Php, "php"},
      {Rsolv.Security.Patterns.Elixir, "elixir"},
      {Rsolv.Security.Patterns.Rails, "rails"},
      {Rsolv.Security.Patterns.Django, "django"},
      {Rsolv.Security.Patterns.Cve, "cve"}
    ]
    
    counts = Enum.map(pattern_modules, fn {module, name} ->
      try do
        # Get all exported functions that return patterns
        functions = module.__info__(:functions)
        pattern_functions = Enum.filter(functions, fn {func_name, arity} ->
          arity == 0 and func_name != :__info__
        end)
        
        # Test each function to see if it returns a valid pattern
        valid_patterns = Enum.filter(pattern_functions, fn {func_name, _} ->
          try do
            result = apply(module, func_name, [])
            is_map(result) and Map.has_key?(result, :id) and Map.has_key?(result, :regex)
          rescue
            _ -> false
          end
        end)
        
        count = length(valid_patterns)
        IO.puts("  #{name}: #{count} patterns")
        
        {name, %{
          module: module,
          count: count,
          functions: pattern_functions,
          valid_patterns: valid_patterns
        }}
      rescue
        error ->
          IO.puts("  #{name}: ERROR - #{inspect(error)}")
          {name, %{module: module, count: 0, error: inspect(error)}}
      end
    end)
    
    total = counts |> Enum.map(fn {_, data} -> Map.get(data, :count, 0) end) |> Enum.sum()
    IO.puts("  TOTAL: #{total} patterns")
    
    %{
      by_language: Map.new(counts),
      total_count: total,
      audit_timestamp: DateTime.utc_now()
    }
  end

  defp validate_structure do
    IO.puts("\n🔧 Phase 2: Pattern Structure Validation")
    IO.puts("---------------------------------------")
    
    # Test a sample of patterns for required fields
    sample_patterns = get_sample_patterns()
    
    validations = Enum.map(sample_patterns, fn {name, pattern} ->
      required_fields = [:id, :name, :description, :type, :severity, :languages, :regex, :recommendation]
      missing_fields = Enum.filter(required_fields, fn field -> not Map.has_key?(pattern, field) end)
      
      regex_valid = case pattern.regex do
        %Regex{} -> true
        _ -> false
      end
      
      valid = length(missing_fields) == 0 and regex_valid
      
      if valid do
        IO.puts("  ✅ #{name}")
      else
        IO.puts("  ❌ #{name} - Missing: #{inspect(missing_fields)}, Regex valid: #{regex_valid}")
      end
      
      {name, %{
        valid: valid,
        missing_fields: missing_fields,
        regex_valid: regex_valid,
        pattern: pattern
      }}
    end)
    
    valid_count = validations |> Enum.count(fn {_, data} -> data.valid end)
    total_count = length(validations)
    
    IO.puts("  Valid: #{valid_count}/#{total_count}")
    
    %{
      validations: Map.new(validations),
      valid_count: valid_count,
      total_tested: total_count,
      validation_timestamp: DateTime.utc_now()
    }
  end

  defp test_detection do
    IO.puts("\n🎯 Phase 3: Pattern Detection Testing")
    IO.puts("------------------------------------")
    
    # Test patterns with their provided test cases
    sample_patterns = get_sample_patterns()
    
    test_results = Enum.map(sample_patterns, fn {name, pattern} ->
      vulnerable_tests = test_vulnerable_code(pattern)
      safe_tests = test_safe_code(pattern)
      
      all_passed = vulnerable_tests.all_detected and safe_tests.none_detected
      
      if all_passed do
        IO.puts("  ✅ #{name} - Detection working correctly")
      else
        IO.puts("  ❌ #{name} - Vulnerable: #{vulnerable_tests.detected}/#{vulnerable_tests.total}, Safe: #{safe_tests.detected}/#{safe_tests.total}")
      end
      
      {name, %{
        passed: all_passed,
        vulnerable_tests: vulnerable_tests,
        safe_tests: safe_tests
      }}
    end)
    
    passed_count = test_results |> Enum.count(fn {_, data} -> data.passed end)
    total_count = length(test_results)
    
    IO.puts("  Passed: #{passed_count}/#{total_count}")
    
    %{
      test_results: Map.new(test_results),
      passed_count: passed_count,
      total_tested: total_count,
      testing_timestamp: DateTime.utc_now()
    }
  end

  defp verify_api do
    IO.puts("\n🌐 Phase 4: API Endpoint Verification")
    IO.puts("------------------------------------")
    
    # Test API endpoints if the server is running
    base_url = System.get_env("RSOLV_API_URL", "http://localhost:4000")
    
    endpoints = [
      {"/api/v1/patterns/public/javascript", :public},
      {"/api/v1/patterns/health", :health}
    ]
    
    api_results = Enum.map(endpoints, fn {endpoint, type} ->
      url = base_url <> endpoint
      
      case HTTPoison.get(url, [], timeout: 5000, recv_timeout: 5000) do
        {:ok, %HTTPoison.Response{status_code: 200, body: body}} ->
          case Jason.decode(body) do
            {:ok, data} ->
              IO.puts("  ✅ #{endpoint} - #{type}")
              {endpoint, %{success: true, data: data, type: type}}
            {:error, _} ->
              IO.puts("  ❌ #{endpoint} - Invalid JSON")
              {endpoint, %{success: false, error: "invalid_json", type: type}}
          end
        {:ok, %HTTPoison.Response{status_code: status}} ->
          IO.puts("  ❌ #{endpoint} - HTTP #{status}")
          {endpoint, %{success: false, error: "http_#{status}", type: type}}
        {:error, error} ->
          IO.puts("  ⚠️  #{endpoint} - Connection failed (#{inspect(error)})")
          {endpoint, %{success: false, error: "connection_failed", type: type}}
      end
    end)
    
    successful = api_results |> Enum.count(fn {_, data} -> data.success end)
    total = length(api_results)
    
    IO.puts("  Successful: #{successful}/#{total}")
    
    %{
      endpoint_results: Map.new(api_results),
      successful_count: successful,
      total_tested: total,
      api_timestamp: DateTime.utc_now()
    }
  end

  defp get_sample_patterns do
    # Get a representative sample of patterns for testing
    [
      {"js-sql-injection", Rsolv.Security.Patterns.Javascript.sql_injection_concatenation()},
      {"python-command-injection", Rsolv.Security.Patterns.Python.command_injection()},
      {"ruby-path-traversal", Rsolv.Security.Patterns.Ruby.path_traversal()},
      {"java-xpath-injection", Rsolv.Security.Patterns.Java.xpath_injection()},
      {"php-sql-injection", Rsolv.Security.Patterns.Php.sql_injection_concatenation()},
      {"cve-log4shell", Rsolv.Security.Patterns.Cve.log4shell_jndi_injection()}
    ]
  rescue
    _ ->
      # Fallback if specific functions don't exist
      []
  end

  defp test_vulnerable_code(pattern) do
    test_cases = Map.get(pattern, :test_cases, %{})
    vulnerable_cases = Map.get(test_cases, :vulnerable, [])
    
    if length(vulnerable_cases) > 0 do
      detected = Enum.count(vulnerable_cases, fn code ->
        Regex.match?(pattern.regex, code)
      end)
      
      %{
        detected: detected,
        total: length(vulnerable_cases),
        all_detected: detected == length(vulnerable_cases)
      }
    else
      %{detected: 0, total: 0, all_detected: true}
    end
  end

  defp test_safe_code(pattern) do
    test_cases = Map.get(pattern, :test_cases, %{})
    safe_cases = Map.get(test_cases, :safe, [])
    
    if length(safe_cases) > 0 do
      detected = Enum.count(safe_cases, fn code ->
        Regex.match?(pattern.regex, code)
      end)
      
      %{
        detected: detected,
        total: length(safe_cases),
        none_detected: detected == 0
      }
    else
      %{detected: 0, total: 0, none_detected: true}
    end
  end

  defp generate_summary(results) do
    pattern_audit = results.pattern_audit
    structure_validation = results.structure_validation
    detection_testing = results.detection_testing
    api_verification = results.api_verification
    
    %{
      total_patterns: pattern_audit.total_count,
      languages_and_frameworks: pattern_audit.by_language |> Map.keys() |> length(),
      structure_validation_rate: 
        if structure_validation.total_tested > 0 do
          Float.round(structure_validation.valid_count / structure_validation.total_tested * 100, 1)
        else
          0.0
        end,
      detection_accuracy_rate:
        if detection_testing.total_tested > 0 do
          Float.round(detection_testing.passed_count / detection_testing.total_tested * 100, 1)
        else
          0.0
        end,
      api_availability_rate:
        if api_verification.total_tested > 0 do
          Float.round(api_verification.successful_count / api_verification.total_tested * 100, 1)
        else
          0.0
        end,
      verification_timestamp: DateTime.utc_now()
    }
  end

  defp save_results(results) do
    json = Jason.encode!(results, pretty: true)
    File.write!("verification_results.json", json)
  end
end

# Run the verification
PatternSystemVerifier.run()