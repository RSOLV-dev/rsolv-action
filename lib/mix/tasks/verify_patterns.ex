defmodule Mix.Tasks.VerifyPatterns do
  @moduledoc """
  Comprehensive verification of the RSOLV pattern system.

  Usage: mix verify_patterns
  """
  use Mix.Task

  require Logger

  def run(_args) do
    Mix.Task.run("app.start")

    IO.puts("🔍 RSOLV Pattern System Verification")
    IO.puts("===================================")

    results = %{
      pattern_audit: audit_patterns(),
      language_breakdown: analyze_languages(),
      structure_validation: validate_structure(),
      detection_testing: test_detection(),
      api_verification: verify_api(),
      integration_test: test_integration()
    }

    summary = generate_summary(results)
    save_results(Map.put(results, :summary, summary))

    IO.puts("\n" <> String.duplicate("=", 50))
    print_summary(summary)
    IO.puts(String.duplicate("=", 50))

    summary
  end

  defp audit_patterns do
    IO.puts("\n📊 Phase 1: Pattern Count Audit")
    IO.puts("------------------------------")

    pattern_modules = [
      {Rsolv.Security.Patterns.Javascript, "JavaScript/TypeScript"},
      {Rsolv.Security.Patterns.Python, "Python"},
      {Rsolv.Security.Patterns.Ruby, "Ruby"},
      {Rsolv.Security.Patterns.Java, "Java"},
      {Rsolv.Security.Patterns.Php, "PHP"},
      {Rsolv.Security.Patterns.Elixir, "Elixir/Phoenix"},
      {Rsolv.Security.Patterns.Rails, "Ruby on Rails"},
      {Rsolv.Security.Patterns.Django, "Django/Python"},
      {Rsolv.Security.Patterns.Cve, "CVE (Cross-language)"}
    ]

    counts =
      Enum.map(pattern_modules, fn {module, name} ->
        try do
          # Get all exported functions that return patterns
          functions = module.__info__(:functions)

          pattern_functions =
            Enum.filter(functions, fn {func_name, arity} ->
              arity == 0 and func_name != :__info__ and
                not String.starts_with?(Atom.to_string(func_name), "_")
            end)

          # Test each function to see if it returns a valid pattern
          valid_patterns =
            Enum.filter(pattern_functions, fn {func_name, _} ->
              try do
                result = apply(module, func_name, [])
                is_valid_pattern?(result)
              rescue
                _ -> false
              end
            end)

          count = length(valid_patterns)
          IO.puts("  #{String.pad_trailing(name, 20)}: #{count} patterns")

          {name,
           %{
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
    IO.puts("  #{String.pad_trailing("TOTAL", 20)}: #{total} patterns")

    %{
      by_language: Map.new(counts),
      total_count: total,
      audit_timestamp: DateTime.utc_now()
    }
  end

  defp analyze_languages do
    IO.puts("\n🔤 Phase 2: Language & Framework Analysis")
    IO.puts("---------------------------------------")

    # Categorize by pure languages vs frameworks
    languages = [
      "JavaScript/TypeScript",
      "Python",
      "Ruby",
      "Java",
      "PHP",
      "Elixir/Phoenix",
      "CVE (Cross-language)"
    ]

    frameworks = ["Ruby on Rails", "Django/Python"]

    IO.puts("  Programming Languages: #{length(languages)}")
    IO.puts("  Frameworks: #{length(frameworks)}")
    IO.puts("  Total categories: #{length(languages) + length(frameworks)}")

    %{
      pure_languages: languages,
      frameworks: frameworks,
      total_categories: length(languages) + length(frameworks)
    }
  end

  defp validate_structure do
    IO.puts("\n🔧 Phase 3: Pattern Structure Validation")
    IO.puts("---------------------------------------")

    # Test sample patterns for required fields
    sample_patterns = get_sample_patterns()

    validations =
      Enum.map(sample_patterns, fn {name, pattern} ->
        required_fields = [
          :id,
          :name,
          :description,
          :type,
          :severity,
          :languages,
          :regex,
          :recommendation
        ]

        missing_fields =
          Enum.filter(required_fields, fn field -> not Map.has_key?(pattern, field) end)

        regex_valid =
          case pattern.regex do
            %Regex{} -> true
            _ -> false
          end

        has_test_cases =
          Map.has_key?(pattern, :test_cases) and
            is_map(pattern.test_cases) and
            Map.has_key?(pattern.test_cases, :vulnerable)

        valid = Enum.empty?(missing_fields) and regex_valid and has_test_cases

        if valid do
          IO.puts("  ✅ #{name}")
        else
          issues = []

          issues =
            if length(missing_fields) > 0,
              do: issues ++ ["Missing: #{inspect(missing_fields)}"],
              else: issues

          issues = if not regex_valid, do: issues ++ ["Invalid regex"], else: issues
          issues = if not has_test_cases, do: issues ++ ["No test cases"], else: issues
          IO.puts("  ❌ #{name} - #{Enum.join(issues, ", ")}")
        end

        {name,
         %{
           valid: valid,
           missing_fields: missing_fields,
           regex_valid: regex_valid,
           has_test_cases: has_test_cases,
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
    IO.puts("\n🎯 Phase 4: Pattern Detection Testing")
    IO.puts("------------------------------------")

    sample_patterns = get_sample_patterns()

    test_results =
      Enum.map(sample_patterns, fn {name, pattern} ->
        vulnerable_tests = test_vulnerable_code(pattern)
        safe_tests = test_safe_code(pattern)

        all_passed = vulnerable_tests.all_detected and safe_tests.none_detected

        if all_passed do
          IO.puts("  ✅ #{name} - Detection working correctly")
        else
          v_status = if vulnerable_tests.all_detected, do: "✅", else: "❌"
          s_status = if safe_tests.none_detected, do: "✅", else: "❌"

          IO.puts(
            "  #{if all_passed, do: "✅", else: "❌"} #{name} - Vulnerable: #{v_status}#{vulnerable_tests.detected}/#{vulnerable_tests.total}, Safe: #{s_status}#{safe_tests.not_detected}/#{safe_tests.total}"
          )
        end

        {name,
         %{
           passed: all_passed,
           vulnerable_tests: vulnerable_tests,
           safe_tests: safe_tests
         }}
      end)

    passed_count = test_results |> Enum.count(fn {_, data} -> data.passed end)
    total_count = length(test_results)

    IO.puts("  Overall: #{passed_count}/#{total_count} patterns working correctly")

    %{
      test_results: Map.new(test_results),
      passed_count: passed_count,
      total_tested: total_count,
      testing_timestamp: DateTime.utc_now()
    }
  end

  defp verify_api do
    IO.puts("\n🌐 Phase 5: API Endpoint Verification")
    IO.puts("------------------------------------")

    # Test the pattern controller directly
    try do
      # Test getting all patterns
      all_patterns = Rsolv.Security.list_all_patterns()
      pattern_count = length(all_patterns)

      # Test getting patterns by language
      js_patterns = Rsolv.Security.list_patterns_by_language("javascript")
      js_count = length(js_patterns)

      # Test getting patterns by tier (if available)
      public_patterns = Rsolv.Security.list_patterns_by_tier(:public)
      public_count = length(public_patterns)

      IO.puts("  ✅ All patterns: #{pattern_count}")
      IO.puts("  ✅ JavaScript patterns: #{js_count}")
      IO.puts("  ✅ Public tier patterns: #{public_count}")

      %{
        success: true,
        total_patterns: pattern_count,
        javascript_patterns: js_count,
        public_patterns: public_count,
        api_timestamp: DateTime.utc_now()
      }
    rescue
      error ->
        IO.puts("  ❌ API functions not available: #{inspect(error)}")
        %{success: false, error: inspect(error)}
    end
  end

  defp test_integration do
    IO.puts("\n🔗 Phase 6: Integration Testing")
    IO.puts("------------------------------")

    # Test that patterns can be retrieved and applied
    try do
      # Get a sample pattern
      pattern = Rsolv.Security.Patterns.Javascript.SqlInjectionConcat.pattern()

      # Test it against vulnerable code
      vulnerable_code = ~s|const query = "SELECT * FROM users WHERE id = " + userId;|

      safe_code =
        ~s|const query = "SELECT * FROM users WHERE id = ?"; db.execute(query, [userId]);|

      vulnerable_detected = Regex.match?(pattern.regex, vulnerable_code)
      safe_detected = Regex.match?(pattern.regex, safe_code)

      integration_working = vulnerable_detected and not safe_detected

      if integration_working do
        IO.puts("  ✅ End-to-end pattern application working")
      else
        IO.puts(
          "  ❌ Integration test failed - Vulnerable: #{vulnerable_detected}, Safe: #{safe_detected}"
        )
      end

      %{
        success: integration_working,
        vulnerable_detected: vulnerable_detected,
        safe_detected: safe_detected,
        integration_timestamp: DateTime.utc_now()
      }
    rescue
      error ->
        IO.puts("  ❌ Integration test failed: #{inspect(error)}")
        %{success: false, error: inspect(error)}
    end
  end

  defp is_valid_pattern?(pattern) do
    is_map(pattern) and
      Map.has_key?(pattern, :id) and
      Map.has_key?(pattern, :regex) and
      Map.has_key?(pattern, :name) and
      Map.has_key?(pattern, :type)
  end

  defp get_sample_patterns do
    [
      {"js-sql-injection", Rsolv.Security.Patterns.Javascript.SqlInjectionConcat.pattern()},
      {"js-xss", Rsolv.Security.Patterns.Javascript.xss_innerhtml()},
      {"python-command-injection",
       Rsolv.Security.Patterns.Python.CommandInjectionOsSystem.pattern()},
      {"ruby-path-traversal", Rsolv.Security.Patterns.Ruby.path_traversal()},
      {"java-sql-injection", Rsolv.Security.Patterns.Java.SqlInjectionStatement.pattern()},
      {"php-sql-injection", Rsolv.Security.Patterns.Php.SqlInjectionConcat.pattern()},
      {"elixir-sql-injection", Rsolv.Security.Patterns.Elixir.SqlInjectionFragment.pattern()},
      # {"rails-mass-assignment", Rsolv.Security.Patterns.Rails.MassAssignment.pattern()},
      # {"django-sql-injection", Rsolv.Security.Patterns.Django.SqlInjectionRaw.pattern()},
      {"cve-log4shell", Rsolv.Security.Patterns.Cve.log4shell_detection()}
    ]
  rescue
    error ->
      IO.puts("    Warning: Some sample patterns not available: #{inspect(error)}")
      []
  end

  defp test_vulnerable_code(pattern) do
    test_cases = Map.get(pattern, :test_cases, %{})
    vulnerable_cases = Map.get(test_cases, :vulnerable, [])

    if length(vulnerable_cases) > 0 do
      detected =
        Enum.count(vulnerable_cases, fn code ->
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
      detected =
        Enum.count(safe_cases, fn code ->
          Regex.match?(pattern.regex, code)
        end)

      not_detected = length(safe_cases) - detected

      %{
        detected: detected,
        not_detected: not_detected,
        total: length(safe_cases),
        none_detected: detected == 0
      }
    else
      %{detected: 0, not_detected: 0, total: 0, none_detected: true}
    end
  end

  defp generate_summary(results) do
    pattern_audit = results.pattern_audit
    language_breakdown = results.language_breakdown
    structure_validation = results.structure_validation
    detection_testing = results.detection_testing
    api_verification = results.api_verification
    integration_test = results.integration_test

    %{
      # Core metrics
      total_patterns_actual: pattern_audit.total_count,
      total_languages: length(language_breakdown.pure_languages),
      total_frameworks: length(language_breakdown.frameworks),
      total_categories: language_breakdown.total_categories,

      # Quality metrics
      structure_validation_rate:
        if structure_validation.total_tested > 0 do
          Float.round(
            structure_validation.valid_count / structure_validation.total_tested * 100,
            1
          )
        else
          0.0
        end,
      detection_accuracy_rate:
        if detection_testing.total_tested > 0 do
          Float.round(detection_testing.passed_count / detection_testing.total_tested * 100, 1)
        else
          0.0
        end,

      # System status
      api_functions_available: api_verification.success,
      integration_test_passed: integration_test.success,

      # Detailed breakdown
      patterns_by_category:
        pattern_audit.by_language
        |> Enum.map(fn {name, data} -> {name, Map.get(data, :count, 0)} end)
        |> Map.new(),
      verification_timestamp: DateTime.utc_now(),
      verification_complete: true
    }
  end

  defp print_summary(summary) do
    IO.puts("📊 VERIFICATION SUMMARY")
    IO.puts("")
    IO.puts("🔢 Pattern Counts:")
    IO.puts("   Total patterns: #{summary.total_patterns_actual} (not 448+)")
    IO.puts("   Languages: #{summary.total_languages}")
    IO.puts("   Frameworks: #{summary.total_frameworks}")
    IO.puts("   Total categories: #{summary.total_categories}")
    IO.puts("")
    IO.puts("📋 Pattern Breakdown:")

    Enum.each(summary.patterns_by_category, fn {name, count} ->
      IO.puts("   #{String.pad_trailing(name, 20)}: #{count}")
    end)

    IO.puts("")
    IO.puts("✅ Quality Metrics:")
    IO.puts("   Structure validation: #{summary.structure_validation_rate}%")
    IO.puts("   Detection accuracy: #{summary.detection_accuracy_rate}%")
    IO.puts("   API functions: #{if summary.api_functions_available, do: "✅", else: "❌"}")
    IO.puts("   Integration test: #{if summary.integration_test_passed, do: "✅", else: "❌"}")
    IO.puts("")
    IO.puts("🎯 Key Findings:")
    IO.puts("   - Actual pattern count is #{summary.total_patterns_actual}, not 448+")

    IO.puts(
      "   - #{summary.total_categories} total categories (#{summary.total_languages} languages + #{summary.total_frameworks} frameworks)"
    )

    IO.puts(
      "   - Pattern detection #{if summary.detection_accuracy_rate > 80, do: "working well", else: "needs improvement"}"
    )

    IO.puts(
      "   - System integration #{if summary.integration_test_passed, do: "functional", else: "has issues"}"
    )
  end

  defp save_results(results) do
    timestamp = DateTime.utc_now() |> DateTime.to_iso8601()
    filename = "pattern_verification_#{String.replace(timestamp, ":", "-")}.json"

    json = JSON.encode!(results, pretty: true)
    File.write!(filename, json)
    IO.puts("\n💾 Detailed results saved to: #{filename}")
  end
end
