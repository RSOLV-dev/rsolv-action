# credo:disable-for-this-file Credo.Check.Warning.IoInspect
defmodule Rsolv.Security.Patterns.Elixir.DebugModeEnabledTest do
  use ExUnit.Case, async: true

  alias Rsolv.Security.Patterns.Elixir.DebugModeEnabled
  alias Rsolv.Security.Pattern

  describe "debug_mode_enabled pattern" do
    test "returns correct pattern structure" do
      pattern = DebugModeEnabled.pattern()

      assert %Pattern{} = pattern
      assert pattern.id == "elixir-debug-mode-enabled"
      assert pattern.name == "Debug Mode Enabled"
      assert pattern.type == :information_disclosure
      assert pattern.severity == :medium
      assert pattern.languages == ["elixir"]
      assert pattern.frameworks == ["phoenix"]
      assert pattern.cwe_id == "CWE-489"
      assert pattern.owasp_category == "A05:2021"

      assert is_binary(pattern.description)
      assert is_binary(pattern.recommendation)
      assert is_list(pattern.regex)
      assert length(pattern.regex) > 0
    end

    test "detects config debug: true" do
      pattern = DebugModeEnabled.pattern()

      vulnerable_code = "config :my_app, debug: true"
      assert Enum.any?(pattern.regex, &Regex.match?(&1, vulnerable_code))
    end

    test "detects config with debug true in different formats" do
      pattern = DebugModeEnabled.pattern()

      test_cases = [
        "config :my_app, debug: true",
        "config :phoenix, debug: true",
        "config :logger, debug: true",
        "config :my_app, some_key: \"value\", debug: true",
        "config :my_app,\n  debug: true",
        "config(:my_app, debug: true)"
      ]

      for vulnerable_code <- test_cases do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, vulnerable_code)),
               "Failed to detect: #{vulnerable_code}"
      end
    end

    test "detects Phoenix debug annotations enabled" do
      pattern = DebugModeEnabled.pattern()

      test_cases = [
        "config :phoenix_live_view, debug_heex_annotations: true",
        "config :phoenix_live_view,\n  debug_heex_annotations: true"
      ]

      for vulnerable_code <- test_cases do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, vulnerable_code)),
               "Failed to detect: #{vulnerable_code}"
      end
    end

    test "detects IO.inspect calls" do
      pattern = DebugModeEnabled.pattern()

      test_cases = [
        "IO.inspect(user_data)",
        "IO.inspect(sensitive_data, label: \"DEBUG\")",
        "IO.inspect(conn.params)",
        "IO.inspect conn.assigns",
        "user_data |> IO.inspect()",
        "password |> IO.inspect(label: \"Password\")"
      ]

      for vulnerable_code <- test_cases do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, vulnerable_code)),
               "Failed to detect: #{vulnerable_code}"
      end
    end

    test "detects dbg() calls" do
      pattern = DebugModeEnabled.pattern()

      test_cases = [
        "dbg(user_input)",
        "dbg(sensitive_data)",
        "user_data |> dbg()",
        "password |> dbg()"
      ]

      for vulnerable_code <- test_cases do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, vulnerable_code)),
               "Failed to detect: #{vulnerable_code}"
      end
    end

    test "detects Mix.env() != :prod checks" do
      pattern = DebugModeEnabled.pattern()

      test_cases = [
        "if Mix.env() != :prod do\n  IO.inspect(data)\nend",
        "unless Mix.env() == :prod do\n  IO.inspect(sensitive)\nend"
      ]

      for vulnerable_code <- test_cases do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, vulnerable_code)),
               "Failed to detect: #{vulnerable_code}"
      end
    end

    test "detects Logger debug level in production" do
      pattern = DebugModeEnabled.pattern()

      test_cases = [
        "config :logger, level: :debug",
        "config :logger,\n  level: :debug"
      ]

      for vulnerable_code <- test_cases do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, vulnerable_code)),
               "Failed to detect: #{vulnerable_code}"
      end
    end

    test "does not detect safe configurations" do
      pattern = DebugModeEnabled.pattern()

      safe_code = [
        "config :my_app, debug: false",
        "config :logger, level: :info",
        "config :phoenix_live_view, debug_heex_annotations: false",
        "Logger.debug(\"Safe debug message\")",
        "config :my_app, some_other_setting: true"
      ]

      for safe <- safe_code do
        refute Enum.any?(pattern.regex, &Regex.match?(&1, safe)),
               "False positive detected for: #{safe}"
      end
    end

    test "includes comprehensive vulnerability metadata" do
      metadata = DebugModeEnabled.vulnerability_metadata()

      assert metadata.attack_vectors
      assert metadata.business_impact
      assert metadata.technical_impact
      assert metadata.likelihood
      assert metadata.cve_examples
      assert metadata.compliance_standards
      assert metadata.remediation_steps
      assert metadata.prevention_tips
      assert metadata.detection_methods
      assert metadata.safe_alternatives
    end

    test "vulnerability metadata contains debug mode specific information" do
      metadata = DebugModeEnabled.vulnerability_metadata()

      assert String.contains?(metadata.attack_vectors, "Information Disclosure")
      assert String.contains?(metadata.business_impact, "sensitive data")
      assert String.contains?(metadata.technical_impact, "configuration")
      assert String.contains?(metadata.safe_alternatives, "Logger")
      assert String.contains?(metadata.prevention_tips, "production")
    end

    test "includes AST enhancement rules" do
      enhancement = DebugModeEnabled.ast_enhancement()

      assert enhancement.min_confidence
      assert enhancement.context_rules
      assert enhancement.confidence_rules
      assert enhancement.ast_rules
    end

    test "AST enhancement has debug-specific rules" do
      enhancement = DebugModeEnabled.ast_enhancement()

      assert enhancement.context_rules.exclude_development_files
      assert enhancement.context_rules.production_indicators
      assert enhancement.ast_rules.config_analysis
      assert enhancement.ast_rules.debug_function_analysis
      assert enhancement.confidence_rules.adjustments.config_file_bonus
    end

    test "enhanced pattern integrates AST rules" do
      enhanced = DebugModeEnabled.enhanced_pattern()

      assert enhanced.id == "elixir-debug-mode-enabled"
      assert enhanced.ast_enhancement.min_confidence
      assert is_float(enhanced.ast_enhancement.min_confidence)
    end

    test "pattern includes educational test cases" do
      pattern = DebugModeEnabled.pattern()

      assert pattern.test_cases.vulnerable
      assert pattern.test_cases.safe
      assert length(pattern.test_cases.vulnerable) > 0
      assert length(pattern.test_cases.safe) > 0
    end
  end
end
