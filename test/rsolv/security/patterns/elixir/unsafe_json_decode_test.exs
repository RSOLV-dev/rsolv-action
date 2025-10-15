defmodule Rsolv.Security.Patterns.Elixir.UnsafeJsonDecodeTest do
  use ExUnit.Case, async: true

  alias Rsolv.Security.Patterns.Elixir.UnsafeJsonDecode
  alias Rsolv.Security.Pattern

  describe "unsafe_json_decode pattern" do
    test "returns correct pattern structure" do
      pattern = UnsafeJsonDecode.pattern()

      assert %Pattern{} = pattern
      assert pattern.id == "elixir-unsafe-json-decode"
      assert pattern.name == "Unsafe JSON Decoding"
      assert pattern.type == :dos
      assert pattern.severity == :medium
      assert pattern.languages == ["elixir"]
      assert pattern.cwe_id == "CWE-20"
      assert pattern.owasp_category == "A05:2021"

      assert is_binary(pattern.description)
      assert is_binary(pattern.recommendation)
      assert is_list(pattern.regex)
      assert length(pattern.regex) > 0
    end

    test "detects Jason.decode! with user input" do
      pattern = UnsafeJsonDecode.pattern()

      test_cases = [
        ~S|Jason.decode!(user_input)|,
        ~S|Jason.decode!(params["data"])|,
        ~S|Jason.decode!(conn.body_params["json"])|,
        ~S|Jason.decode!(request_body)|,
        ~S|result = Jason.decode!(untrusted_data)|,
        ~S|Jason.decode!(socket.assigns.user_data)|
      ]

      for vulnerable_code <- test_cases do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, vulnerable_code)),
               "Failed to detect: #{vulnerable_code}"
      end
    end

    test "detects Poison.decode! with user input" do
      pattern = UnsafeJsonDecode.pattern()

      test_cases = [
        ~S|Poison.decode!(user_input)|,
        ~S|Poison.decode!(params["json"])|,
        ~S|Poison.decode!(request.body)|,
        ~S|data = Poison.decode!(external_json)|
      ]

      for vulnerable_code <- test_cases do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, vulnerable_code)),
               "Failed to detect: #{vulnerable_code}"
      end
    end

    test "detects JSON.decode! with user input" do
      pattern = UnsafeJsonDecode.pattern()

      test_cases = [
        ~S|JSON.decode!(user_data)|,
        ~S|JSON.decode!(conn.params["payload"])|,
        ~S|JSON.decode!(raw_json)|
      ]

      for vulnerable_code <- test_cases do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, vulnerable_code)),
               "Failed to detect: #{vulnerable_code}"
      end
    end

    test "detects decode! with variable assignment patterns" do
      pattern = UnsafeJsonDecode.pattern()

      test_cases = [
        ~S|{:ok, data} = Jason.decode!(user_input)|,
        ~S|parsed = Jason.decode!(external_data)|,
        ~S|result = Poison.decode!(untrusted_input)|,
        ~S|case Jason.decode!(user_json) do|
      ]

      for vulnerable_code <- test_cases do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, vulnerable_code)),
               "Failed to detect: #{vulnerable_code}"
      end
    end

    test "detects decode! in function calls and piping" do
      pattern = UnsafeJsonDecode.pattern()

      test_cases = [
        "user_input |> Jason.decode!()",
        ~S|process_data(Jason.decode!(raw_json))|,
        ~S|validate(Poison.decode!(input))|,
        ~S|Map.get(Jason.decode!(data), "key")|
      ]

      for vulnerable_code <- test_cases do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, vulnerable_code)),
               "Failed to detect: #{vulnerable_code}"
      end
    end

    test "does not detect safe JSON.decode usage" do
      pattern = UnsafeJsonDecode.pattern()

      safe_code = [
        ~S|case Jason.decode(user_input) do|,
        ~S|{:ok, data} = Jason.decode(params["json"])|,
        ~S|Jason.decode(trusted_data, keys: :atoms)|,
        ~S|Poison.decode(user_input)|,
        ~S|with {:ok, json} <- Jason.decode(data) do|
      ]

      for safe <- safe_code do
        refute Enum.any?(pattern.regex, &Regex.match?(&1, safe)),
               "False positive detected for: #{safe}"
      end
    end

    test "does not detect decode! with trusted static data" do
      pattern = UnsafeJsonDecode.pattern()

      safe_code = [
        ~S|Jason.decode!("{\"key\": \"value\"}")|,
        ~S|Jason.decode!(@static_config)|,
        ~S|Poison.decode!(Application.get_env(:app, :json_config))|,
        ~S|Jason.decode!(File.read!("config.json"))|
      ]

      for safe <- safe_code do
        refute Enum.any?(pattern.regex, &Regex.match?(&1, safe)),
               "False positive detected for: #{safe}"
      end
    end

    test "AST enhancement detects comments for exclusion" do
      enhancement = UnsafeJsonDecode.ast_enhancement()

      # AST enhancement should have comment detection rules
      assert enhancement.context_rules.exclude_comments
      assert enhancement.context_rules.comment_patterns
      assert enhancement.confidence_rules.adjustments.comment_penalty == -1.0

      # In production, AST enhancement will filter out comments,
      # but regex patterns may match them initially
      assert length(enhancement.context_rules.comment_patterns) > 0
    end

    test "includes comprehensive vulnerability metadata" do
      metadata = UnsafeJsonDecode.vulnerability_metadata()

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

    test "vulnerability metadata contains JSON-specific information" do
      metadata = UnsafeJsonDecode.vulnerability_metadata()

      assert String.contains?(metadata.attack_vectors, "malformed")
      assert String.contains?(metadata.business_impact, "Service")
      assert String.contains?(metadata.technical_impact, "crash")
      assert String.contains?(metadata.safe_alternatives, "Jason.decode")
      assert String.contains?(metadata.prevention_tips, "Validate")
    end

    test "includes AST enhancement rules" do
      enhancement = UnsafeJsonDecode.ast_enhancement()

      assert enhancement.min_confidence
      assert enhancement.context_rules
      assert enhancement.confidence_rules
      assert enhancement.ast_rules
    end

    test "AST enhancement has JSON-specific rules" do
      enhancement = UnsafeJsonDecode.ast_enhancement()

      assert enhancement.context_rules.input_sources
      assert enhancement.context_rules.trusted_sources
      assert enhancement.ast_rules.function_analysis
      assert enhancement.ast_rules.input_analysis
      assert enhancement.confidence_rules.adjustments.trusted_source_penalty
    end

    test "enhanced pattern integrates AST rules" do
      enhanced = UnsafeJsonDecode.enhanced_pattern()

      assert enhanced.id == "elixir-unsafe-json-decode"
      assert enhanced.ast_enhancement.min_confidence
      assert is_float(enhanced.ast_enhancement.min_confidence)
    end

    test "pattern includes educational test cases" do
      pattern = UnsafeJsonDecode.pattern()

      assert pattern.test_cases.vulnerable
      assert pattern.test_cases.safe
      assert length(pattern.test_cases.vulnerable) > 0
      assert length(pattern.test_cases.safe) > 0
    end
  end
end
