defmodule Rsolv.Security.Patterns.Elixir.AtomExhaustionTest do
  use ExUnit.Case, async: true

  alias Rsolv.Security.Patterns.Elixir.AtomExhaustion
  alias Rsolv.Security.Pattern

  describe "atom_exhaustion pattern" do
    test "returns correct pattern structure" do
      pattern = AtomExhaustion.pattern()

      assert %Pattern{} = pattern
      assert pattern.id == "elixir-atom-exhaustion"
      assert pattern.name == "Atom Table Exhaustion Risk"
      assert pattern.type == :resource_exhaustion
      assert pattern.severity == :high
      assert pattern.languages == ["elixir"]
      assert pattern.frameworks == []
      assert pattern.cwe_id == "CWE-400"
      assert pattern.owasp_category == "A05:2021"

      assert is_binary(pattern.description)
      assert is_binary(pattern.recommendation)
      assert is_list(pattern.regex)
      assert length(pattern.regex) > 0
    end

    test "detects Jason.decode with atoms key conversion" do
      pattern = AtomExhaustion.pattern()

      test_cases = [
        "Jason.decode!(user_input, keys: :atoms)",
        "Jason.decode(untrusted_data, keys: :atoms)",
        "Jason.decode!(request.body, keys: :atoms)",
        "Jason.decode(params[:data], keys: :atoms)"
      ]

      for vulnerable_code <- test_cases do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, vulnerable_code)),
               "Failed to detect: #{vulnerable_code}"
      end
    end

    test "detects other JSON libraries with atom key conversion" do
      pattern = AtomExhaustion.pattern()

      test_cases = [
        "Poison.decode!(json_string, keys: :atoms)",
        "Poison.decode(json_data, keys: :atoms)",
        "JSON.decode!(user_input, keys: :atoms)"
      ]

      for vulnerable_code <- test_cases do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, vulnerable_code)),
               "Failed to detect: #{vulnerable_code}"
      end
    end

    test "detects unsafe atom creation functions with user input" do
      pattern = AtomExhaustion.pattern()

      test_cases = [
        "String.to_atom(user_input)",
        "binary_to_atom(user_data)",
        "List.to_atom(params.key)",
        "String.to_atom(request.headers[\"x-custom\"])"
      ]

      for vulnerable_code <- test_cases do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, vulnerable_code)),
               "Failed to detect: #{vulnerable_code}"
      end
    end

    test "detects unsafe atom creation with interpolation" do
      pattern = AtomExhaustion.pattern()

      test_cases = [
        ~S|String.to_atom("prefix_#{user_input}")|,
        ~S|String.to_atom("#{category}_#{user_type}")|,
        ~S|binary_to_atom("table_#{table_name}")|
      ]

      for vulnerable_code <- test_cases do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, vulnerable_code)),
               "Failed to detect: #{vulnerable_code}"
      end
    end

    test "detects pattern matching on user-controlled atoms" do
      pattern = AtomExhaustion.pattern()

      test_cases = [
        "String.to_atom(action) do",
        "case String.to_atom(user_role) do",
        "with {:ok, atom} <- String.to_atom(input)"
      ]

      for vulnerable_code <- test_cases do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, vulnerable_code)),
               "Failed to detect: #{vulnerable_code}"
      end
    end

    test "does not detect safe atom usage" do
      pattern = AtomExhaustion.pattern()

      safe_code = [
        # No keys: :atoms
        "Jason.decode!(user_input)",
        # Safe :atoms! option
        "Jason.decode(data, keys: :atoms!)",
        # Uses existing atoms only
        "String.to_existing_atom(known_value)",
        # Safe alternative
        "binary_to_existing_atom(validated_input)",
        # Hardcoded atoms are safe
        ":hardcoded_atom",
        # Compile-time atoms
        "Enum.map(~w[one two three]a, &process/1)"
      ]

      for safe <- safe_code do
        refute Enum.any?(pattern.regex, &Regex.match?(&1, safe)),
               "False positive detected for: #{safe}"
      end
    end

    test "does not detect safe JSON decoding patterns" do
      pattern = AtomExhaustion.pattern()

      safe_code = [
        # String keys (default)
        "Jason.decode!(json_string)",
        # Explicit string keys
        "Jason.decode(data, keys: :strings)",
        # Struct decoding
        "Poison.decode!(json, as: %User{})",
        # Comments
        "# This comment mentions Jason.decode with keys: :atoms"
      ]

      for safe <- safe_code do
        refute Enum.any?(pattern.regex, &Regex.match?(&1, safe)),
               "False positive detected for: #{safe}"
      end
    end

    test "includes comprehensive vulnerability metadata" do
      metadata = AtomExhaustion.vulnerability_metadata()

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

    test "vulnerability metadata contains atom-specific information" do
      metadata = AtomExhaustion.vulnerability_metadata()

      assert String.contains?(metadata.attack_vectors, "atom table")
      assert String.contains?(metadata.business_impact, "crash")
      assert String.contains?(metadata.technical_impact, "exhaustion")
      assert String.contains?(metadata.safe_alternatives, "existing_atom")
      assert String.contains?(metadata.prevention_tips, "runtime")
    end

    test "includes AST enhancement rules" do
      enhancement = AtomExhaustion.ast_enhancement()

      assert enhancement.min_confidence
      assert enhancement.context_rules
      assert enhancement.confidence_rules
      assert enhancement.ast_rules
    end

    test "AST enhancement has atom-specific rules" do
      enhancement = AtomExhaustion.ast_enhancement()

      assert enhancement.context_rules.exclude_test_files
      assert enhancement.context_rules.user_input_indicators
      assert enhancement.ast_rules.atom_analysis
      assert enhancement.ast_rules.json_analysis
      assert enhancement.confidence_rules.adjustments.user_input_bonus
    end

    test "enhanced pattern integrates AST rules" do
      enhanced = AtomExhaustion.enhanced_pattern()

      assert enhanced.id == "elixir-atom-exhaustion"
      assert enhanced.ast_enhancement.min_confidence
      assert is_float(enhanced.ast_enhancement.min_confidence)
    end

    test "pattern includes educational test cases" do
      pattern = AtomExhaustion.pattern()

      assert pattern.test_cases.vulnerable
      assert pattern.test_cases.safe
      assert length(pattern.test_cases.vulnerable) > 0
      assert length(pattern.test_cases.safe) > 0
    end
  end
end
