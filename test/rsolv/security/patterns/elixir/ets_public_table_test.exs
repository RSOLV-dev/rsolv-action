defmodule Rsolv.Security.Patterns.Elixir.EtsPublicTableTest do
  use ExUnit.Case, async: true

  alias Rsolv.Security.Patterns.Elixir.EtsPublicTable
  alias Rsolv.Security.Pattern

  describe "ets_public_table pattern" do
    test "returns correct pattern structure" do
      pattern = EtsPublicTable.pattern()

      assert %Pattern{} = pattern
      assert pattern.id == "elixir-ets-public-table"
      assert pattern.name == "Public ETS Table Security Risk"
      assert pattern.type == :authentication
      assert pattern.severity == :medium
      assert pattern.languages == ["elixir"]
      assert pattern.frameworks == []
      assert pattern.cwe_id == "CWE-732"
      assert pattern.owasp_category == "A01:2021"

      assert is_binary(pattern.description)
      assert is_binary(pattern.recommendation)
      assert is_list(pattern.regex)
      assert length(pattern.regex) > 0
    end

    test "detects basic public ETS table creation" do
      pattern = EtsPublicTable.pattern()

      test_cases = [
        ":ets.new(:sessions, [:public, :named_table])",
        ":ets.new(:cache, [:public])",
        ":ets.new(:user_data, [:public, :set])",
        ":ets.new(:tokens, [:public, :bag])"
      ]

      for vulnerable_code <- test_cases do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, vulnerable_code)),
               "Failed to detect: #{vulnerable_code}"
      end
    end

    test "detects public tables with various options" do
      pattern = EtsPublicTable.pattern()

      test_cases = [
        ":ets.new(:data, [:public, :ordered_set, :named_table])",
        ":ets.new(:metrics, [:named_table, :public, :set])",
        ":ets.new(:stats, [:public, :duplicate_bag])",
        ":ets.new(:config, [:public, :read_concurrency])"
      ]

      for vulnerable_code <- test_cases do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, vulnerable_code)),
               "Failed to detect: #{vulnerable_code}"
      end
    end

    test "detects public tables in GenServer contexts" do
      pattern = EtsPublicTable.pattern()

      test_cases = [
        "table = :ets.new(__MODULE__, [:public, :named_table])",
        ":ets.new(name, [:public | opts])",
        ":ets.new(table_name, [:public, :set, :named_table])"
      ]

      for vulnerable_code <- test_cases do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, vulnerable_code)),
               "Failed to detect: #{vulnerable_code}"
      end
    end

    test "detects public tables with sensitive data context" do
      pattern = EtsPublicTable.pattern()

      test_cases = [
        ":ets.new(:user_sessions, [:public, :named_table])",
        ":ets.new(:auth_tokens, [:public, :set])",
        ":ets.new(:passwords, [:public])",
        ":ets.new(:api_keys, [:public, :bag])"
      ]

      for vulnerable_code <- test_cases do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, vulnerable_code)),
               "Failed to detect: #{vulnerable_code}"
      end
    end

    test "does not detect protected or private tables" do
      pattern = EtsPublicTable.pattern()

      safe_code = [
        ":ets.new(:sessions, [:protected, :named_table])",
        ":ets.new(:cache, [:private])",
        ":ets.new(:data, [:protected, :set])",
        ":ets.new(:tokens, [:private, :bag])",
        # Default is protected
        ":ets.new(:config, [:protected])",
        # No explicit access level (defaults to protected)
        ":ets.new(:stats, [])"
      ]

      for safe <- safe_code do
        refute Enum.any?(pattern.regex, &Regex.match?(&1, safe)),
               "False positive detected for: #{safe}"
      end
    end

    test "does not detect safe public table usage" do
      pattern = EtsPublicTable.pattern()

      safe_code = [
        # Comments
        "# ETS table with :public access",
        # Table access, not creation
        ":ets.lookup(public_table, key)",
        # Operations on existing tables
        ":ets.insert(existing_table, data)"
      ]

      for safe <- safe_code do
        refute Enum.any?(pattern.regex, &Regex.match?(&1, safe)),
               "False positive detected for: #{safe}"
      end
    end

    test "includes comprehensive vulnerability metadata" do
      metadata = EtsPublicTable.vulnerability_metadata()

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

    test "vulnerability metadata contains ETS-specific information" do
      metadata = EtsPublicTable.vulnerability_metadata()

      assert String.contains?(metadata.attack_vectors, "access")
      assert String.contains?(metadata.business_impact, "data")
      assert String.contains?(metadata.technical_impact, "process")
      assert String.contains?(metadata.safe_alternatives, "protected")
      assert String.contains?(metadata.prevention_tips, "private")
    end

    test "includes AST enhancement rules" do
      enhancement = EtsPublicTable.ast_enhancement()

      assert enhancement.min_confidence
      assert enhancement.context_rules
      assert enhancement.confidence_rules
      assert enhancement.ast_rules
    end

    test "AST enhancement has ETS-specific rules" do
      enhancement = EtsPublicTable.ast_enhancement()

      assert enhancement.context_rules.exclude_test_files
      assert enhancement.context_rules.sensitive_table_names
      assert enhancement.ast_rules.ets_analysis
      assert enhancement.ast_rules.access_control_analysis
      assert enhancement.confidence_rules.adjustments.sensitive_data_bonus
    end

    test "enhanced pattern integrates AST rules" do
      enhanced = EtsPublicTable.enhanced_pattern()

      assert enhanced.id == "elixir-ets-public-table"
      assert enhanced.ast_enhancement.min_confidence
      assert is_float(enhanced.ast_enhancement.min_confidence)
    end

    test "pattern includes educational test cases" do
      pattern = EtsPublicTable.pattern()

      assert pattern.test_cases.vulnerable
      assert pattern.test_cases.safe
      assert length(pattern.test_cases.vulnerable) > 0
      assert length(pattern.test_cases.safe) > 0
    end
  end
end
