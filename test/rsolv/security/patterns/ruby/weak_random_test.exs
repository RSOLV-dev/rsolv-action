defmodule Rsolv.Security.Patterns.Ruby.WeakRandomTest do
  use ExUnit.Case, async: true

  alias Rsolv.Security.Patterns.Ruby.WeakRandom
  alias Rsolv.Security.Pattern

  describe "pattern/0" do
    test "returns a valid pattern struct" do
      pattern = WeakRandom.pattern()

      assert %Pattern{} = pattern
      assert pattern.id == "ruby-weak-random"
      assert pattern.name == "Weak Random Number Generation"
      assert pattern.severity == :medium
      assert pattern.type == :cryptographic_failure
      assert pattern.languages == ["ruby"]
    end

    test "includes CWE and OWASP references" do
      pattern = WeakRandom.pattern()

      assert pattern.cwe_id == "CWE-330"
      assert pattern.owasp_category == "A02:2021"
    end

    test "has multiple regex patterns" do
      pattern = WeakRandom.pattern()

      assert is_list(pattern.regex)
      assert length(pattern.regex) >= 3
    end
  end

  describe "regex matching" do
    setup do
      pattern = WeakRandom.pattern()
      {:ok, pattern: pattern}
    end

    test "matches basic rand usage", %{pattern: pattern} do
      vulnerable_code = [
        ~S|token = rand(100000)|,
        ~S|session_id = rand(10**8)|,
        ~S|password = rand(1000000)|,
        ~S|api_key = rand(99999999)|,
        ~S|csrf_token = rand(2**32)|
      ]

      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Should match: #{code}"
      end
    end

    test "matches Random.rand usage", %{pattern: pattern} do
      vulnerable_code = [
        ~S|token = Random.rand(100000)|,
        ~S|session_key = Random.rand(10**16)|,
        ~S|Random.rand(1..1000)|,
        ~S|number = Random.rand(0...100)|,
        ~S|id = Random.rand|
      ]

      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Should match: #{code}"
      end
    end

    test "matches srand seeding", %{pattern: pattern} do
      vulnerable_code = [
        ~S|srand(Time.now.to_i)|,
        ~S|srand(1234)|,
        ~S|srand|,
        ~S|srand(42)|
      ]

      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Should match: #{code}"
      end
    end

    test "matches Kernel.rand usage", %{pattern: pattern} do
      vulnerable_code = [
        ~S|token = Kernel.rand(100000)|,
        ~S|Kernel.rand(42)|,
        ~S|number = Kernel.rand|
      ]

      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Should match: #{code}"
      end
    end

    test "does not match secure random patterns", %{pattern: pattern} do
      safe_code = [
        ~S|token = SecureRandom.hex(16)|,
        ~S|session_id = SecureRandom.uuid|,
        ~S|password_reset = SecureRandom.urlsafe_base64|,
        ~S|SecureRandom.random_bytes(32)|,
        ~S|SecureRandom.base64(24)|,
        ~S|randomize_tests if defined?(rand)|
      ]

      for code <- safe_code do
        refute Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Should not match: #{code}"
      end
    end

    test "documents regex limitations for comment detection" do
      # NOTE: This pattern has a known limitation - it will match commented-out code
      # This is acceptable because AST enhancement will filter out comments in practice
      commented_code = ~S|# Old code: rand(100)|
      pattern = WeakRandom.pattern()

      # This will match, but AST enhancement filters it out
      assert Enum.any?(pattern.regex, &Regex.match?(&1, commented_code)),
             "Expected regex limitation: matches comments (filtered by AST)"
    end
  end

  describe "vulnerability_metadata/0" do
    test "returns comprehensive metadata" do
      metadata = WeakRandom.vulnerability_metadata()

      assert metadata.description =~ "weak random"
      assert length(metadata.references) >= 3
      assert length(metadata.attack_vectors) >= 5
      assert length(metadata.real_world_impact) >= 3
      assert length(metadata.cve_examples) >= 2
    end

    test "includes CVE examples from research" do
      metadata = WeakRandom.vulnerability_metadata()

      cve_ids = Enum.map(metadata.cve_examples, & &1.id)
      assert Enum.any?(cve_ids, &String.contains?(&1, "CVE-"))
    end

    test "includes proper references" do
      metadata = WeakRandom.vulnerability_metadata()

      ref_types = Enum.map(metadata.references, & &1.type)
      assert :cwe in ref_types
      assert :owasp in ref_types
      assert :research in ref_types
    end
  end

  describe "ast_enhancement/0" do
    test "returns proper enhancement rules" do
      enhancement = WeakRandom.ast_enhancement()

      assert Map.has_key?(enhancement, :ast_rules)
      assert Map.has_key?(enhancement, :context_rules)
      assert Map.has_key?(enhancement, :confidence_rules)
      assert Map.has_key?(enhancement, :min_confidence)

      assert enhancement.min_confidence >= 0.6
    end

    test "includes random-specific AST rules" do
      enhancement = WeakRandom.ast_enhancement()

      assert enhancement.ast_rules.node_type == "CallExpression"
      assert "rand" in enhancement.ast_rules.method_names
    end

    test "has cryptographic context detection" do
      enhancement = WeakRandom.ast_enhancement()

      assert enhancement.context_rules.check_cryptographic_context
      assert "SecureRandom" in enhancement.context_rules.safe_libraries
    end
  end
end
