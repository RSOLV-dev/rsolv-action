defmodule Rsolv.Security.Patterns.Javascript.JwtNoneAlgorithmTest do
  use ExUnit.Case, async: true
  doctest Rsolv.Security.Patterns.Javascript.JwtNoneAlgorithm

  alias Rsolv.Security.Pattern
  alias Rsolv.Security.Patterns.Javascript.JwtNoneAlgorithm

  describe "pattern/0" do
    test "returns correct pattern structure" do
      pattern = JwtNoneAlgorithm.pattern()

      assert %Pattern{} = pattern
      assert pattern.id == "js-jwt-none-algorithm"
      assert pattern.name == "JWT None Algorithm Vulnerability"
      assert pattern.type == :authentication
      assert pattern.severity == :high
      assert pattern.languages == ["javascript", "typescript"]
      assert pattern.cwe_id == "CWE-347"
      assert pattern.owasp_category == "A02:2021"
    end

    test "pattern has required metadata" do
      pattern = JwtNoneAlgorithm.pattern()

      assert pattern.description =~ "JWT"
      assert pattern.recommendation =~ "algorithm"
      assert is_map(pattern.test_cases)
      assert is_list(pattern.test_cases.vulnerable)
      assert is_list(pattern.test_cases.safe)
    end
  end

  describe "vulnerability_metadata/0" do
    test "returns comprehensive vulnerability metadata" do
      metadata = JwtNoneAlgorithm.vulnerability_metadata()

      assert is_map(metadata)
      assert is_binary(metadata.description)
      assert is_list(metadata.references)
      assert is_list(metadata.attack_vectors)
      assert is_list(metadata.real_world_impact)
      assert is_list(metadata.cve_examples)
      assert is_list(metadata.safe_alternatives)
    end

    test "metadata includes required reference types" do
      metadata = JwtNoneAlgorithm.vulnerability_metadata()
      references = metadata.references

      assert Enum.any?(references, &(&1.type == :cwe))
      assert Enum.any?(references, &(&1.type == :owasp))
    end

    test "metadata includes JWT-specific information" do
      metadata = JwtNoneAlgorithm.vulnerability_metadata()

      # Should mention JWT and none algorithm
      assert metadata.description =~ "JWT" || metadata.description =~ "none"
      assert metadata.description =~ "algorithm"

      # Should have JWT-specific attack vectors
      assert Enum.any?(metadata.attack_vectors, &(&1 =~ "none"))
    end
  end

  describe "detection tests" do
    test "detects jwt.verify without algorithms parameter" do
      pattern = JwtNoneAlgorithm.pattern()

      vulnerable_codes = [
        ~S|jwt.verify(token, secret)|,
        ~S|jwt.verify(token, publicKey)|,
        ~S|const decoded = jwt.verify(req.headers.authorization, key)|,
        ~S|return jwt.verify(authToken, process.env.JWT_SECRET)|
      ]

      for code <- vulnerable_codes do
        assert Regex.match?(pattern.regex, code), "Should detect: #{code}"
      end
    end

    test "detects jwt.verify with options but no algorithms" do
      pattern = JwtNoneAlgorithm.pattern()

      vulnerable_codes = [
        ~S|jwt.verify(token, publicKey, {issuer: 'myapp'})|,
        ~S|jwt.verify(token, secret, {audience: 'users'})|,
        ~S|jwt.verify(token, key, {expiresIn: '1h'})|,
        ~S|jwt.verify(token, secret, {complete: true})|
      ]

      for code <- vulnerable_codes do
        assert Regex.match?(pattern.regex, code), "Should detect: #{code}"
      end
    end
  end

  describe "safe code validation" do
    test "does not match jwt.verify with algorithms specified" do
      pattern = JwtNoneAlgorithm.pattern()

      safe_codes = [
        ~S|jwt.verify(token, secret, {algorithms: ['HS256']})|,
        ~S|jwt.verify(token, publicKey, {algorithms: ['RS256'], issuer: 'myapp'})|,
        ~S|jwt.verify(token, key, {algorithms: ['HS256', 'HS384', 'HS512']})|,
        ~S|jwt.verify(token, cert, {algorithms: ['ES256']})|
      ]

      for code <- safe_codes do
        refute Regex.match?(pattern.regex, code), "Should not match: #{code}"
      end
    end

    test "does not match other jwt methods" do
      pattern = JwtNoneAlgorithm.pattern()

      safe_codes = [
        ~S|jwt.sign(payload, secret)|,
        ~S|jwt.decode(token)|,
        ~S|jwt.refresh(token, secret)|
      ]

      for code <- safe_codes do
        refute Regex.match?(pattern.regex, code), "Should not match: #{code}"
      end
    end
  end

  describe "applies_to_file?/1" do
    test "applies to JavaScript files" do
      assert JwtNoneAlgorithm.applies_to_file?("auth.js", nil)
      assert JwtNoneAlgorithm.applies_to_file?("middleware/jwt.js", nil)
      assert JwtNoneAlgorithm.applies_to_file?("src/auth/verify.js", nil)
    end

    test "applies to TypeScript files" do
      assert JwtNoneAlgorithm.applies_to_file?("auth.ts", nil)
      assert JwtNoneAlgorithm.applies_to_file?("middleware/jwt.tsx", nil)
      assert JwtNoneAlgorithm.applies_to_file?("src/auth/verify.ts", nil)
    end

    test "does not apply to non-JS/TS files" do
      refute JwtNoneAlgorithm.applies_to_file?("config.json", nil)
      refute JwtNoneAlgorithm.applies_to_file?("auth.py", nil)
      refute JwtNoneAlgorithm.applies_to_file?("Gemfile", nil)
    end
  end

  describe "ast_enhancement/0" do
    test "returns complete AST enhancement structure" do
      enhancement = JwtNoneAlgorithm.ast_enhancement()

      assert is_map(enhancement)
      assert Map.has_key?(enhancement, :ast_rules)
      assert Map.has_key?(enhancement, :context_rules)
      assert Map.has_key?(enhancement, :confidence_rules)
      assert Map.has_key?(enhancement, :min_confidence)
    end

    test "AST rules specify jwt.verify patterns" do
      enhancement = JwtNoneAlgorithm.ast_enhancement()

      assert enhancement.ast_rules.node_type == "CallExpression"
      assert enhancement.ast_rules.callee_pattern == "jwt.verify"
      assert is_map(enhancement.ast_rules.argument_analysis)
      assert enhancement.ast_rules.argument_analysis.missing_algorithms_option == true
    end

    test "context rules exclude test files" do
      enhancement = JwtNoneAlgorithm.ast_enhancement()

      assert is_list(enhancement.context_rules.exclude_paths)
      assert enhancement.context_rules.exclude_if_algorithms_enforced == true
      assert is_list(enhancement.context_rules.safe_jwt_libraries)
    end

    test "confidence rules provide appropriate scoring" do
      enhancement = JwtNoneAlgorithm.ast_enhancement()

      assert is_number(enhancement.confidence_rules.base)
      assert is_map(enhancement.confidence_rules.adjustments)
      assert Map.has_key?(enhancement.confidence_rules.adjustments, "no_algorithms_option")
      assert Map.has_key?(enhancement.confidence_rules.adjustments, "has_algorithms_option")
      assert enhancement.min_confidence == 0.7
    end
  end
end
