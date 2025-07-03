defmodule Rsolv.Security.Patterns.Javascript.TimingAttackComparisonTest do
  use ExUnit.Case, async: true
  doctest Rsolv.Security.Patterns.Javascript.TimingAttackComparison
  
  alias Rsolv.Security.Pattern
  alias Rsolv.Security.Patterns.Javascript.TimingAttackComparison

  describe "pattern/0" do
    test "returns correct pattern structure" do
      pattern = TimingAttackComparison.pattern()
      
      assert %Pattern{} = pattern
      assert pattern.id == "js-timing-attack"
      assert pattern.name == "Timing Attack via String Comparison"
      assert pattern.type == :timing_attack
      assert pattern.severity == :low
      assert pattern.languages == ["javascript", "typescript"]
      assert pattern.cwe_id == "CWE-208"
      assert pattern.owasp_category == "A04:2021"
    end

    test "pattern has required metadata" do
      pattern = TimingAttackComparison.pattern()
      
      assert pattern.description =~ "timing"
      assert pattern.recommendation =~ "timingSafeEqual"
      assert is_map(pattern.test_cases)
      assert is_list(pattern.test_cases.vulnerable)
      assert is_list(pattern.test_cases.safe)
    end
  end

  describe "vulnerability_metadata/0" do
    test "returns comprehensive vulnerability metadata" do
      metadata = TimingAttackComparison.vulnerability_metadata()
      
      assert is_map(metadata)
      assert is_binary(metadata.description)
      assert is_list(metadata.references)
      assert is_list(metadata.attack_vectors)
      assert is_list(metadata.real_world_impact)
      assert is_list(metadata.cve_examples)
      assert is_list(metadata.safe_alternatives)
    end

    test "metadata includes required reference types" do
      metadata = TimingAttackComparison.vulnerability_metadata()
      references = metadata.references
      
      assert Enum.any?(references, &(&1.type == :cwe))
      assert Enum.any?(references, &(&1.type == :owasp))
    end

    test "metadata includes timing attack specific information" do
      metadata = TimingAttackComparison.vulnerability_metadata()
      
      assert metadata.description =~ "timing" || metadata.description =~ "constant"
      assert metadata.description =~ "comparison"
    end
  end

  describe "detection tests" do
    test "detects direct string comparison of secrets" do
      pattern = TimingAttackComparison.pattern()
      
      vulnerable_codes = [
        ~S|if (userToken === secretToken)|,
        ~s|return password == storedPassword|,
        ~S|if (req.headers.authorization !== apiKey)|,
        ~S|const valid = hash === expectedHash|,
        ~S|if (token != expectedToken) return false|
      ]
      
      for code <- vulnerable_codes do
        assert Regex.match?(pattern.regex, code), "Should detect: #{code}"
      end
    end

    test "detects various patterns of insecure comparison" do
      pattern = TimingAttackComparison.pattern()
      
      vulnerable_codes = [
        ~S|userSecret === dbSecret|,
        ~S|inputKey == config.apiKey|,
        ~S|authToken !== expectedToken|,
        ~S|return userPassword === savedPassword|
      ]
      
      for code <- vulnerable_codes do
        assert Regex.match?(pattern.regex, code), "Should detect: #{code}"
      end
    end
  end

  describe "safe code validation" do
    test "does not match timing-safe comparisons" do
      pattern = TimingAttackComparison.pattern()
      
      safe_codes = [
        ~S|crypto.timingSafeEqual(Buffer.from(userToken), Buffer.from(secretToken))|,
        ~S|bcrypt.compare(password, storedPassword)|,
        ~S|const valid = timingSafeCompare(req.headers.authorization, apiKey)|,
        ~S|return await argon2.verify(storedHash, password)|
      ]
      
      for code <- safe_codes do
        refute Regex.match?(pattern.regex, code), "Should not match: #{code}"
      end
    end

    test "does not match non-secret comparisons" do
      pattern = TimingAttackComparison.pattern()
      
      safe_codes = [
        ~S|if (username === "admin")|,
        ~S|return status == 200|,
        ~S|if (count !== expected)|,
        ~S|const isValid = input === validated|
      ]
      
      for code <- safe_codes do
        refute Regex.match?(pattern.regex, code), "Should not match: #{code}"
      end
    end
  end

  describe "applies_to_file?/1" do
    test "applies to JavaScript files" do
      assert TimingAttackComparison.applies_to_file?("app.js", nil)
      assert TimingAttackComparison.applies_to_file?("auth.mjs", nil)
      assert TimingAttackComparison.applies_to_file?("utils/compare.js", nil)
    end

    test "applies to TypeScript files" do
      assert TimingAttackComparison.applies_to_file?("app.ts", nil)
      assert TimingAttackComparison.applies_to_file?("auth.tsx", nil)
      assert TimingAttackComparison.applies_to_file?("src/security.ts", nil)
    end

    test "does not apply to non-JS/TS files" do
      refute TimingAttackComparison.applies_to_file?("config.json", nil)
      refute TimingAttackComparison.applies_to_file?("app.py", nil)
      refute TimingAttackComparison.applies_to_file?("style.css", nil)
    end
  end
  
  describe "ast_enhancement/0" do
    test "returns complete AST enhancement structure" do
      enhancement = TimingAttackComparison.ast_enhancement()
      
      assert is_map(enhancement)
      assert Map.has_key?(enhancement, :ast_rules)
      assert Map.has_key?(enhancement, :context_rules)
      assert Map.has_key?(enhancement, :confidence_rules)
      assert Map.has_key?(enhancement, :min_confidence)
    end
    
    test "AST rules specify comparison operators" do
      enhancement = TimingAttackComparison.ast_enhancement()
      
      assert enhancement.ast_rules.node_type == "BinaryExpression"
      assert is_list(enhancement.ast_rules.operators)
      assert "===" in enhancement.ast_rules.operators
      assert is_map(enhancement.ast_rules.operand_analysis)
    end
    
    test "context rules exclude safe patterns" do
      enhancement = TimingAttackComparison.ast_enhancement()
      
      assert is_list(enhancement.context_rules.exclude_paths)
      assert enhancement.context_rules.exclude_if_timing_safe == true
      assert is_list(enhancement.context_rules.safe_functions)
    end
    
    test "confidence rules provide appropriate scoring" do
      enhancement = TimingAttackComparison.ast_enhancement()
      
      assert is_number(enhancement.confidence_rules.base)
      assert is_map(enhancement.confidence_rules.adjustments)
      assert Map.has_key?(enhancement.confidence_rules.adjustments, "compares_secret_variable")
      assert enhancement.min_confidence == 0.6
    end
  end
end