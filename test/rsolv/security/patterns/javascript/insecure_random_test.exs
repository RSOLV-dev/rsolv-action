defmodule Rsolv.Security.Patterns.Javascript.InsecureRandomTest do
  use ExUnit.Case, async: true
  doctest Rsolv.Security.Patterns.Javascript.InsecureRandom
  
  alias Rsolv.Security.Pattern
  alias Rsolv.Security.Patterns.Javascript.InsecureRandom

  describe "pattern/0" do
    test "returns correct pattern structure" do
      pattern = InsecureRandom.pattern()
      
      assert %Pattern{} = pattern
      assert pattern.id == "js-insecure-random"
      assert pattern.name == "Insecure Random Number Generation"
      assert pattern.type == :insecure_random
      assert pattern.severity == :medium
      assert pattern.languages == ["javascript", "typescript"]
      assert pattern.cwe_id == "CWE-330"
      assert pattern.owasp_category == "A02:2021"
    end

    test "pattern has required metadata" do
      pattern = InsecureRandom.pattern()
      
      assert pattern.description =~ "Math.random"
      assert pattern.recommendation =~ "crypto.randomBytes"
      assert is_map(pattern.test_cases)
      assert is_list(pattern.test_cases.vulnerable)
      assert is_list(pattern.test_cases.safe)
    end
  end

  describe "vulnerability_metadata/0" do
    test "returns comprehensive vulnerability metadata" do
      metadata = InsecureRandom.vulnerability_metadata()
      
      assert is_map(metadata)
      assert is_binary(metadata.description)
      assert is_list(metadata.references)
      assert is_list(metadata.attack_vectors)
      assert is_list(metadata.real_world_impact)
      assert is_list(metadata.cve_examples)
      assert is_list(metadata.safe_alternatives)
    end

    test "metadata includes required reference types" do
      metadata = InsecureRandom.vulnerability_metadata()
      references = metadata.references
      
      assert Enum.any?(references, &(&1.type == :cwe))
      assert Enum.any?(references, &(&1.type == :owasp))
    end

    test "metadata includes cryptographic security information" do
      metadata = InsecureRandom.vulnerability_metadata()
      
      assert metadata.description =~ "cryptographic" || metadata.description =~ "predictable"
      assert metadata.description =~ "Math.random"
    end
  end

  describe "detection tests" do
    test "detects Math.random used for security tokens" do
      pattern = InsecureRandom.pattern()
      
      vulnerable_codes = [
        ~S|const token = Math.random().toString()|,
        ~S|const sessionId = Math.random() * 1000000|,
        ~S|const salt = Math.random().toString(36)|,
        ~S|const password = Math.random().toString(16)|,
        ~S|const apiKey = "key-" + Math.random()|
      ]
      
      for code <- vulnerable_codes do
        assert Regex.match?(pattern.regex, code), "Should detect: #{code}"
      end
    end

    test "detects various patterns of insecure randomness" do
      pattern = InsecureRandom.pattern()
      
      vulnerable_codes = [
        ~S|let secret = Math.random() * Date.now()|,
        ~S|const nonce = Math.floor(Math.random() * 1000000)|,
        ~S|var authToken = btoa(Math.random())|,
        ~S|const key = Math.random().toString().substring(2)|
      ]
      
      for code <- vulnerable_codes do
        assert Regex.match?(pattern.regex, code), "Should detect: #{code}"
      end
    end
  end

  describe "safe code validation" do
    test "does not match secure random generation" do
      pattern = InsecureRandom.pattern()
      
      safe_codes = [
        ~S|const token = crypto.randomBytes(32).toString('hex')|,
        ~S|const sessionId = crypto.randomUUID()|,
        ~S|const salt = crypto.getRandomValues(new Uint8Array(16))|,
        ~S|const id = require('uuid').v4()|
      ]
      
      for code <- safe_codes do
        refute Regex.match?(pattern.regex, code), "Should not match: #{code}"
      end
    end

    test "does not match non-security Math.random usage" do
      pattern = InsecureRandom.pattern()
      
      safe_codes = [
        ~S|const randomIndex = Math.floor(Math.random() * array.length)|,
        ~S|const x = Math.random() * canvas.width|,
        ~S|const delay = Math.random() * 1000|,
        ~S|const color = Math.floor(Math.random() * 255)|
      ]
      
      for code <- safe_codes do
        refute Regex.match?(pattern.regex, code), "Should not match: #{code}"
      end
    end
  end

  describe "applies_to_file?/1" do
    test "applies to JavaScript files" do
      assert InsecureRandom.applies_to_file?("app.js", nil)
      assert InsecureRandom.applies_to_file?("crypto.mjs", nil)
      assert InsecureRandom.applies_to_file?("utils/tokens.js", nil)
    end

    test "applies to TypeScript files" do
      assert InsecureRandom.applies_to_file?("app.ts", nil)
      assert InsecureRandom.applies_to_file?("auth.tsx", nil)
      assert InsecureRandom.applies_to_file?("src/security.ts", nil)
    end

    test "does not apply to non-JS/TS files" do
      refute InsecureRandom.applies_to_file?("config.json", nil)
      refute InsecureRandom.applies_to_file?("app.py", nil)
      refute InsecureRandom.applies_to_file?("style.css", nil)
    end
  end
  
  describe "ast_enhancement/0" do
    test "returns complete AST enhancement structure" do
      enhancement = InsecureRandom.ast_enhancement()
      
      assert is_map(enhancement)
      assert Map.has_key?(enhancement, :ast_rules)
      assert Map.has_key?(enhancement, :context_rules)
      assert Map.has_key?(enhancement, :confidence_rules)
      assert Map.has_key?(enhancement, :min_confidence)
    end
    
    test "AST rules specify Math.random patterns" do
      enhancement = InsecureRandom.ast_enhancement()
      
      assert enhancement.ast_rules.node_type == "CallExpression"
      assert enhancement.ast_rules.callee_pattern == "Math.random"
      assert is_map(enhancement.ast_rules.usage_analysis)
    end
    
    test "context rules exclude appropriate usage" do
      enhancement = InsecureRandom.ast_enhancement()
      
      assert is_list(enhancement.context_rules.exclude_paths)
      assert enhancement.context_rules.exclude_if_game_logic == true
      assert enhancement.context_rules.exclude_if_animation == true
    end
    
    test "confidence rules provide appropriate scoring" do
      enhancement = InsecureRandom.ast_enhancement()
      
      assert is_number(enhancement.confidence_rules.base)
      assert is_map(enhancement.confidence_rules.adjustments)
      assert Map.has_key?(enhancement.confidence_rules.adjustments, "assigned_to_security_var")
      assert enhancement.min_confidence == 0.7
    end
  end
end