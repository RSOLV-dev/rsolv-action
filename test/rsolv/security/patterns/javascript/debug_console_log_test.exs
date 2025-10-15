defmodule Rsolv.Security.Patterns.Javascript.DebugConsoleLogTest do
  use ExUnit.Case, async: true
  doctest Rsolv.Security.Patterns.Javascript.DebugConsoleLog

  alias Rsolv.Security.Pattern
  alias Rsolv.Security.Patterns.Javascript.DebugConsoleLog

  describe "pattern/0" do
    test "returns correct pattern structure" do
      pattern = DebugConsoleLog.pattern()

      assert %Pattern{} = pattern
      assert pattern.id == "js-debug-console-log"
      assert pattern.name == "Sensitive Data in Console Logs"
      assert pattern.type == :information_disclosure
      assert pattern.severity == :low
      assert pattern.languages == ["javascript", "typescript"]
      assert pattern.cwe_id == "CWE-532"
      assert pattern.owasp_category == "A09:2021"
    end

    test "pattern has required metadata" do
      pattern = DebugConsoleLog.pattern()

      assert pattern.description =~ "Console"
      assert pattern.recommendation =~ "Remove console.log"
      assert is_map(pattern.test_cases)
      assert is_list(pattern.test_cases.vulnerable)
      assert is_list(pattern.test_cases.safe)
    end
  end

  describe "vulnerability_metadata/0" do
    test "returns comprehensive vulnerability metadata" do
      metadata = DebugConsoleLog.vulnerability_metadata()

      assert is_map(metadata)
      assert is_binary(metadata.description)
      assert is_list(metadata.references)
      assert is_list(metadata.attack_vectors)
      assert is_list(metadata.real_world_impact)
      assert is_list(metadata.cve_examples)
      assert is_list(metadata.safe_alternatives)
    end

    test "metadata includes required reference types" do
      metadata = DebugConsoleLog.vulnerability_metadata()
      references = metadata.references

      assert Enum.any?(references, &(&1.type == :cwe))
      assert Enum.any?(references, &(&1.type == :owasp))
    end

    test "metadata includes console logging specific information" do
      metadata = DebugConsoleLog.vulnerability_metadata()

      assert metadata.description =~ "console" || metadata.description =~ "log"
      assert metadata.description =~ "sensitive"
    end
  end

  describe "detection tests" do
    test "detects console.log with sensitive data keywords" do
      pattern = DebugConsoleLog.pattern()

      vulnerable_codes = [
        ~S|console.log(password)|,
        ~S|console.error("Auth failed for token:", token)|,
        ~S|console.info({apiKey: config.apiKey})|,
        ~S|console.warn("Secret:", userSecret)|,
        ~S|console.log("Credentials:", credentials)|
      ]

      for code <- vulnerable_codes do
        assert Regex.match?(pattern.regex, code), "Should detect: #{code}"
      end
    end

    test "detects various console methods with sensitive data" do
      pattern = DebugConsoleLog.pattern()

      vulnerable_codes = [
        ~S|console.log("API Key: " + apiKey)|,
        ~S|console.error(`Password reset token: ${token}`)|,
        ~S|console.warn("Auth header:", req.headers.authorization)|,
        ~S|console.info("privateKey:", key)|
      ]

      for code <- vulnerable_codes do
        assert Regex.match?(pattern.regex, code), "Should detect: #{code}"
      end
    end
  end

  describe "safe code validation" do
    test "does not match safe console.log usage" do
      pattern = DebugConsoleLog.pattern()

      safe_codes = [
        ~S|console.log("Login attempt for user:", username)|,
        ~S|console.log("Request received")|,
        ~S|console.error("Invalid input")|,
        ~S|logger.debug("User authenticated", {userId: user.id})|
      ]

      for code <- safe_codes do
        refute Regex.match?(pattern.regex, code), "Should not match: #{code}"
      end
    end

    test "does not match conditional logging" do
      pattern = DebugConsoleLog.pattern()

      safe_codes = [
        ~S|if (isDevelopment) { console.log(debugInfo) }|,
        ~S|if (process.env.NODE_ENV !== 'production') console.log(data)|,
        ~S|DEBUG && console.log(sensitiveData)|
      ]

      for code <- safe_codes do
        refute Regex.match?(pattern.regex, code), "Should not match: #{code}"
      end
    end
  end

  describe "applies_to_file?/1" do
    test "applies to JavaScript files" do
      assert DebugConsoleLog.applies_to_file?("app.js", nil)
      assert DebugConsoleLog.applies_to_file?("server.mjs", nil)
      assert DebugConsoleLog.applies_to_file?("utils/logger.js", nil)
    end

    test "applies to TypeScript files" do
      assert DebugConsoleLog.applies_to_file?("app.ts", nil)
      assert DebugConsoleLog.applies_to_file?("server.tsx", nil)
      assert DebugConsoleLog.applies_to_file?("src/debug.ts", nil)
    end

    test "does not apply to non-JS/TS files" do
      refute DebugConsoleLog.applies_to_file?("config.json", nil)
      refute DebugConsoleLog.applies_to_file?("app.py", nil)
      refute DebugConsoleLog.applies_to_file?("style.css", nil)
    end
  end

  describe "ast_enhancement/0" do
    test "returns complete AST enhancement structure" do
      enhancement = DebugConsoleLog.ast_enhancement()

      assert is_map(enhancement)
      assert Map.has_key?(enhancement, :ast_rules)
      assert Map.has_key?(enhancement, :context_rules)
      assert Map.has_key?(enhancement, :confidence_rules)
      assert Map.has_key?(enhancement, :min_confidence)
    end

    test "AST rules specify console method patterns" do
      enhancement = DebugConsoleLog.ast_enhancement()

      assert enhancement.ast_rules.node_type == "CallExpression"
      assert is_list(enhancement.ast_rules.callee_patterns)
      assert "console.log" in enhancement.ast_rules.callee_patterns
      assert is_map(enhancement.ast_rules.argument_analysis)
    end

    test "context rules exclude production guards" do
      enhancement = DebugConsoleLog.ast_enhancement()

      assert is_list(enhancement.context_rules.exclude_paths)
      assert enhancement.context_rules.exclude_if_conditional == true
      assert enhancement.context_rules.exclude_if_production_check == true
    end

    test "confidence rules provide appropriate scoring" do
      enhancement = DebugConsoleLog.ast_enhancement()

      assert is_number(enhancement.confidence_rules.base)
      assert is_map(enhancement.confidence_rules.adjustments)
      assert Map.has_key?(enhancement.confidence_rules.adjustments, "has_sensitive_keyword")
      assert enhancement.min_confidence == 0.6
    end
  end
end
