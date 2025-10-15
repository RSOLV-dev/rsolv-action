defmodule Rsolv.Security.Patterns.Ruby.DebugModeEnabledTest do
  use ExUnit.Case, async: true

  alias Rsolv.Security.Patterns.Ruby.DebugModeEnabled
  alias Rsolv.Security.Pattern

  describe "pattern/0" do
    test "returns a valid pattern struct" do
      pattern = DebugModeEnabled.pattern()

      assert %Pattern{} = pattern
      assert pattern.id == "ruby-debug-mode"
      assert pattern.name == "Debug Mode Enabled"
      assert pattern.severity == :medium
      assert pattern.type == :information_disclosure
      assert pattern.languages == ["ruby"]
    end

    test "includes CWE and OWASP references" do
      pattern = DebugModeEnabled.pattern()

      assert pattern.cwe_id == "CWE-489"
      assert pattern.owasp_category == "A05:2021"
    end

    test "has multiple regex patterns" do
      pattern = DebugModeEnabled.pattern()

      assert is_list(pattern.regex)
      assert length(pattern.regex) >= 4
    end
  end

  describe "regex matching" do
    setup do
      pattern = DebugModeEnabled.pattern()
      {:ok, pattern: pattern}
    end

    test "matches pry debugging statements", %{pattern: pattern} do
      vulnerable_code = [
        ~S|require 'pry'|,
        ~S|require "pry"|,
        ~S|binding.pry|,
        ~S|binding.pry if Rails.env.development?|,
        ~S|pry if some_condition|,
        ~S|puts "Debug: #{user}"; binding.pry|
      ]

      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Should match: #{code}"
      end
    end

    test "matches byebug debugging statements", %{pattern: pattern} do
      vulnerable_code = [
        ~S|byebug|,
        ~S|require 'byebug'|,
        ~S|require "byebug"|,
        ~S|byebug if Rails.env.development?|,
        ~S|puts "Starting debug"; byebug|
      ]

      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Should match: #{code}"
      end
    end

    test "matches debugger statements", %{pattern: pattern} do
      vulnerable_code = [
        ~S|debugger|,
        ~S|require 'debugger'|,
        ~S|debugger if condition|,
        ~S|puts "Break here"; debugger|
      ]

      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Should match: #{code}"
      end
    end

    test "matches capybara debugging helpers", %{pattern: pattern} do
      vulnerable_code = [
        ~S|save_and_open_page|,
        ~S|save_and_open_screenshot|,
        ~S|save_page|,
        ~S|save_screenshot|,
        ~S|page.save_and_open_page|,
        ~S|save_and_open_page(path: "debug.html")|
      ]

      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Should match: #{code}"
      end
    end

    test "matches logging of sensitive information", %{pattern: pattern} do
      vulnerable_code = [
        ~S|Rails.logger.debug "Password: #{password}"|,
        ~S|logger.debug "API key: #{api_key}"|,
        ~S|puts "Token: #{auth_token}"|,
        ~S|Rails.logger.info "Secret: #{secret}"|,
        ~S|logger.warn "Credit card: #{cc_number}"|
      ]

      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Should match: #{code}"
      end
    end

    test "does not match safe debug patterns", %{pattern: pattern} do
      safe_code = [
        ~S|Rails.logger.info "User #{user.email} logged in"|,
        ~S|def pry_something; end|,
        ~S|Rails.logger.debug "Processing request #{request.id}"|,
        ~S|puts "Application started successfully"|,
        ~S|logger.info "Cache cleared"|
      ]

      for code <- safe_code do
        refute Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Should not match: #{code}"
      end
    end

    test "documents regex limitations for comment detection" do
      # NOTE: This pattern has a known limitation - it will match commented-out code
      # This is acceptable because AST enhancement will filter out comments in practice
      pattern = DebugModeEnabled.pattern()

      commented_code = [
        ~S|# binding.pry # Commented out debug|,
        ~S|# TODO: Remove debugger before production|
      ]

      for code <- commented_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Regex limitation: Will match commented code: #{code}"
      end
    end
  end

  describe "vulnerability_metadata/0" do
    test "returns comprehensive metadata" do
      metadata = DebugModeEnabled.vulnerability_metadata()

      assert metadata.description =~ "debug"
      assert length(metadata.references) >= 3
      assert length(metadata.attack_vectors) >= 5
      assert length(metadata.real_world_impact) >= 3
      assert length(metadata.cve_examples) >= 2
    end

    test "includes CVE examples from research" do
      metadata = DebugModeEnabled.vulnerability_metadata()

      cve_ids = Enum.map(metadata.cve_examples, & &1.id)
      assert Enum.any?(cve_ids, &String.contains?(&1, "CVE-"))
    end

    test "includes proper references" do
      metadata = DebugModeEnabled.vulnerability_metadata()

      ref_types = Enum.map(metadata.references, & &1.type)
      assert :cwe in ref_types
      assert :owasp in ref_types
      assert :research in ref_types
    end
  end

  describe "ast_enhancement/0" do
    test "returns proper enhancement rules" do
      enhancement = DebugModeEnabled.ast_enhancement()

      assert Map.has_key?(enhancement, :ast_rules)
      assert Map.has_key?(enhancement, :context_rules)
      assert Map.has_key?(enhancement, :confidence_rules)
      assert Map.has_key?(enhancement, :min_confidence)

      assert enhancement.min_confidence >= 0.7
    end

    test "includes debug-specific AST rules" do
      enhancement = DebugModeEnabled.ast_enhancement()

      assert enhancement.ast_rules.node_type == "CallExpression"

      assert "pry" in enhancement.ast_rules.method_names ||
               "pry" in enhancement.ast_rules.require_names
    end

    test "has production environment detection" do
      enhancement = DebugModeEnabled.ast_enhancement()

      assert enhancement.context_rules.check_environment_context
      assert "production" in enhancement.context_rules.danger_environments
    end
  end
end
