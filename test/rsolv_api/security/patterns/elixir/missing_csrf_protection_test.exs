defmodule RsolvApi.Security.Patterns.Elixir.MissingCsrfProtectionTest do
  use ExUnit.Case, async: true

  alias RsolvApi.Security.Patterns.Elixir.MissingCsrfProtection
  alias RsolvApi.Security.Pattern

  describe "pattern/0" do
    test "returns correct pattern structure" do
      pattern = MissingCsrfProtection.pattern()
      
      assert %Pattern{} = pattern
      assert pattern.id == "elixir-missing-csrf-protection"
      assert pattern.name == "Missing CSRF Protection"
      assert pattern.type == :csrf
      assert pattern.severity == :medium
      assert pattern.languages == ["elixir"]
      assert pattern.frameworks == ["phoenix"]
      assert pattern.cwe_id == "CWE-352"
      assert pattern.owasp_category == "A01:2021"
      assert is_list(pattern.regex) or pattern.regex.__struct__ == Regex
    end

    test "pattern has comprehensive test cases" do
      pattern = MissingCsrfProtection.pattern()
      
      assert Map.has_key?(pattern.test_cases, :vulnerable)
      assert Map.has_key?(pattern.test_cases, :safe)
      assert length(pattern.test_cases.vulnerable) >= 3
      assert length(pattern.test_cases.safe) >= 3
    end
  end

  describe "vulnerability_metadata/0" do
    test "returns comprehensive metadata" do
      metadata = MissingCsrfProtection.vulnerability_metadata()
      
      assert is_map(metadata)
      assert Map.has_key?(metadata, :description)
      assert Map.has_key?(metadata, :references)
      assert Map.has_key?(metadata, :attack_vectors)
      assert Map.has_key?(metadata, :real_world_impact)
      assert Map.has_key?(metadata, :cve_examples)
      assert Map.has_key?(metadata, :safe_alternatives)
      
      assert String.length(metadata.description) > 100
      assert length(metadata.references) >= 3
      assert length(metadata.attack_vectors) >= 3
      assert length(metadata.cve_examples) >= 1
    end

    test "includes CSRF and Phoenix information" do
      metadata = MissingCsrfProtection.vulnerability_metadata()
      
      # Should mention CSRF and Phoenix
      assert String.contains?(metadata.description, "CSRF") or
             String.contains?(metadata.description, "Cross-Site Request Forgery") or
             String.contains?(metadata.description, "Phoenix")
      
      # Should mention form protection
      assert Enum.any?(metadata.safe_alternatives, &String.contains?(&1, "form")) or
             Enum.any?(metadata.safe_alternatives, &String.contains?(&1, "token"))
    end

    test "references include CWE-352 and OWASP A01:2021" do
      metadata = MissingCsrfProtection.vulnerability_metadata()
      
      cwe_ref = Enum.find(metadata.references, &(&1.type == :cwe))
      assert cwe_ref.id == "CWE-352"
      
      owasp_ref = Enum.find(metadata.references, &(&1.type == :owasp))
      assert owasp_ref.id == "A01:2021"
    end

    test "includes Phoenix-specific CSRF information" do
      metadata = MissingCsrfProtection.vulnerability_metadata()
      
      # Should reference Phoenix or form_for
      references_text = Enum.map(metadata.references, &(&1.title)) |> Enum.join(" ")
      assert String.contains?(references_text, "Phoenix") or
             String.contains?(references_text, "CSRF") or
             String.contains?(references_text, "OWASP")
    end
  end

  describe "ast_enhancement/0" do
    test "returns proper AST enhancement structure" do
      enhancement = MissingCsrfProtection.ast_enhancement()
      
      assert is_map(enhancement)
      assert Map.has_key?(enhancement, :ast_rules)
      assert Map.has_key?(enhancement, :context_rules)
      assert Map.has_key?(enhancement, :confidence_rules)
      assert Map.has_key?(enhancement, :min_confidence)
      
      assert enhancement.min_confidence >= 0.7
    end

    test "AST rules check for form construction" do
      enhancement = MissingCsrfProtection.ast_enhancement()
      
      assert enhancement.ast_rules.node_type == "CallExpression"
      assert Map.has_key?(enhancement.ast_rules, :form_analysis)
      assert enhancement.ast_rules.form_analysis.check_form_helpers == true
    end

    test "context rules identify Phoenix forms" do
      enhancement = MissingCsrfProtection.ast_enhancement()
      
      assert Map.has_key?(enhancement.context_rules, :phoenix_contexts)
      assert "form_for" in enhancement.context_rules.phoenix_contexts
      assert "form_with" in enhancement.context_rules.phoenix_contexts
    end

    test "confidence adjustments for CSRF context" do
      enhancement = MissingCsrfProtection.ast_enhancement()
      
      assert Map.has_key?(enhancement.confidence_rules.adjustments, "csrf_disabled")
      assert Map.has_key?(enhancement.confidence_rules.adjustments, "state_changing_form")
    end
  end

  describe "vulnerable code detection" do
    test "detects form_for with csrf_token: false" do
      pattern = MissingCsrfProtection.pattern()
      
      vulnerable_code = ~S|form_for(@changeset, Routes.user_path(@conn, :create), [csrf_token: false], fn f ->|
      assert pattern_matches?(pattern, vulnerable_code)
      
      vulnerable_code2 = ~S|form_for(@user, "/users", csrf_token: false, fn f ->|
      assert pattern_matches?(pattern, vulnerable_code2)
    end

    test "detects form_with with csrf: false" do
      pattern = MissingCsrfProtection.pattern()
      
      vulnerable_code = ~S|form_with(@changeset, csrf: false) do|
      assert pattern_matches?(pattern, vulnerable_code)
    end

    test "detects Phoenix.HTML.Form.form_for with disabled CSRF" do
      pattern = MissingCsrfProtection.pattern()
      
      vulnerable_code = ~S|Phoenix.HTML.Form.form_for(@changeset, @action, [csrf_token: false])|
      assert pattern_matches?(pattern, vulnerable_code)
    end

    test "detects multiline form_for with csrf_token: false" do
      pattern = MissingCsrfProtection.pattern()
      
      vulnerable_code = """
      form_for(
        @changeset,
        Routes.user_path(@conn, :create),
        [csrf_token: false],
        fn f ->
      """
      assert pattern_matches?(pattern, vulnerable_code)
    end

    test "detects manual form with missing csrf_token" do
      pattern = MissingCsrfProtection.pattern()
      
      vulnerable_code = ~S|<form action="/submit" method="post">|
      assert pattern_matches?(pattern, vulnerable_code)
    end

    test "detects Plug.CSRFProtection.delete_csrf_token/0 usage" do
      pattern = MissingCsrfProtection.pattern()
      
      vulnerable_code = ~S|Plug.CSRFProtection.delete_csrf_token()|
      assert pattern_matches?(pattern, vulnerable_code)
    end
  end

  describe "safe code validation" do
    test "does not match form_for with default CSRF protection" do
      pattern = MissingCsrfProtection.pattern()
      
      safe_code = ~S|form_for(@changeset, Routes.user_path(@conn, :create), fn f ->|
      refute pattern_matches?(pattern, safe_code)
    end

    test "does not match form_for with explicit csrf_token: true" do
      pattern = MissingCsrfProtection.pattern()
      
      safe_code = ~S|form_for(@changeset, Routes.user_path(@conn, :create), [csrf_token: true], fn f ->|
      refute pattern_matches?(pattern, safe_code)
    end

    test "does not match form_with with default CSRF" do
      pattern = MissingCsrfProtection.pattern()
      
      safe_code = ~S|form_with(@changeset) do|
      refute pattern_matches?(pattern, safe_code)
    end

    test "does not match forms with hidden csrf fields" do
      pattern = MissingCsrfProtection.pattern()
      
      safe_code = ~S|<form><input type="hidden" name="_csrf_token" value="<%= csrf_token %>"></form>|
      refute pattern_matches?(pattern, safe_code)
    end

    test "does not match GET forms (no CSRF needed)" do
      pattern = MissingCsrfProtection.pattern()
      
      safe_code = ~S|<form action="/search" method="get">|
      refute pattern_matches?(pattern, safe_code)
    end
  end

  describe "enhanced_pattern/0" do
    test "uses ast_enhancement for better detection" do
      enhanced = MissingCsrfProtection.enhanced_pattern()
      
      assert enhanced.id == "elixir-missing-csrf-protection"
      assert Map.has_key?(enhanced, :ast_enhancement)
      assert enhanced.ast_enhancement == MissingCsrfProtection.ast_enhancement()
    end
  end

  # Helper function to check if pattern matches
  defp pattern_matches?(pattern, code) do
    case pattern.regex do
      regexes when is_list(regexes) ->
        Enum.any?(regexes, fn regex -> Regex.match?(regex, code) end)
      regex ->
        Regex.match?(regex, code)
    end
  end
end