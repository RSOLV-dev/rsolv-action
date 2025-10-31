defmodule Rsolv.Security.Patterns.Elixir.XssRawHtmlTest do
  use ExUnit.Case, async: true

  alias Rsolv.Security.Patterns.Elixir.XssRawHtml
  alias Rsolv.Security.Pattern

  describe "pattern/0" do
    test "returns correct pattern structure" do
      pattern = XssRawHtml.pattern()

      assert %Pattern{} = pattern
      assert pattern.id == "elixir-xss-raw-html"
      assert pattern.name == "XSS via raw/html_safe in Phoenix"
      assert pattern.type == :xss
      assert pattern.severity == :high
      assert pattern.languages == ["elixir"]
      assert pattern.cwe_id == "CWE-79"
      assert pattern.owasp_category == "A03:2021"
      assert is_list(pattern.regex)
      assert length(pattern.regex) > 0
    end

    test "pattern has comprehensive test cases" do
      pattern = XssRawHtml.pattern()

      assert Map.has_key?(pattern.test_cases, :vulnerable)
      assert Map.has_key?(pattern.test_cases, :safe)
      assert length(pattern.test_cases.vulnerable) >= 3
      assert length(pattern.test_cases.safe) >= 3
    end
  end

  describe "vulnerability_metadata/0" do
    test "returns comprehensive metadata" do
      metadata = XssRawHtml.vulnerability_metadata()

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

    test "includes CVE-2021-46871 in examples" do
      metadata = XssRawHtml.vulnerability_metadata()
      cve_ids = Enum.map(metadata.cve_examples, & &1.id)

      assert "CVE-2021-46871" in cve_ids
    end

    test "references include CWE-79 and OWASP A03:2021" do
      metadata = XssRawHtml.vulnerability_metadata()

      cwe_ref = Enum.find(metadata.references, &(&1.type == :cwe))
      assert cwe_ref.id == "CWE-79"

      owasp_ref = Enum.find(metadata.references, &(&1.type == :owasp))
      assert owasp_ref.id == "A03:2021"
    end
  end

  describe "ast_enhancement/0" do
    test "returns proper AST enhancement structure" do
      enhancement = XssRawHtml.ast_enhancement()

      assert is_map(enhancement)
      assert Map.has_key?(enhancement, :ast_rules)
      assert Map.has_key?(enhancement, :context_rules)
      assert Map.has_key?(enhancement, :confidence_rules)
      assert Map.has_key?(enhancement, :min_confidence)

      assert enhancement.min_confidence == 0.7
    end

    test "AST rules check for XSS-specific patterns" do
      enhancement = XssRawHtml.ast_enhancement()

      assert enhancement.ast_rules.node_type == "CallExpression"
      assert Map.has_key?(enhancement.ast_rules, :xss_analysis)
      assert enhancement.ast_rules.xss_analysis.check_html_safety == true
      assert "Phoenix.HTML.raw" in enhancement.ast_rules.xss_analysis.dangerous_functions
    end

    test "context rules exclude test files" do
      enhancement = XssRawHtml.ast_enhancement()

      assert is_list(enhancement.context_rules.exclude_paths)
      assert ~r/test/ in enhancement.context_rules.exclude_paths
    end

    test "confidence adjustments for user input and sanitization" do
      enhancement = XssRawHtml.ast_enhancement()

      assert enhancement.confidence_rules.base == 0.6
      assert Map.has_key?(enhancement.confidence_rules.adjustments, "has_user_input")
      assert Map.has_key?(enhancement.confidence_rules.adjustments, "uses_html_sanitizer")
    end
  end

  describe "vulnerable code detection" do
    test "detects Phoenix.HTML.raw with user input" do
      pattern = XssRawHtml.pattern()

      vulnerable_code = ~S|Phoenix.HTML.raw(user_input)|
      assert Enum.any?(pattern.regex, &Regex.match?(&1, vulnerable_code))

      vulnerable_code2 = ~S|raw(params["content"])|
      assert Enum.any?(pattern.regex, &Regex.match?(&1, vulnerable_code2))
    end

    test "detects html_safe usage" do
      pattern = XssRawHtml.pattern()

      vulnerable_code = ~S"user_content |> html_safe()"
      assert Enum.any?(pattern.regex, &Regex.match?(&1, vulnerable_code))

      vulnerable_code2 = ~S'params["html"].html_safe()'
      assert Enum.any?(pattern.regex, &Regex.match?(&1, vulnerable_code2))
    end

    test "detects raw in template interpolation" do
      pattern = XssRawHtml.pattern()

      vulnerable_code = ~S|<%= raw(@user_content) %>|
      assert Enum.any?(pattern.regex, &Regex.match?(&1, vulnerable_code))

      vulnerable_code2 = ~S|<%= raw(assigns[:content]) %>|
      assert Enum.any?(pattern.regex, &Regex.match?(&1, vulnerable_code2))
    end

    test "detects Phoenix.HTML.html_safe" do
      pattern = XssRawHtml.pattern()

      vulnerable_code = ~S|Phoenix.HTML.html_safe(user_generated)|
      assert Enum.any?(pattern.regex, &Regex.match?(&1, vulnerable_code))
    end
  end

  describe "safe code validation" do
    test "does not match Phoenix.HTML.escape" do
      pattern = XssRawHtml.pattern()

      safe_code = ~S|Phoenix.HTML.escape(user_input)|
      refute Enum.any?(pattern.regex, &Regex.match?(&1, safe_code))
    end

    test "does not match raw with static content" do
      pattern = XssRawHtml.pattern()

      safe_code = ~S|raw("<strong>Static Content</strong>")|
      refute Enum.any?(pattern.regex, &Regex.match?(&1, safe_code))

      safe_code2 = ~S|Phoenix.HTML.raw("<div>Fixed HTML</div>")|
      refute Enum.any?(pattern.regex, &Regex.match?(&1, safe_code2))
    end

    test "does not match regular template interpolation (auto-escaped)" do
      pattern = XssRawHtml.pattern()

      safe_code = ~S|<%= @user_input %>|
      refute Enum.any?(pattern.regex, &Regex.match?(&1, safe_code))

      safe_code2 = ~S|<div><%= params["content"] %></div>|
      refute Enum.any?(pattern.regex, &Regex.match?(&1, safe_code2))
    end

    test "does not match content_tag with user input (auto-escaped)" do
      pattern = XssRawHtml.pattern()

      safe_code = ~S|content_tag(:div, user_input)|
      refute Enum.any?(pattern.regex, &Regex.match?(&1, safe_code))
    end
  end

  describe "enhanced_pattern/0" do
    test "uses ast_enhancement for better detection" do
      enhanced = XssRawHtml.enhanced_pattern()

      assert enhanced.id == "elixir-xss-raw-html"
      assert Map.has_key?(enhanced, :ast_enhancement)
      assert enhanced.ast_enhancement == XssRawHtml.ast_enhancement()
    end
  end
end
