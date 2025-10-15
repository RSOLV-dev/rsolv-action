defmodule Rsolv.Security.Patterns.Javascript.XssInnerhtmlTest do
  use ExUnit.Case, async: true

  alias Rsolv.Security.Patterns.Javascript.XssInnerhtml
  alias Rsolv.Security.Pattern

  doctest XssInnerhtml

  describe "pattern/0" do
    test "returns a valid pattern struct" do
      pattern = XssInnerhtml.pattern()

      assert %Pattern{} = pattern
      assert pattern.id == "js-xss-innerhtml"
      assert pattern.name == "Cross-Site Scripting (XSS) via innerHTML"
      assert pattern.type == :xss
      assert pattern.severity == :high
      assert pattern.languages == ["javascript", "typescript"]
    end

    test "pattern detects vulnerable innerHTML assignments" do
      pattern = XssInnerhtml.pattern()

      vulnerable_cases = [
        ~S|element.innerHTML = userInput|,
        ~S|document.getElementById('content').innerHTML = data|,
        ~S|div.innerHTML = req.query.search|,
        ~S|container.innerHTML = '<div>' + untrustedData + '</div>'|,
        ~S|el.innerHTML = `<p>${userMessage}</p>`|
      ]

      for code <- vulnerable_cases do
        assert Regex.match?(pattern.regex, code),
               "Failed to match vulnerable code: #{code}"
      end
    end

    test "pattern does not match non-innerHTML assignments" do
      pattern = XssInnerhtml.pattern()

      safe_cases = [
        ~S|element.innerText = userInput|,
        ~S|element.textContent = data|,
        # New Sanitizer API
        ~S|container.setHTML(untrustedData)|,
        ~S|element.insertAdjacentHTML('beforeend', sanitized)|
      ]

      for code <- safe_cases do
        refute Regex.match?(pattern.regex, code),
               "Incorrectly matched safe code: #{code}"
      end
    end

    test "pattern matches innerHTML even with safe wrappers (AST will filter)" do
      pattern = XssInnerhtml.pattern()

      # These will match the regex but AST rules will filter them as safe
      wrapped_safe_cases = [
        ~S|div.innerHTML = DOMPurify.sanitize(userInput)|,
        ~S|el.innerHTML = escapeHtml(userMessage)|
      ]

      for code <- wrapped_safe_cases do
        assert Regex.match?(pattern.regex, code),
               "Should match innerHTML assignment (AST will determine safety): #{code}"
      end
    end
  end

  describe "vulnerability_metadata/0" do
    test "returns comprehensive vulnerability information" do
      metadata = XssInnerhtml.vulnerability_metadata()

      assert is_map(metadata)
      assert is_binary(metadata.description)
      assert is_list(metadata.references)
      assert is_list(metadata.attack_vectors)

      # Check references include OWASP DOM XSS
      ref_urls = Enum.map(metadata.references, & &1.url)
      assert Enum.any?(ref_urls, &String.contains?(&1, "DOM_based_XSS"))
    end

    test "metadata includes DOM-specific information" do
      metadata = XssInnerhtml.vulnerability_metadata()

      # Should mention DOM-based XSS
      assert metadata.description =~ "DOM"

      # Should have attack vectors with event handlers
      attack_vector_text = Enum.join(metadata.attack_vectors, " ")
      assert attack_vector_text =~ "onerror" || attack_vector_text =~ "onload"
    end

    test "metadata includes safe alternatives" do
      metadata = XssInnerhtml.vulnerability_metadata()

      assert Map.has_key?(metadata, :safe_alternatives)
      alternatives_text = Enum.join(metadata.safe_alternatives, " ")
      assert alternatives_text =~ "innerText"
      assert alternatives_text =~ "textContent"
    end
  end

  describe "applies_to_file?/2" do
    test "applies to JavaScript and TypeScript files" do
      assert XssInnerhtml.applies_to_file?("app.js", nil)
      assert XssInnerhtml.applies_to_file?("index.ts", nil)
      assert XssInnerhtml.applies_to_file?("src/components/widget.jsx", nil)
      assert XssInnerhtml.applies_to_file?("pages/home.tsx", nil)
    end

    test "applies to HTML files with embedded JavaScript" do
      html_content = """
      <script>
        document.getElementById('output').innerHTML = userInput;
      </script>
      """

      assert XssInnerhtml.applies_to_file?("index.html", html_content)
    end

    test "does not apply to non-JavaScript files" do
      refute XssInnerhtml.applies_to_file?("style.css", nil)
      refute XssInnerhtml.applies_to_file?("data.json", nil)
      refute XssInnerhtml.applies_to_file?("README.md", nil)
    end
  end

  describe "ast_enhancement/0" do
    test "returns comprehensive AST enhancement rules" do
      enhancement = XssInnerhtml.ast_enhancement()

      assert is_map(enhancement)

      assert Enum.sort(Map.keys(enhancement)) ==
               Enum.sort([:ast_rules, :context_rules, :confidence_rules, :min_confidence])
    end

    test "AST rules target assignment expressions with innerHTML" do
      enhancement = XssInnerhtml.ast_enhancement()

      assert enhancement.ast_rules.node_type == "AssignmentExpression"
      assert enhancement.ast_rules.left_side.property == "innerHTML"
      assert enhancement.ast_rules.left_side.object_type == "MemberExpression"
      assert enhancement.ast_rules.right_side_analysis.contains_user_input == true
      assert enhancement.ast_rules.right_side_analysis.not_sanitized == true
    end

    test "context rules exclude test files and sanitized content" do
      enhancement = XssInnerhtml.ast_enhancement()

      assert Enum.any?(enhancement.context_rules.exclude_paths, &(&1 == ~r/test/))
      assert enhancement.context_rules.exclude_if_sanitized == true
      assert enhancement.context_rules.exclude_if_static_content == true
      assert enhancement.context_rules.exclude_if_escaped == true
      assert enhancement.context_rules.safe_if_uses_text_content == true
    end

    test "confidence rules heavily penalize sanitization libraries" do
      enhancement = XssInnerhtml.ast_enhancement()

      assert enhancement.confidence_rules.base == 0.4
      assert enhancement.confidence_rules.adjustments["uses_dom_purify"] == -0.9
      assert enhancement.confidence_rules.adjustments["uses_sanitize_function"] == -0.8
      assert enhancement.confidence_rules.adjustments["static_html_only"] == -1.0
      assert enhancement.confidence_rules.adjustments["direct_user_input_to_innerhtml"] == 0.5
      # Adjusted to catch legitimate innerHTML vulnerabilities
      assert enhancement.min_confidence == 0.6
    end
  end

  describe "enhanced_pattern/0" do
    test "returns pattern with AST enhancement from ast_enhancement/0" do
      enhanced = XssInnerhtml.enhanced_pattern()
      enhancement = XssInnerhtml.ast_enhancement()

      # Verify it has all the AST enhancement fields
      assert enhanced.ast_rules == enhancement.ast_rules
      assert enhanced.context_rules == enhancement.context_rules
      assert enhanced.confidence_rules == enhancement.confidence_rules
      assert enhanced.min_confidence == enhancement.min_confidence

      # And still has all the pattern fields
      assert enhanced.id == "js-xss-innerhtml"
      assert enhanced.severity == :high
    end
  end
end
