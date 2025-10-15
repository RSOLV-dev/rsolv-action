defmodule Rsolv.Security.Patterns.Javascript.XssJqueryHtmlTest do
  use ExUnit.Case, async: true

  alias Rsolv.Security.Patterns.Javascript.XssJqueryHtml
  alias Rsolv.Security.Pattern

  describe "pattern structure" do
    test "returns correct pattern structure with all required fields" do
      pattern = XssJqueryHtml.pattern()

      assert %Pattern{} = pattern
      assert pattern.id == "js-xss-jquery-html"
      assert pattern.name == "XSS via jQuery html()"
      assert pattern.type == :xss
      assert pattern.severity == :high
      assert pattern.languages == ["javascript", "typescript"]
      assert pattern.cwe_id == "CWE-79"
      assert pattern.owasp_category == "A03:2021"
      assert is_binary(pattern.recommendation)
      assert is_map(pattern.test_cases)
    end
  end

  describe "vulnerability detection" do
    test "detects jQuery html() with user input" do
      pattern = XssJqueryHtml.pattern()

      vulnerable_code = [
        ~S|$("#output").html(userInput)|,
        ~S|$('.content').html(req.body.content)|,
        ~S|jQuery("#div").html(params.message)|,
        ~S|$element.html(query.data)|,
        ~S|$(this).html(userData)|,
        ~S|$("<div>").html(request.body.html)|,
        ~S|jQuery('.result').html(input)|,
        ~S|$container.html(untrustedData)|
      ]

      for code <- vulnerable_code do
        assert Regex.match?(pattern.regex, code),
               "Should match vulnerable code: #{code}"
      end
    end

    test "detects jQuery html() with concatenation" do
      pattern = XssJqueryHtml.pattern()

      vulnerable_code = [
        ~S|$("#output").html("<p>" + userInput + "</p>")|,
        ~S|$('.content').html(prefix + req.body.content)|,
        ~S|jQuery("#div").html(`<span>${params.message}</span>`)|
      ]

      for code <- vulnerable_code do
        assert Regex.match?(pattern.regex, code),
               "Should match vulnerable code: #{code}"
      end
    end

    test "ignores safe jQuery html() usage" do
      pattern = XssJqueryHtml.pattern()

      safe_code = [
        ~S|$("#output").html(DOMPurify.sanitize(userInput))|,
        ~S|$('.content').html(escapeHtml(req.body.content))|,
        ~S|jQuery("#div").html(sanitizeHTML(params.message))|,
        ~S|$element.html("<p>Static content</p>")|,
        ~S|$(this).html(SAFE_TEMPLATE)|,
        ~S|$container.html(purify(userData))|
      ]

      for code <- safe_code do
        refute Regex.match?(pattern.regex, code),
               "Should NOT match safe code: #{code}"
      end
    end

    test "ignores jQuery text() method" do
      pattern = XssJqueryHtml.pattern()

      safe_code = [
        ~S|$("#output").text(userInput)|,
        ~S|$('.content').text(req.body.content)|,
        ~S|jQuery("#div").text(params.message)|
      ]

      for code <- safe_code do
        refute Regex.match?(pattern.regex, code),
               "Should NOT match safe text() method: #{code}"
      end
    end
  end

  describe "vulnerability metadata" do
    test "provides comprehensive metadata" do
      metadata = XssJqueryHtml.vulnerability_metadata()

      assert is_map(metadata)
      assert is_binary(metadata.description)
      assert is_list(metadata.references)
      assert is_list(metadata.attack_vectors)
      assert is_list(metadata.real_world_impact)
      assert is_list(metadata.safe_alternatives)
      assert is_list(metadata.cve_examples)
      assert length(metadata.cve_examples) >= 3
    end
  end

  describe "AST enhancement" do
    test "returns correct AST enhancement structure" do
      enhancement = XssJqueryHtml.ast_enhancement()

      assert is_map(enhancement)
      assert Map.has_key?(enhancement, :ast_rules)
      assert Map.has_key?(enhancement, :context_rules)
      assert Map.has_key?(enhancement, :confidence_rules)
      assert Map.has_key?(enhancement, :min_confidence)

      assert enhancement.ast_rules.node_type == "CallExpression"
      assert is_number(enhancement.min_confidence)
    end

    test "AST rules identify jQuery selectors" do
      enhancement = XssJqueryHtml.ast_enhancement()

      assert is_list(enhancement.ast_rules.callee_patterns)
      assert "$" in enhancement.ast_rules.callee_patterns
      assert "jQuery" in enhancement.ast_rules.callee_patterns
    end

    test "context rules exclude safe patterns" do
      enhancement = XssJqueryHtml.ast_enhancement()

      assert is_list(enhancement.context_rules.safe_patterns)
      assert "DOMPurify.sanitize" in enhancement.context_rules.safe_patterns
      assert "escapeHtml" in enhancement.context_rules.safe_patterns
    end

    test "confidence scoring adjusts for jQuery context" do
      enhancement = XssJqueryHtml.ast_enhancement()
      adjustments = enhancement.confidence_rules.adjustments

      assert adjustments["user_input"] > 0
      assert adjustments["sanitized"] < 0
      assert adjustments["static_content"] < 0
    end
  end

  describe "file applicability" do
    test "applies to JavaScript and TypeScript files" do
      assert XssJqueryHtml.applies_to_file?("app.js", nil)
      assert XssJqueryHtml.applies_to_file?("component.jsx", nil)
      assert XssJqueryHtml.applies_to_file?("service.ts", nil)
      assert XssJqueryHtml.applies_to_file?("module.tsx", nil)

      refute XssJqueryHtml.applies_to_file?("style.css", nil)
      refute XssJqueryHtml.applies_to_file?("data.json", nil)
    end
  end
end
