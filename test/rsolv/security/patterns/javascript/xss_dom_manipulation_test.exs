defmodule Rsolv.Security.Patterns.Javascript.XssDomManipulationTest do
  use ExUnit.Case, async: true
  
  alias Rsolv.Security.Patterns.Javascript.XssDomManipulation
  alias Rsolv.Security.Pattern
  
  describe "pattern structure" do
    test "returns correct pattern structure with all required fields" do
      pattern = XssDomManipulation.pattern()
      
      assert %Pattern{} = pattern
      assert pattern.id == "js-xss-dom-manipulation"
      assert pattern.name == "XSS via DOM Manipulation"
      assert pattern.type == :xss
      assert pattern.severity == :high
      assert pattern.languages == ["javascript", "typescript", "jsx", "tsx"]
      assert pattern.cwe_id == "CWE-79"
      assert pattern.owasp_category == "A03:2021"
      assert is_binary(pattern.recommendation)
      assert is_map(pattern.test_cases)
    end
  end
  
  describe "vulnerability detection" do
    test "detects insertAdjacentHTML with user input" do
      pattern = XssDomManipulation.pattern()
      
      vulnerable_code = [
        ~S|element.insertAdjacentHTML('beforeend', userInput)|,
        ~S|div.insertAdjacentHTML('afterbegin', req.body.html)|,
        ~S|node.insertAdjacentHTML('beforebegin', params.content)|,
        ~S|insertAdjacentHTML('afterend', userData)|,
        ~S|document.body.insertAdjacentHTML('beforeend', input)|,
        ~S|target.insertAdjacentHTML("beforeend", query.html)|
      ]
      
      for code <- vulnerable_code do
        assert Regex.match?(pattern.regex, code),
          "Should match vulnerable code: #{code}"
      end
    end
    
    test "detects jQuery DOM manipulation methods with user input" do
      pattern = XssDomManipulation.pattern()
      
      vulnerable_code = [
        ~S|$(element).append(userInput)|,
        ~S|$('#content').prepend(req.body.content)|,
        ~S|$(".container").after(params.html)|,
        ~S|$('div').before(userData)|,
        ~S|jQuery('#main').append(input)|,
        ~S|$target.prepend(query.message)|
      ]
      
      for code <- vulnerable_code do
        assert Regex.match?(pattern.regex, code),
          "Should match vulnerable code: #{code}"
      end
    end
    
    test "detects vanilla JS DOM manipulation with user input" do
      pattern = XssDomManipulation.pattern()
      
      vulnerable_code = [
        ~S|element.outerHTML = userInput|,
        ~S|node.outerHTML = params.content|,
        ~S|div.outerHTML = req.body.html|
      ]
      
      for code <- vulnerable_code do
        assert Regex.match?(pattern.regex, code),
          "Should match vulnerable code: #{code}"
      end
    end
    
    test "ignores safe DOM manipulation" do
      pattern = XssDomManipulation.pattern()
      
      # These have comment markers and won't match
      safe_code_commented = [
        ~S|// element.insertAdjacentHTML('beforeend', userInput)|,
        ~S|// $(element).append(userData)|,
        ~S|// $('#content').prepend(req.body.content)|,
        ~S|// node.outerHTML = params.html|
      ]
      
      for code <- safe_code_commented do
        refute Regex.match?(pattern.regex, code),
          "Should NOT match commented code: #{code}"
      end
      
      # These have sanitization - regex will match but AST should filter
      safe_code_with_sanitization = [
        ~S|element.insertAdjacentHTML('beforeend', DOMPurify.sanitize(userInput))|,
        ~S|$(element).append(escapeHtml(userData))|,
        ~S|$('#content').prepend(sanitizeHtml(req.body.content))|
      ]
      
      for code <- safe_code_with_sanitization do
        # These will match the regex but AST enhancement handles filtering
        assert Regex.match?(pattern.regex, code),
          "Regex matches but AST enhancement would filter: #{code}"
      end
    end
    
    test "ignores safe DOM operations" do
      pattern = XssDomManipulation.pattern()
      
      safe_code = [
        ~S|element.textContent = userInput|,
        ~S|$(element).text(userData)|,
        ~S|node.innerText = params.message|,
        ~S|element.setAttribute('data-value', userInput)|,
        ~S|$(element).attr('title', userData)|
      ]
      
      for code <- safe_code do
        refute Regex.match?(pattern.regex, code),
          "Should NOT match safe DOM operations: #{code}"
      end
    end
  end
  
  describe "vulnerability metadata" do
    test "provides comprehensive metadata" do
      metadata = XssDomManipulation.vulnerability_metadata()
      
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
      enhancement = XssDomManipulation.ast_enhancement()
      
      assert is_map(enhancement)
      assert Map.has_key?(enhancement, :ast_rules)
      assert Map.has_key?(enhancement, :context_rules)
      assert Map.has_key?(enhancement, :confidence_rules)
      assert Map.has_key?(enhancement, :min_confidence)
      
      assert is_list(enhancement.ast_rules.method_names)
      assert is_number(enhancement.min_confidence)
    end
    
    test "AST rules identify DOM manipulation methods" do
      enhancement = XssDomManipulation.ast_enhancement()
      
      assert "insertAdjacentHTML" in enhancement.ast_rules.method_names
      assert "append" in enhancement.ast_rules.method_names
      assert "prepend" in enhancement.ast_rules.method_names
    end
    
    test "context rules exclude safe patterns" do
      enhancement = XssDomManipulation.ast_enhancement()
      
      assert is_list(enhancement.context_rules.safe_patterns)
      assert "DOMPurify.sanitize" in enhancement.context_rules.safe_patterns
      assert "escapeHtml" in enhancement.context_rules.safe_patterns
    end
    
    test "confidence scoring adjusts for DOM context" do
      enhancement = XssDomManipulation.ast_enhancement()
      adjustments = enhancement.confidence_rules.adjustments
      
      assert adjustments["user_input"] > 0
      assert adjustments["sanitized"] < 0
      assert adjustments["static_content"] < 0
    end
  end
  
  describe "file applicability" do
    test "applies to JavaScript files" do
      assert XssDomManipulation.applies_to_file?("app.js", nil)
      assert XssDomManipulation.applies_to_file?("component.jsx", nil)
      assert XssDomManipulation.applies_to_file?("service.ts", nil)
      assert XssDomManipulation.applies_to_file?("module.tsx", nil)
      
      refute XssDomManipulation.applies_to_file?("style.css", nil)
      refute XssDomManipulation.applies_to_file?("data.json", nil)
    end
  end
end