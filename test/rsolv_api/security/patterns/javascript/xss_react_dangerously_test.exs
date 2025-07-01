defmodule RsolvApi.Security.Patterns.Javascript.XssReactDangerouslyTest do
  use ExUnit.Case, async: true
  
  alias RsolvApi.Security.Patterns.Javascript.XssReactDangerously
  alias RsolvApi.Security.Pattern
  
  describe "pattern structure" do
    test "returns correct pattern structure with all required fields" do
      pattern = XssReactDangerously.pattern()
      
      assert %Pattern{} = pattern
      assert pattern.id == "js-xss-react-dangerously"
      assert pattern.name == "XSS via React dangerouslySetInnerHTML"
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
    test "detects dangerouslySetInnerHTML with user input" do
      pattern = XssReactDangerously.pattern()
      
      vulnerable_code = [
        ~S|<div dangerouslySetInnerHTML={{__html: userInput}} />|,
        ~S|<span dangerouslySetInnerHTML={{__html: req.body.content}} />|,
        ~S|<div dangerouslySetInnerHTML={{__html: params.message}}></div>|,
        ~S|dangerouslySetInnerHTML={{__html: userData}}|,
        ~S|dangerouslySetInnerHTML={{ __html: query.html }}|,
        ~S|React.createElement('div', {dangerouslySetInnerHTML: {__html: input}})|,
        ~S|createElement("div", { dangerouslySetInnerHTML: { __html: userContent } })|
      ]
      
      for code <- vulnerable_code do
        assert Regex.match?(pattern.regex, code),
          "Should match vulnerable code: #{code}"
      end
    end
    
    test "detects dangerouslySetInnerHTML with concatenation" do
      pattern = XssReactDangerously.pattern()
      
      vulnerable_code = [
        ~S|<div dangerouslySetInnerHTML={{__html: "<p>" + userInput + "</p>"}} />|,
        ~S|dangerouslySetInnerHTML={{__html: `<span>${params.name}</span>`}}|,
        ~S|<article dangerouslySetInnerHTML={{__html: header + body.content + footer}} />|
      ]
      
      for code <- vulnerable_code do
        assert Regex.match?(pattern.regex, code),
          "Should match vulnerable code: #{code}"
      end
    end
    
    test "ignores safe dangerouslySetInnerHTML usage" do
      pattern = XssReactDangerously.pattern()
      
      # The regex is intentionally permissive - AST enhancement filters false positives
      # These patterns would match the regex but AST enhancement would filter them out
      safe_code_with_user_input = [
        ~S|<div dangerouslySetInnerHTML={{__html: DOMPurify.sanitize(userInput)}} />|,
        ~S|<span dangerouslySetInnerHTML={{__html: sanitizeHtml(content)}} />|,
        ~S|dangerouslySetInnerHTML={{__html: purify(userData)}}|,
        ~S|React.createElement('div', {dangerouslySetInnerHTML: {__html: escapeHtml(input)}})|
      ]
      
      # These have constants/literals so won't match the regex
      safe_code_no_user_input = [
        ~S|<div dangerouslySetInnerHTML={{__html: "<p>Static text</p>"}} />|,
        ~S|<div dangerouslySetInnerHTML={{__html: `<p>Template literal</p>`}} />|
      ]
      
      # SAFE_TEMPLATE is excluded by prefix check
      safe_constants = [
        ~S|dangerouslySetInnerHTML={{__html: SAFE_TEMPLATE}}|,
        ~S|dangerouslySetInnerHTML={{__html: STATIC_HTML}}|
      ]
      
      for code <- safe_code_no_user_input do
        refute Regex.match?(pattern.regex, code),
          "Should NOT match safe code without user input: #{code}"
      end
      
      # Safe constants are excluded by the SAFE_/STATIC_ prefix check
      for code <- safe_constants do
        refute Regex.match?(pattern.regex, code),
          "Should NOT match safe constants: #{code}"
      end
      
      # For sanitized content, the regex now excludes common sanitization functions
      # This provides defense in depth - both regex and AST enhancement filter these
      for code <- safe_code_with_user_input do
        # The regex now excludes DOMPurify.sanitize, sanitizeHtml, etc.
        refute Regex.match?(pattern.regex, code),
          "Regex excludes common sanitization functions: #{code}"
      end
    end
    
    test "ignores regular React content" do
      pattern = XssReactDangerously.pattern()
      
      safe_code = [
        ~S|<div>{userInput}</div>|,
        ~S|<span>{req.body.content}</span>|,
        ~S|React.createElement('div', null, userInput)|,
        ~S|<p className="content">{params.message}</p>|
      ]
      
      for code <- safe_code do
        refute Regex.match?(pattern.regex, code),
          "Should NOT match safe React content: #{code}"
      end
    end
  end
  
  describe "vulnerability metadata" do
    test "provides comprehensive metadata" do
      metadata = XssReactDangerously.vulnerability_metadata()
      
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
      enhancement = XssReactDangerously.ast_enhancement()
      
      assert is_map(enhancement)
      assert Map.has_key?(enhancement, :ast_rules)
      assert Map.has_key?(enhancement, :context_rules)
      assert Map.has_key?(enhancement, :confidence_rules)
      assert Map.has_key?(enhancement, :min_confidence)
      
      assert enhancement.ast_rules.node_type == "JSXAttribute"
      assert is_number(enhancement.min_confidence)
    end
    
    test "AST rules identify React patterns" do
      enhancement = XssReactDangerously.ast_enhancement()
      
      assert enhancement.ast_rules.attribute_name == "dangerouslySetInnerHTML"
      assert is_map(enhancement.ast_rules.value_check)
    end
    
    test "context rules exclude safe patterns" do
      enhancement = XssReactDangerously.ast_enhancement()
      
      assert is_list(enhancement.context_rules.safe_patterns)
      assert "DOMPurify.sanitize" in enhancement.context_rules.safe_patterns
      assert "sanitizeHtml" in enhancement.context_rules.safe_patterns
    end
    
    test "confidence scoring adjusts for React context" do
      enhancement = XssReactDangerously.ast_enhancement()
      adjustments = enhancement.confidence_rules.adjustments
      
      assert adjustments["user_input"] > 0
      assert adjustments["sanitized"] < 0
      assert adjustments["static_content"] < 0
    end
  end
  
  describe "file applicability" do
    test "applies to JavaScript and React files" do
      assert XssReactDangerously.applies_to_file?("app.js", nil)
      assert XssReactDangerously.applies_to_file?("component.jsx", nil)
      assert XssReactDangerously.applies_to_file?("service.ts", nil)
      assert XssReactDangerously.applies_to_file?("module.tsx", nil)
      
      refute XssReactDangerously.applies_to_file?("style.css", nil)
      refute XssReactDangerously.applies_to_file?("data.json", nil)
    end
  end
end