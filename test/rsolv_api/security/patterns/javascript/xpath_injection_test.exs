defmodule RsolvApi.Security.Patterns.Javascript.XpathInjectionTest do
  use ExUnit.Case, async: true
  alias RsolvApi.Security.Pattern
  alias RsolvApi.Security.Patterns.Javascript.XpathInjection

  doctest XpathInjection

  describe "pattern/0" do
    test "returns correct pattern structure" do
      pattern = XpathInjection.pattern()
      
      assert %Pattern{} = pattern
      assert pattern.id == "js-xpath-injection"
      assert pattern.name == "XPath Injection"
      assert pattern.type == :xpath_injection
      assert pattern.severity == :high
      assert pattern.languages == ["javascript", "typescript"]
      assert pattern.cwe_id == "CWE-643"
      assert pattern.owasp_category == "A03:2021"
    end

    test "pattern has required metadata" do
      pattern = XpathInjection.pattern()
      
      assert pattern.description =~ "XPath"
      assert pattern.recommendation =~ "parameterized"
      assert is_map(pattern.test_cases)
      assert is_list(pattern.test_cases.vulnerable)
      assert is_list(pattern.test_cases.safe)
    end
  end

  describe "vulnerability_metadata/0" do
    test "returns comprehensive vulnerability metadata" do
      metadata = XpathInjection.vulnerability_metadata()
      
      assert is_map(metadata)
      assert is_binary(metadata.description)
      assert is_list(metadata.references)
      assert is_list(metadata.attack_vectors)
      assert is_list(metadata.real_world_impact)
      assert is_list(metadata.cve_examples)
      assert is_list(metadata.safe_alternatives)
    end

    test "metadata includes required reference types" do
      metadata = XpathInjection.vulnerability_metadata()
      references = metadata.references
      
      assert Enum.any?(references, &(&1.type == :cwe))
      assert Enum.any?(references, &(&1.type == :owasp))
    end
  end

  describe "detection tests" do
    test "detects XPath string concatenation" do
      pattern = XpathInjection.pattern()
      
      vulnerable_codes = [
        ~S|xpath.select("//user[name='" + username + "']")|,
        ~S|doc.evaluate("/users/user[@id='" + userId + "']", doc)|,
        ~S|xml.selectNodes("//product[price<" + maxPrice + "]")|
      ]
      
      for code <- vulnerable_codes do
        assert Regex.match?(pattern.regex, code), "Should detect: #{code}"
      end
    end

    test "detects XPath template literal injection" do
      pattern = XpathInjection.pattern()
      
      vulnerable_codes = [
        ~S|xpath.select(`//user[@id='${userId}']`)|,
        ~S|doc.evaluate(`/books/book[author="${req.query.author}"]`, doc)|,
        ~S|xml.selectSingleNode(`//item[@category="${category}"]`)|
      ]
      
      for code <- vulnerable_codes do
        assert Regex.match?(pattern.regex, code), "Should detect: #{code}"
      end
    end

    test "detects XPath with various input sources" do
      pattern = XpathInjection.pattern()
      
      vulnerable_codes = [
        ~S|xpath.evaluate("//user[email='" + req.body.email + "']")|,
        ~S|xml.selectNodes("//*[@name='" + userInput + "']")|,
        ~S|doc.evaluate("//node[text()='" + data.value + "']", doc)|
      ]
      
      for code <- vulnerable_codes do
        assert Regex.match?(pattern.regex, code), "Should detect: #{code}"
      end
    end

    test "detects complex XPath expressions" do
      pattern = XpathInjection.pattern()
      
      vulnerable_code = ~S|xpath.select("//user[name='" + name + "' and password='" + pass + "']")|
      
      assert Regex.match?(pattern.regex, vulnerable_code)
    end
  end

  describe "safe code validation" do
    test "does not match parameterized XPath queries" do
      pattern = XpathInjection.pattern()
      
      safe_codes = [
        ~S|xpath.select("//user[name=$username]", {username: sanitizeInput(username)})|,
        ~S|const query = xpath.compile("//user[@id=$id]"); query.select({id: userId})|,
        ~S|xpath.select("//product[price<$price]", {price: parseFloat(maxPrice)})|,
        ~S|doc.evaluate("//user[@id='12345']", doc)|
      ]
      
      for code <- safe_codes do
        refute Regex.match?(pattern.regex, code), "Should not match: #{code}"
      end
    end

    test "does not match XPath with proper escaping" do
      pattern = XpathInjection.pattern()
      
      safe_code = """
      const escapedName = escapeXPath(username);
      xpath.select(`//user[name='${escapedName}']`);
      """
      
      refute Regex.match?(pattern.regex, safe_code)
    end
  end

  describe "applies_to_file?/1" do
    test "applies to JavaScript files" do
      assert XpathInjection.applies_to_file?("xml-parser.js", nil)
      assert XpathInjection.applies_to_file?("xpath-helper.mjs", nil)
      assert XpathInjection.applies_to_file?("src/xml/query.js", nil)
    end

    test "applies to TypeScript files" do
      assert XpathInjection.applies_to_file?("xml-service.ts", nil)
      assert XpathInjection.applies_to_file?("xpath-utils.tsx", nil)
      assert XpathInjection.applies_to_file?("lib/xml-processor.ts", nil)
    end

    test "does not apply to non-JS/TS files" do
      refute XpathInjection.applies_to_file?("query.xml", nil)
      refute XpathInjection.applies_to_file?("xpath.py", nil)
      refute XpathInjection.applies_to_file?("Makefile", nil)
    end
  end
  
  describe "ast_enhancement/0" do
    test "returns comprehensive AST enhancement rules" do
      enhancement = XpathInjection.ast_enhancement()
      
      assert is_map(enhancement)
      assert Enum.sort(Map.keys(enhancement)) == Enum.sort([:ast_rules, :context_rules, :confidence_rules, :min_confidence])
    end
    
    test "AST rules target XPath evaluation methods" do
      enhancement = XpathInjection.ast_enhancement()
      
      assert enhancement.ast_rules.node_type == "CallExpression"
      assert is_list(enhancement.ast_rules.callee_patterns)
      assert enhancement.ast_rules.argument_analysis.has_xpath_expression == true
      assert enhancement.ast_rules.argument_analysis.contains_user_input == true
      assert enhancement.ast_rules.argument_analysis.uses_string_building == true
      assert enhancement.ast_rules.argument_analysis.not_parameterized == true
    end
    
    test "context rules exclude test files and parameterized queries" do
      enhancement = XpathInjection.ast_enhancement()
      
      assert Enum.any?(enhancement.context_rules.exclude_paths, &(&1 == ~r/test/))
      assert Enum.any?(enhancement.context_rules.exclude_paths, &(&1 == ~r/spec/))
      assert enhancement.context_rules.exclude_if_parameterized == true
      assert enhancement.context_rules.exclude_if_escaped == true
      assert enhancement.context_rules.exclude_if_compiled == true
      assert enhancement.context_rules.safe_xpath_patterns == ["xpath.compile", "createExpression"]
    end
    
    test "confidence rules heavily penalize parameterized and pre-compiled patterns" do
      enhancement = XpathInjection.ast_enhancement()
      
      assert enhancement.confidence_rules.base == 0.3
      assert enhancement.confidence_rules.adjustments["direct_string_concat_xpath"] == 0.5
      assert enhancement.confidence_rules.adjustments["template_literal_xpath"] == 0.4
      assert enhancement.confidence_rules.adjustments["user_controlled_predicate"] == 0.4
      assert enhancement.confidence_rules.adjustments["uses_parameterized_xpath"] == -0.9
      assert enhancement.confidence_rules.adjustments["pre_compiled_expression"] == -0.8
      assert enhancement.confidence_rules.adjustments["xpath_builder_library"] == -0.7
      assert enhancement.confidence_rules.adjustments["static_xpath_only"] == -1.0
      assert enhancement.min_confidence == 0.8
    end
  end
  
  describe "enhanced_pattern/0" do
    test "returns pattern with AST enhancement from ast_enhancement/0" do
      enhanced = XpathInjection.enhanced_pattern()
      enhancement = XpathInjection.ast_enhancement()
      
      # Verify it has all the AST enhancement fields
      assert enhanced.ast_rules == enhancement.ast_rules
      assert enhanced.context_rules == enhancement.context_rules
      assert enhanced.confidence_rules == enhancement.confidence_rules
      assert enhanced.min_confidence == enhancement.min_confidence
      
      # And still has all the pattern fields
      assert enhanced.id == "js-xpath-injection"
      assert enhanced.severity == :high
    end
  end
end