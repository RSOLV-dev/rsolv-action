defmodule RsolvApi.Security.Patterns.Java.XpathInjectionTest do
  use ExUnit.Case, async: true
  
  alias RsolvApi.Security.Patterns.Java.XpathInjection
  alias RsolvApi.Security.Pattern
  
  describe "pattern/0" do
    test "returns a valid pattern struct" do
      pattern = XpathInjection.pattern()
      
      assert %Pattern{} = pattern
      assert pattern.id == "java-xpath-injection"
      assert pattern.name == "XPath Injection"
      assert pattern.severity == :high
      assert pattern.type == :xpath_injection
      assert pattern.languages == ["java"]
    end
    
    test "includes CWE and OWASP references" do
      pattern = XpathInjection.pattern()
      
      assert pattern.cwe_id == "CWE-643"
      assert pattern.owasp_category == "A03:2021"
    end
    
    test "has multiple regex patterns" do
      pattern = XpathInjection.pattern()
      
      assert is_list(pattern.regex)
      assert length(pattern.regex) >= 5
    end
  end
  
  describe "regex matching" do
    setup do
      pattern = XpathInjection.pattern()
      {:ok, pattern: pattern}
    end
    
    test "matches xpath.evaluate with string concatenation", %{pattern: pattern} do
      vulnerable_code = [
        ~S|XPath xpath = XPathFactory.newInstance().newXPath();
xpath.evaluate("//user[name='" + username + "']", doc);|,
        ~S|xpath.evaluate("//book[@id='" + bookId + "']", document);|,
        ~S|result = xpath.evaluate("//product[price>" + price + "]", xmlDoc);|,
        ~S|xpath.evaluate("/users/user[@name='" + userInput + "' and @password='" + pass + "']", doc);|
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Should match: #{code}"
      end
    end
    
    test "matches xpath.compile with concatenation", %{pattern: pattern} do
      vulnerable_code = [
        ~S|xpath.compile("//product[@id='" + productId + "']");|,
        ~S|XPathExpression expr = xpath.compile("//user[name='" + name + "']");|,
        ~S|expression = xpath.compile("/root/element[@attr='" + value + "']");|
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Should match: #{code}"
      end
    end
    
    test "matches selectNodes and selectSingleNode", %{pattern: pattern} do
      vulnerable_code = [
        ~S|document.selectNodes("//user[id='" + userId + "']");|,
        ~S|doc.selectSingleNode("//book[@isbn='" + isbn + "']");|,
        ~S|xmlDoc.selectNodes("/catalog/item[@id='" + itemId + "']");|
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Should match: #{code}"
      end
    end
    
    test "matches evaluate with XPathConstants", %{pattern: pattern} do
      vulnerable_code = [
        ~S|xpath.evaluate("//user[@id='" + id + "']", doc, XPathConstants.NODE);|,
        ~S|NodeList nodes = (NodeList) xpath.evaluate("//item[name='" + name + "']", document, XPathConstants.NODESET);|,
        ~S|String result = (String) xpath.evaluate("//data[@key='" + key + "']", xmlDoc, XPathConstants.STRING);|
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Should match: #{code}"
      end
    end
    
    test "matches JXPath usage (CVE-2022-41852)", %{pattern: pattern} do
      vulnerable_code = [
        ~S|JXPathContext.getValue(userXPath);|,
        ~S|context.getValue("//user[name='" + username + "']");|,
        ~S|JXPathContext.newContext(root).getValue(xpath);|,
        ~S|jxpath.iterate("//item[@price>" + price + "]");|
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Should match: #{code}"
      end
    end
    
    test "does not match safe XPath usage", %{pattern: pattern} do
      safe_code = [
        ~S|// Use XPath variables
XPath xpath = XPathFactory.newInstance().newXPath();
xpath.setXPathVariableResolver(resolver);
xpath.evaluate("//user[name=$username]", doc);|,
        ~S|// Static XPath expression
xpath.evaluate("//users/user[@role='admin']", document);|,
        ~S|// Comment mentioning xpath
// This uses xpath internally|,
        ~S|String xpathQuery = "//book[@id='123']";|,
        ~S|logger.info("Using XPath: " + query);|
      ]
      
      for code <- safe_code do
        refute Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Should not match: #{code}"
      end
    end
    
    test "matches blind XPath injection patterns", %{pattern: pattern} do
      vulnerable_code = [
        ~S|xpath.evaluate("//user[password/text()='" + password + "']", doc);|,
        ~S|xpath.evaluate("count(//user[name='" + name + "']) > 0", doc);|,
        ~S|boolean exists = (Boolean) xpath.evaluate("//item[@id='" + id + "']", doc, XPathConstants.BOOLEAN);|
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Should match: #{code}"
      end
    end
  end
  
  describe "vulnerability_metadata/0" do
    test "returns comprehensive metadata" do
      metadata = XpathInjection.vulnerability_metadata()
      
      assert metadata.description =~ "XPath"
      assert length(metadata.references) >= 4
      assert length(metadata.attack_vectors) >= 5
      assert length(metadata.real_world_impact) >= 4
      assert length(metadata.cve_examples) >= 3
    end
    
    test "includes CVE examples from research" do
      metadata = XpathInjection.vulnerability_metadata()
      
      cve_ids = Enum.map(metadata.cve_examples, & &1.id)
      assert Enum.any?(cve_ids, &String.contains?(&1, "CVE-"))
      # Should include recent CVEs from research
      assert Enum.any?(cve_ids, &String.contains?(&1, "2024"))
      assert Enum.any?(cve_ids, &String.contains?(&1, "2022"))
    end
    
    test "includes proper security references" do
      metadata = XpathInjection.vulnerability_metadata()
      
      ref_types = Enum.map(metadata.references, & &1.type)
      assert :cwe in ref_types
      assert :owasp in ref_types
      assert :research in ref_types
    end
    
    test "includes blind injection techniques" do
      metadata = XpathInjection.vulnerability_metadata()
      
      assert Enum.any?(metadata.attack_vectors, &String.contains?(&1, "blind"))
      assert metadata.additional_context.blind_techniques
    end
  end
  
  describe "ast_enhancement/0" do
    test "returns proper enhancement rules" do
      enhancement = XpathInjection.ast_enhancement()
      
      assert Map.has_key?(enhancement, :ast_rules)
      assert Map.has_key?(enhancement, :context_rules)
      assert Map.has_key?(enhancement, :confidence_rules)
      assert Map.has_key?(enhancement, :min_confidence)
      
      assert enhancement.min_confidence >= 0.7
    end
    
    test "includes XPath method analysis" do
      enhancement = XpathInjection.ast_enhancement()
      
      assert enhancement.ast_rules.node_type == "MethodInvocation"
      assert enhancement.ast_rules.xpath_analysis.check_method_name
      assert enhancement.ast_rules.xpath_analysis.xpath_methods
      assert enhancement.ast_rules.xpath_analysis.check_string_concatenation
    end
    
    test "has string concatenation detection" do
      enhancement = XpathInjection.ast_enhancement()
      
      assert enhancement.ast_rules.concatenation_analysis.check_operators
      assert enhancement.ast_rules.concatenation_analysis.dangerous_operators
      assert enhancement.ast_rules.concatenation_analysis.check_xpath_context
    end
    
    test "includes variable resolver detection" do
      enhancement = XpathInjection.ast_enhancement()
      
      assert enhancement.context_rules.check_variable_resolver
      assert enhancement.context_rules.safe_resolver_patterns
      assert enhancement.context_rules.parameterized_xpath_indicators
    end
  end
end