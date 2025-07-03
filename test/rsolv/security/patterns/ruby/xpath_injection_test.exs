defmodule Rsolv.Security.Patterns.Ruby.XpathInjectionTest do
  use ExUnit.Case, async: true
  
  alias Rsolv.Security.Patterns.Ruby.XpathInjection
  alias Rsolv.Security.Pattern
  
  describe "pattern/0" do
    test "returns a valid pattern struct" do
      pattern = XpathInjection.pattern()
      
      assert %Pattern{} = pattern
      assert pattern.id == "ruby-xpath-injection"
      assert pattern.name == "XPath Injection"
      assert pattern.severity == :high
      assert pattern.type == :xpath_injection
      assert pattern.languages == ["ruby"]
    end
    
    test "includes CWE and OWASP references" do
      pattern = XpathInjection.pattern()
      
      assert pattern.cwe_id == "CWE-643"
      assert pattern.owasp_category == "A03:2021"
    end
    
    test "has multiple regex patterns" do
      pattern = XpathInjection.pattern()
      
      assert is_list(pattern.regex)
      assert length(pattern.regex) >= 4
    end
  end
  
  describe "regex matching" do
    setup do
      pattern = XpathInjection.pattern()
      {:ok, pattern: pattern}
    end
    
    test "matches Nokogiri xpath with interpolation", %{pattern: pattern} do
      vulnerable_code = [
        ~S|doc.xpath("//user[name='#{params[:name]}']")|,
        ~S|xml.xpath("//book[@id='#{id}']")|,
        ~S|document.xpath("//product[price=#{price}]")|,
        ~S|node.xpath("//item[@category='#{category}']")|,
        ~S|nokogiri_doc.xpath("//person[age>#{age}]")|
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Should match: #{code}"
      end
    end
    
    test "matches REXML elements with interpolation", %{pattern: pattern} do
      vulnerable_code = [
        ~S|xml.elements["//user[@name='#{username}']"]|,
        ~S|doc.elements["//product[@id=#{product_id}]"]|,
        ~S|root.elements["//item[text()='#{search}']"]|,
        ~S|document.elements["//node[@attr='#{value}']"]|
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Should match: #{code}"
      end
    end
    
    test "matches XPath::Parser with interpolation", %{pattern: pattern} do
      vulnerable_code = [
        ~S|XPath::Parser.parse("//user[name='#{user_name}']")|,
        ~S|parser.parse("//item[@id=#{item_id}]")|,
        ~S|XPath.parse("//node[@value='#{user_input}']")|
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Should match: #{code}"
      end
    end
    
    test "matches generic xpath calls with interpolation", %{pattern: pattern} do
      vulnerable_code = [
        ~S|find_by_xpath("//user[@id='#{id}']")|,
        ~S|select_xpath("//item[contains(text(),'#{search}')]")|,
        ~S|query_xpath("//product[@price=#{price}]")|,
        ~S|get_xpath("//node[@attr='#{attribute}']")|
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Should match: #{code}"
      end
    end
    
    test "does not match safe XPath patterns", %{pattern: pattern} do
      safe_code = [
        ~S|doc.xpath("//user", name: params[:name])|,
        ~S|xml.xpath("//user[@name=$name]", nil, name: params[:name])|,
        ~S|doc.at_xpath("//user[@id=?]", params[:id])|,
        ~S|xml.elements["//static/path"]|,
        ~S|doc.xpath("//user[@id=123]")|,
        ~S|puts "Searching for #{query}"|
      ]
      
      for code <- safe_code do
        refute Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Should not match: #{code}"
      end
    end
    
    test "documents regex limitations for comment detection" do
      # NOTE: This pattern has a known limitation - it will match commented-out code
      # This is acceptable because AST enhancement will filter out comments in practice
      commented_code = ~S|# doc.xpath("//user[@name='#{name}']")|
      pattern = XpathInjection.pattern()
      
      # This will match, but AST enhancement filters it out
      assert Enum.any?(pattern.regex, &Regex.match?(&1, commented_code)),
             "Expected regex limitation: matches comments (filtered by AST)"
    end
  end
  
  describe "vulnerability_metadata/0" do
    test "returns comprehensive metadata" do
      metadata = XpathInjection.vulnerability_metadata()
      
      assert metadata.description =~ "XPath injection"
      assert length(metadata.references) >= 3
      assert length(metadata.attack_vectors) >= 5
      assert length(metadata.real_world_impact) >= 3
      assert length(metadata.cve_examples) >= 2
    end
    
    test "includes real-world incident references" do
      metadata = XpathInjection.vulnerability_metadata()
      
      impact = Enum.join(metadata.real_world_impact, " ")
      assert impact =~ "CVE-2015-20108" || impact =~ "ruby-saml" || impact =~ "Nokogiri"
    end
    
    test "includes proper references" do
      metadata = XpathInjection.vulnerability_metadata()
      
      ref_types = Enum.map(metadata.references, & &1.type)
      assert :cwe in ref_types
      assert :owasp in ref_types
      assert :research in ref_types
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
    
    test "includes XPath-specific AST rules" do
      enhancement = XpathInjection.ast_enhancement()
      
      assert enhancement.ast_rules.node_type == "CallExpression"
      assert "xpath" in enhancement.ast_rules.method_names
    end
    
    test "has proper context detection" do
      enhancement = XpathInjection.ast_enhancement()
      
      assert enhancement.context_rules.check_xpath_context
      assert "$" in enhancement.context_rules.safe_patterns
    end
  end
end