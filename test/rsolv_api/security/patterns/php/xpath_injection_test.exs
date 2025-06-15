defmodule RsolvApi.Security.Patterns.Php.XpathInjectionTest do
  use ExUnit.Case, async: true
  
  alias RsolvApi.Security.Patterns.Php.XpathInjection
  alias RsolvApi.Security.Pattern
  
  describe "pattern/0" do
    test "returns a valid pattern struct" do
      pattern = XpathInjection.pattern()
      
      assert %Pattern{} = pattern
      assert pattern.id == "php-xpath-injection"
      assert pattern.name == "XPath Injection"
      assert pattern.severity == :high
      assert pattern.type == :xpath_injection
      assert pattern.languages == ["php"]
    end
    
    test "includes CWE and OWASP references" do
      pattern = XpathInjection.pattern()
      
      assert pattern.cwe_id == "CWE-643"
      assert pattern.owasp_category == "A03:2021"
    end
  end
  
  describe "regex matching" do
    setup do
      pattern = XpathInjection.pattern()
      {:ok, pattern: pattern}
    end
    
    test "matches XPath query with direct user input", %{pattern: pattern} do
      vulnerable_code = [
        ~S|$xpath->query("//user[name='$_GET[username]']");|,
        ~S|$xpath->query("//book[@id='$_POST[book_id]']");|,
        ~S|$xpath->query("//employee[department='$_REQUEST[dept]']");|,
        ~S|$xpath->query("//product[category='$_COOKIE[cat]']");|
      ]
      
      for code <- vulnerable_code do
        assert Regex.match?(pattern.regex, code),
               "Should match: #{code}"
      end
    end
    
    test "matches DOMXPath query method", %{pattern: pattern} do
      vulnerable_code = [
        ~S|$domxpath->query("//user[@name='$_GET[name]']");|,
        ~S|$xpath->query("//item[id='$_POST[id]']");|,
        ~S|$xmlXpath->query("//record[value='$_REQUEST[val]']");|
      ]
      
      for code <- vulnerable_code do
        assert Regex.match?(pattern.regex, code),
               "Should match: #{code}"
      end
    end
    
    test "matches evaluate method with user input", %{pattern: pattern} do
      vulnerable_code = [
        ~S|$xpath->evaluate("count(//user[@name='$_GET[name]'])");|,
        ~S|$xpath->evaluate("string(//user[@id='$_POST[id]']/@email)");|,
        ~S|$domxpath->evaluate("//book[title='$_REQUEST[title]']");|
      ]
      
      for code <- vulnerable_code do
        assert Regex.match?(pattern.regex, code),
               "Should match: #{code}"
      end
    end
    
    test "matches various XPath filter constructions", %{pattern: pattern} do
      vulnerable_code = [
        ~S|$xpath->query("//user[@name='$_GET[name]' and @active='1']");|,
        ~S|$xpath->query("//element[contains(@class, '$_GET[class]')]");|,
        ~S|$xpath->query("//item[@id='$_POST[item_id]']");|,
        ~S|$xpath->query("//record[@value='$_COOKIE[value]']");|
      ]
      
      for code <- vulnerable_code do
        assert Regex.match?(pattern.regex, code),
               "Should match: #{code}"
      end
    end
    
    test "matches various spacing and formatting", %{pattern: pattern} do
      vulnerable_code = [
        ~S|$xpath->query( "//user[@name='$_GET[name]']" );|,
        ~S|$xpath->query("//user[@name='" . $_POST['name'] . "']");|,
        ~S|$xpath->evaluate("//user[@id=" . $_REQUEST['id'] . "]");|,
        ~S|$domxpath->query("//book[title='" . $_GET['title'] . "']");|
      ]
      
      for code <- vulnerable_code do
        assert Regex.match?(pattern.regex, code),
               "Should match: #{code}"
      end
    end
    
    test "does not match safe operations", %{pattern: pattern} do
      safe_code = [
        ~S|$xpath->query("//user[@name='safe_value']");|,
        ~S|$xpath->query("//user[@name='" . $safe_var . "']");|,
        ~S|$xpath->query($safe_query);|,
        ~S|$xpath->compile("//user[@name='static']");|,
        ~S|echo "XPath query: " . $_GET['query'];|
      ]
      
      for code <- safe_code do
        refute Regex.match?(pattern.regex, code),
               "Should not match: #{code}"
      end
    end
    
    test "matches real-world vulnerable patterns", %{pattern: pattern} do
      vulnerable_code = [
        ~S|$xpath->query("//user[@username='$_POST[login]' and @password='$_POST[pass]']");|,
        ~S|$domxpath->query("//product[@category='$_GET[cat]' and @price<'$_GET[max_price]']");|,
        ~S|$xpath->evaluate("count(//order[@customer_id='$_REQUEST[customer]'])");|
      ]
      
      for code <- vulnerable_code do
        assert Regex.match?(pattern.regex, code),
               "Should match: #{code}"
      end
    end
  end
  
  describe "test_cases/0" do
    test "all positive cases match" do
      pattern = XpathInjection.pattern()
      test_cases = XpathInjection.test_cases()
      
      for test_case <- test_cases.positive do
        assert Regex.match?(pattern.regex, test_case.code),
               "Failed to match positive case: #{test_case.description}"
      end
    end
    
    test "negative cases are documented correctly" do
      test_cases = XpathInjection.test_cases()
      
      assert length(test_cases.negative) > 0
      
      for test_case <- test_cases.negative do
        assert Map.has_key?(test_case, :code)
        assert Map.has_key?(test_case, :description)
      end
    end
  end
  
  describe "ast_enhancement/0" do
    test "returns proper enhancement rules" do
      enhancement = XpathInjection.ast_enhancement()
      
      assert enhancement.min_confidence >= 0.7
      assert length(enhancement.rules) >= 3
      
      xpath_functions_rule = Enum.find(enhancement.rules, &(&1.type == "xpath_functions"))
      assert xpath_functions_rule
      assert "query" in xpath_functions_rule.methods
      assert "evaluate" in xpath_functions_rule.methods
      
      user_input_rule = Enum.find(enhancement.rules, &(&1.type == "user_input_analysis"))
      assert user_input_rule
      assert "$_GET" in user_input_rule.dangerous_sources
      assert "$_POST" in user_input_rule.dangerous_sources
    end
  end
  
  describe "pattern metadata" do
    test "has proper OWASP reference" do
      pattern = XpathInjection.pattern()
      assert pattern.owasp_category == "A03:2021"
    end
    
    test "has educational content" do
      desc = XpathInjection.vulnerability_description()
      assert desc =~ "XPath injection"
      assert desc =~ "xpath"
      assert desc =~ "query"
    end
    
    test "provides safe alternatives" do
      examples = XpathInjection.examples()
      assert Map.has_key?(examples.fixed, "Input validation")
      assert Map.has_key?(examples.fixed, "Parameterized queries")
    end
  end
end