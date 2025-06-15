defmodule RsolvApi.Security.Patterns.Php.XssPrintTest do
  use ExUnit.Case, async: true
  
  alias RsolvApi.Security.Patterns.Php.XssPrint
  alias RsolvApi.Security.Pattern
  
  describe "pattern/0" do
    test "returns a valid pattern struct" do
      pattern = XssPrint.pattern()
      
      assert %Pattern{} = pattern
      assert pattern.id == "php-xss-print"
      assert pattern.name == "XSS via print"
      assert pattern.severity == :high
      assert pattern.type == :xss
      assert pattern.languages == ["php"]
    end
    
    test "includes CWE and OWASP references" do
      pattern = XssPrint.pattern()
      
      assert pattern.cwe_id == "CWE-79"
      assert pattern.owasp_category == "A03:2021"
    end
  end
  
  describe "regex matching" do
    setup do
      pattern = XssPrint.pattern()
      {:ok, pattern: pattern}
    end
    
    test "matches print with direct user input", %{pattern: pattern} do
      vulnerable_code = [
        ~S|print $_GET['name'];|,
        ~S|print $_POST['comment'];|,
        ~S|print $_REQUEST['value'];|,
        ~S|print $_COOKIE['session'];|
      ]
      
      for code <- vulnerable_code do
        assert Regex.match?(pattern.regex, code),
               "Should match: #{code}"
      end
    end
    
    test "matches print with concatenation", %{pattern: pattern} do
      vulnerable_code = [
        ~S|print "Hello " . $_GET['user'];|,
        ~S|print 'Welcome ' . $_POST['name'] . '!';|,
        ~S|print "<div>" . $_REQUEST['content'] . "</div>";|
      ]
      
      for code <- vulnerable_code do
        assert Regex.match?(pattern.regex, code),
               "Should match: #{code}"
      end
    end
    
    test "matches print with interpolation", %{pattern: pattern} do
      vulnerable_code = [
        ~S|print "Welcome $_GET[user]";|,
        ~S|print "Hello {$_POST['name']}!";|,
        ~S|print "<h1>$_REQUEST[title]</h1>";|
      ]
      
      for code <- vulnerable_code do
        assert Regex.match?(pattern.regex, code),
               "Should match: #{code}"
      end
    end
    
    test "matches print with parentheses", %{pattern: pattern} do
      vulnerable_code = [
        ~S|print($_GET['message']);|,
        ~S|print("User: " . $_POST['user']);|,
        ~S|print('Status: ' . $_COOKIE['status']);|
      ]
      
      for code <- vulnerable_code do
        assert Regex.match?(pattern.regex, code),
               "Should match: #{code}"
      end
    end
    
    test "does not match safe code with htmlspecialchars", %{pattern: pattern} do
      safe_code = [
        ~S|print htmlspecialchars($_GET['name'], ENT_QUOTES, 'UTF-8');|,
        ~S|print htmlspecialchars($_POST['comment'], ENT_QUOTES);|,
        ~S|print "Welcome " . htmlspecialchars($_GET['user'], ENT_QUOTES);|,
        ~S|print("<p>" . htmlspecialchars($user_input, ENT_QUOTES) . "</p>");|
      ]
      
      for code <- safe_code do
        refute Regex.match?(pattern.regex, code),
               "Should not match: #{code}"
      end
    end
    
    test "does not match print without user input", %{pattern: pattern} do
      safe_code = [
        ~S|print "Hello World";|,
        ~S|print $safe_variable;|,
        ~S|print CONSTANT_VALUE;|,
        ~S|print date('Y-m-d');|
      ]
      
      for code <- safe_code do
        refute Regex.match?(pattern.regex, code),
               "Should not match: #{code}"
      end
    end
  end
  
  describe "test_cases/0" do
    test "all positive cases match" do
      pattern = XssPrint.pattern()
      test_cases = XssPrint.test_cases()
      
      for test_case <- test_cases.positive do
        assert Regex.match?(pattern.regex, test_case.code),
               "Failed to match positive case: #{test_case.description}"
      end
    end
    
    test "negative cases are documented correctly" do
      test_cases = XssPrint.test_cases()
      
      assert length(test_cases.negative) > 0
      
      for test_case <- test_cases.negative do
        assert Map.has_key?(test_case, :code)
        assert Map.has_key?(test_case, :description)
      end
    end
  end
  
  describe "ast_enhancement/0" do
    test "returns proper enhancement rules" do
      enhancement = XssPrint.ast_enhancement()
      
      assert enhancement.min_confidence >= 0.7
      assert length(enhancement.rules) >= 2
      
      output_context_rule = Enum.find(enhancement.rules, &(&1.type == "output_context"))
      assert output_context_rule
      assert "print" in output_context_rule.functions
      
      sanitization_rule = Enum.find(enhancement.rules, &(&1.type == "input_sanitization"))
      assert sanitization_rule
      assert "htmlspecialchars" in sanitization_rule.safe_functions
    end
  end
  
  describe "pattern metadata" do
    test "has proper OWASP reference" do
      pattern = XssPrint.pattern()
      assert pattern.owasp_category == "A03:2021"
    end
    
    test "has educational content" do
      desc = XssPrint.vulnerability_description()
      assert desc =~ "XSS"
      assert desc =~ "cross-site scripting"
      assert desc =~ "print"
    end
    
    test "provides safe alternatives" do
      examples = XssPrint.examples()
      assert Map.has_key?(examples.fixed, "Using htmlspecialchars()")
      assert Map.has_key?(examples.fixed, "Safe print wrapper")
    end
  end
end