defmodule Rsolv.Security.Patterns.Php.XssEchoTest do
  use ExUnit.Case, async: true
  
  alias Rsolv.Security.Patterns.Php.XssEcho
  alias Rsolv.Security.Pattern
  
  describe "pattern/0" do
    test "returns a valid pattern struct" do
      pattern = XssEcho.pattern()
      
      assert %Pattern{} = pattern
      assert pattern.id == "php-xss-echo"
      assert pattern.name == "XSS via echo"
      assert pattern.severity == :high
      assert pattern.type == :xss
      assert pattern.languages == ["php"]
    end
    
    test "includes CWE and OWASP references" do
      pattern = XssEcho.pattern()
      
      assert pattern.cwe_id == "CWE-79"
      assert pattern.owasp_category == "A03:2021"
    end
  end
  
  describe "regex matching" do
    setup do
      pattern = XssEcho.pattern()
      {:ok, pattern: pattern}
    end
    
    test "matches echo with direct user input", %{pattern: pattern} do
      vulnerable_code = [
        ~S|echo $_GET['name'];|,
        ~S|echo $_POST['comment'];|,
        ~S|echo $_REQUEST['value'];|,
        ~S|echo $_COOKIE['session'];|
      ]
      
      for code <- vulnerable_code do
        assert Regex.match?(pattern.regex, code),
               "Should match: #{code}"
      end
    end
    
    test "matches echo with concatenation", %{pattern: pattern} do
      vulnerable_code = [
        ~S|echo "Welcome " . $_GET['user'];|,
        ~S|echo 'Hello ' . $_POST['name'] . '!';|,
        ~S|echo "<div>" . $_REQUEST['content'] . "</div>";|
      ]
      
      for code <- vulnerable_code do
        assert Regex.match?(pattern.regex, code),
               "Should match: #{code}"
      end
    end
    
    test "matches echo with interpolation", %{pattern: pattern} do
      vulnerable_code = [
        ~S|echo "Welcome $_GET[user]";|,
        ~S|echo "Hello {$_POST['name']}!";|,
        ~S|echo "<h1>$_REQUEST[title]</h1>";|
      ]
      
      for code <- vulnerable_code do
        assert Regex.match?(pattern.regex, code),
               "Should match: #{code}"
      end
    end
    
    test "matches echo with complex expressions", %{pattern: pattern} do
      vulnerable_code = [
        ~S|echo "<p>User: " . $_GET['user'] . " - Status: " . $_GET['status'] . "</p>";|,
        ~S|echo $_GET['prefix'] . $data . $_GET['suffix'];|,
        ~S|echo trim($_POST['input']);|
      ]
      
      for code <- vulnerable_code do
        assert Regex.match?(pattern.regex, code),
               "Should match: #{code}"
      end
    end
    
    test "does not match safe code with htmlspecialchars", %{pattern: pattern} do
      safe_code = [
        ~S|echo htmlspecialchars($_GET['name'], ENT_QUOTES, 'UTF-8');|,
        ~S|echo htmlspecialchars($_POST['comment'], ENT_QUOTES);|,
        ~S|echo "Welcome " . htmlspecialchars($_GET['user'], ENT_QUOTES);|,
        ~S|echo "<p>" . htmlspecialchars($user_input, ENT_QUOTES) . "</p>";|
      ]
      
      for code <- safe_code do
        refute Regex.match?(pattern.regex, code),
               "Should not match: #{code}"
      end
    end
    
    test "does not match echo without user input", %{pattern: pattern} do
      safe_code = [
        ~S|echo "Hello World";|,
        ~S|echo $safe_variable;|,
        ~S|echo CONSTANT_VALUE;|,
        ~S|echo date('Y-m-d');|
      ]
      
      for code <- safe_code do
        refute Regex.match?(pattern.regex, code),
               "Should not match: #{code}"
      end
    end
    
    test "matches echo with array access variations", %{pattern: pattern} do
      vulnerable_code = [
        ~S|echo $_GET["name"];|,  # Double quotes
        ~S|echo $_GET['name'];|,  # Single quotes
        ~S|echo $_GET[name];|,    # No quotes (PHP style)
      ]
      
      for code <- vulnerable_code do
        assert Regex.match?(pattern.regex, code),
               "Should match: #{code}"
      end
    end
  end
  
  describe "test_cases/0" do
    test "all positive cases match" do
      pattern = XssEcho.pattern()
      test_cases = XssEcho.test_cases()
      
      for test_case <- test_cases.positive do
        assert Regex.match?(pattern.regex, test_case.code),
               "Failed to match positive case: #{test_case.description}"
      end
    end
    
    test "negative cases are documented correctly" do
      test_cases = XssEcho.test_cases()
      
      # Verify we have negative test cases documented
      assert length(test_cases.negative) > 0
      
      # Each negative case should have code and description
      for test_case <- test_cases.negative do
        assert Map.has_key?(test_case, :code)
        assert Map.has_key?(test_case, :description)
      end
    end
  end
  
  describe "ast_enhancement/0" do
    test "returns proper enhancement rules" do
      enhancement = XssEcho.ast_enhancement()
      
      assert enhancement.min_confidence >= 0.7
      assert length(enhancement.ast_rules) >= 2
      
      # Check for output context rule
      output_context_rule = Enum.find(enhancement.ast_rules, &(&1.type == "output_context"))
      assert output_context_rule
      assert "echo" in output_context_rule.functions
      
      # Check for sanitization rule
      sanitization_rule = Enum.find(enhancement.ast_rules, &(&1.type == "input_sanitization"))
      assert sanitization_rule
      assert "htmlspecialchars" in sanitization_rule.safe_functions
    end
  end
  
  describe "pattern metadata" do
    test "has proper OWASP reference" do
      pattern = XssEcho.pattern()
      assert pattern.owasp_category == "A03:2021"
    end
    
    test "has educational content" do
      desc = XssEcho.vulnerability_description()
      assert desc =~ "XSS"
      assert desc =~ "cross-site scripting"
      assert desc =~ "htmlspecialchars"
    end
    
    test "provides safe alternatives" do
      examples = XssEcho.examples()
      assert Map.has_key?(examples.fixed, "Using htmlspecialchars()")
      assert Map.has_key?(examples.fixed, "Context-aware escaping")
    end
  end
end