defmodule RsolvApi.Security.Patterns.Php.FileInclusionTest do
  use ExUnit.Case, async: true
  
  alias RsolvApi.Security.Patterns.Php.FileInclusion
  alias RsolvApi.Security.Pattern
  
  describe "pattern/0" do
    test "returns a valid pattern struct" do
      pattern = FileInclusion.pattern()
      
      assert %Pattern{} = pattern
      assert pattern.id == "php-file-inclusion"
      assert pattern.name == "File Inclusion Vulnerability"
      assert pattern.severity == :critical
      assert pattern.type == :file_inclusion
      assert pattern.languages == ["php"]
    end
    
    test "includes CWE and OWASP references" do
      pattern = FileInclusion.pattern()
      
      assert pattern.cwe_id == "CWE-98"
      assert pattern.owasp_category == "A03:2021"
    end
  end
  
  describe "regex matching" do
    setup do
      pattern = FileInclusion.pattern()
      {:ok, pattern: pattern}
    end
    
    test "matches include with user input", %{pattern: pattern} do
      vulnerable_code = [
        ~S|include $_GET['page'] . '.php';|,
        ~S|include($_POST['template']);|,
        ~S|include $_REQUEST['file'];|,
        ~S|include($_COOKIE['theme'] . '/header.php');|
      ]
      
      for code <- vulnerable_code do
        assert Regex.match?(pattern.regex, code),
               "Should match: #{code}"
      end
    end
    
    test "matches require with user input", %{pattern: pattern} do
      vulnerable_code = [
        ~S|require $_GET['module'] . '.php';|,
        ~S|require($_POST['config']);|,
        ~S|require $_REQUEST['lib'];|,
        ~S|require($_COOKIE['lang'] . '/strings.php');|
      ]
      
      for code <- vulnerable_code do
        assert Regex.match?(pattern.regex, code),
               "Should match: #{code}"
      end
    end
    
    test "matches include_once and require_once", %{pattern: pattern} do
      vulnerable_code = [
        ~S|include_once $_GET['plugin'] . '.php';|,
        ~S|include_once($_POST['addon']);|,
        ~S|require_once $_REQUEST['class'];|,
        ~S|require_once($_COOKIE['vendor'] . '/autoload.php');|
      ]
      
      for code <- vulnerable_code do
        assert Regex.match?(pattern.regex, code),
               "Should match: #{code}"
      end
    end
    
    test "matches complex path constructions", %{pattern: pattern} do
      vulnerable_code = [
        ~S|include 'pages/' . $_GET['page'] . '.php';|,
        ~S|require_once(dirname(__FILE__) . '/' . $_POST['dir'] . '/config.php');|,
        ~S|include_once($_GET['lang'] . '/locale/' . $_GET['file']);|
      ]
      
      for code <- vulnerable_code do
        assert Regex.match?(pattern.regex, code),
               "Should match: #{code}"
      end
    end
    
    test "does not match safe code with validation", %{pattern: pattern} do
      safe_code = [
        ~S|include 'config.php';|,
        ~S|require_once 'vendor/autoload.php';|,
        ~S|include_once dirname(__FILE__) . '/constants.php';|,
        ~S|require __DIR__ . '/bootstrap.php';|
      ]
      
      for code <- safe_code do
        refute Regex.match?(pattern.regex, code),
               "Should not match: #{code}"
      end
    end
    
    test "matches without parentheses", %{pattern: pattern} do
      vulnerable_code = [
        ~S|include $_GET['file'];|,
        ~S|require $_POST['module'];|,
        ~S|include_once $_REQUEST['page'];|,
        ~S|require_once $_COOKIE['template'];|
      ]
      
      for code <- vulnerable_code do
        assert Regex.match?(pattern.regex, code),
               "Should match: #{code}"
      end
    end
  end
  
  describe "test_cases/0" do
    test "all positive cases match" do
      pattern = FileInclusion.pattern()
      test_cases = FileInclusion.test_cases()
      
      for test_case <- test_cases.positive do
        assert Regex.match?(pattern.regex, test_case.code),
               "Failed to match positive case: #{test_case.description}"
      end
    end
    
    test "negative cases are documented correctly" do
      test_cases = FileInclusion.test_cases()
      
      assert length(test_cases.negative) > 0
      
      for test_case <- test_cases.negative do
        assert Map.has_key?(test_case, :code)
        assert Map.has_key?(test_case, :description)
      end
    end
  end
  
  describe "ast_enhancement/0" do
    test "returns proper enhancement rules" do
      enhancement = FileInclusion.ast_enhancement()
      
      assert enhancement.min_confidence >= 0.8
      assert length(enhancement.rules) >= 3
      
      inclusion_context_rule = Enum.find(enhancement.rules, &(&1.type == "inclusion_context"))
      assert inclusion_context_rule
      assert "include" in inclusion_context_rule.functions
      
      path_validation_rule = Enum.find(enhancement.rules, &(&1.type == "path_validation"))
      assert path_validation_rule
      assert "realpath" in path_validation_rule.safe_functions
    end
  end
  
  describe "pattern metadata" do
    test "has proper OWASP reference" do
      pattern = FileInclusion.pattern()
      assert pattern.owasp_category == "A03:2021"
    end
    
    test "has educational content" do
      desc = FileInclusion.vulnerability_description()
      assert desc =~ "file inclusion"
      assert desc =~ "LFI"
      assert desc =~ "RFI"
    end
    
    test "provides safe alternatives" do
      examples = FileInclusion.examples()
      assert Map.has_key?(examples.fixed, "Whitelist approach")
      assert Map.has_key?(examples.fixed, "Path validation")
    end
  end
end