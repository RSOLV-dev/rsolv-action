defmodule RsolvApi.Security.Patterns.Php.ErrorDisplayTest do
  use ExUnit.Case, async: true
  
  alias RsolvApi.Security.Patterns.Php.ErrorDisplay
  alias RsolvApi.Security.Pattern
  
  describe "pattern/0" do
    test "returns a valid pattern struct" do
      pattern = ErrorDisplay.pattern()
      
      assert %Pattern{} = pattern
      assert pattern.id == "php-error-display"
      assert pattern.name == "Detailed Error Display"
      assert pattern.severity == :low
      assert pattern.type == :information_disclosure
      assert pattern.languages == ["php"]
    end
    
    test "includes CWE and OWASP references" do
      pattern = ErrorDisplay.pattern()
      
      assert pattern.cwe_id == "CWE-209"
      assert pattern.owasp_category == "A05:2021"
    end
  end
  
  describe "regex matching" do
    setup do
      pattern = ErrorDisplay.pattern()
      {:ok, pattern: pattern}
    end
    
    test "matches die with error concatenation", %{pattern: pattern} do
      vulnerable_code = [
        ~S|die("Database error: " . mysqli_error($conn));|,
        ~S|die('Database error: ' . mysqli_error($conn));|,
        ~S|die("Connection failed: " . mysql_error());|,
        ~S|die('Query error: ' . pg_last_error($conn));|
      ]
      
      for code <- vulnerable_code do
        assert Regex.match?(pattern.regex, code),
               "Should match: #{code}"
      end
    end
    
    test "matches exit with error concatenation", %{pattern: pattern} do
      vulnerable_code = [
        ~S|exit("Query failed: " . pg_last_error());|,
        ~S|exit('SQL error: ' . mysqli_error($connection));|,
        ~S|exit("DB error: " . mysql_errno($link));|
      ]
      
      for code <- vulnerable_code do
        assert Regex.match?(pattern.regex, code),
               "Should match: #{code}"
      end
    end
    
    test "matches various error function names", %{pattern: pattern} do
      vulnerable_code = [
        ~S|die("Error: " . mysqli_error($conn));|,
        ~S|die("Error: " . mysql_error());|,
        ~S|die("Error: " . pg_last_error());|,
        ~S|die("Error: " . oci_error());|,
        ~S|die("Error: " . sqlsrv_errors());|,
        ~S|die("Error: " . mysqli_errno($conn));|,
        ~S|die("Error: " . mysql_errno());|
      ]
      
      for code <- vulnerable_code do
        assert Regex.match?(pattern.regex, code),
               "Should match: #{code}"
      end
    end
    
    test "does not match safe error handling", %{pattern: pattern} do
      safe_code = [
        ~S|die("An error occurred. Please try again later.");|,
        ~S|exit("Operation failed");|,
        ~S|error_log("Database error: " . mysqli_error($conn));|,
        ~S|$error = mysqli_error($conn);|
      ]
      
      for code <- safe_code do
        refute Regex.match?(pattern.regex, code),
               "Should not match: #{code}"
      end
    end
    
    test "matches with various spacing", %{pattern: pattern} do
      vulnerable_code = [
        ~S|die( "Error: " . mysqli_error($conn) );|,
        ~S|die("Error: ".mysqli_error($conn));|,
        ~S|die ("Error: " . mysqli_error($conn));|
      ]
      
      for code <- vulnerable_code do
        assert Regex.match?(pattern.regex, code),
               "Should match: #{code}"
      end
    end
    
    test "matches commented code (regex limitation)", %{pattern: pattern} do
      # Regex cannot detect comments - this is a known limitation
      code = ~S|// die("Database error: " . mysqli_error($conn));|
      
      assert Regex.match?(pattern.regex, code),
             "Regex matches commented code (AST needed to exclude)"
    end
  end
  
  describe "test_cases/0" do
    test "all positive cases match" do
      pattern = ErrorDisplay.pattern()
      test_cases = ErrorDisplay.test_cases()
      
      for test_case <- test_cases.positive do
        assert Regex.match?(pattern.regex, test_case.code),
               "Failed to match positive case: #{test_case.description}"
      end
    end
    
    test "negative cases are documented correctly" do
      test_cases = ErrorDisplay.test_cases()
      
      assert length(test_cases.negative) > 0
      
      for test_case <- test_cases.negative do
        assert Map.has_key?(test_case, :code)
        assert Map.has_key?(test_case, :description)
      end
    end
  end
  
  describe "ast_enhancement/0" do
    test "returns proper enhancement rules" do
      enhancement = ErrorDisplay.ast_enhancement()
      
      assert enhancement.min_confidence >= 0.6
      assert length(enhancement.rules) >= 3
      
      error_rule = Enum.find(enhancement.rules, &(&1.type == "error_functions"))
      assert error_rule
      assert "mysqli_error" in error_rule.database_errors
      
      output_rule = Enum.find(enhancement.rules, &(&1.type == "output_context"))
      assert output_rule
      assert "die" in output_rule.dangerous_outputs
    end
  end
  
  describe "pattern metadata" do
    test "has proper OWASP reference" do
      pattern = ErrorDisplay.pattern()
      assert pattern.owasp_category == "A05:2021"
    end
    
    test "has educational content" do
      desc = ErrorDisplay.vulnerability_description()
      assert desc =~ "error"
      assert desc =~ "information"
      assert desc =~ "sensitive"
    end
    
    test "provides safe alternatives" do
      examples = ErrorDisplay.examples()
      assert Map.has_key?(examples.fixed, "Generic error message")
      assert Map.has_key?(examples.fixed, "Structured error handling")
    end
  end
end