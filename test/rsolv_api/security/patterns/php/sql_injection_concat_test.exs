defmodule RsolvApi.Security.Patterns.Php.SqlInjectionConcatTest do
  use ExUnit.Case, async: true
  
  alias RsolvApi.Security.Patterns.Php.SqlInjectionConcat
  alias RsolvApi.Security.Pattern
  
  describe "pattern/0" do
    test "returns a valid pattern struct" do
      pattern = SqlInjectionConcat.pattern()
      
      assert %Pattern{} = pattern
      assert pattern.id == "php-sql-injection-concat"
      assert pattern.name == "SQL Injection via String Concatenation"
      assert pattern.severity == :critical
      assert pattern.type == :sql_injection
      assert pattern.languages == ["php"]
    end
    
    test "includes CWE and OWASP references" do
      pattern = SqlInjectionConcat.pattern()
      
      assert pattern.cwe_id == "CWE-89"
      assert pattern.owasp_category == "A03:2021"
    end
  end
  
  describe "regex matching" do
    setup do
      pattern = SqlInjectionConcat.pattern()
      {:ok, pattern: pattern}
    end
    
    test "matches SELECT with concatenation", %{pattern: pattern} do
      vulnerable_code = [
        ~S|$query = "SELECT * FROM users WHERE id = " . $_GET['id'];|,
        ~S|$sql = "SELECT name FROM products WHERE category = " . $_POST['cat'];|,
        ~S|$query = 'SELECT * FROM orders WHERE status = ' . $_REQUEST['status'];|,
        ~S|$q = "SELECT email FROM users WHERE name = " . $_COOKIE['username'];|
      ]
      
      for code <- vulnerable_code do
        assert Regex.match?(pattern.regex, code),
               "Should match: #{code}"
      end
    end
    
    test "matches DELETE with concatenation", %{pattern: pattern} do
      vulnerable_code = [
        ~S|$sql = 'DELETE FROM posts WHERE author = ' . $_POST['author'];|,
        ~S|$query = "DELETE FROM comments WHERE id = " . $_GET['comment_id'];|
      ]
      
      for code <- vulnerable_code do
        assert Regex.match?(pattern.regex, code),
               "Should match: #{code}"
      end
    end
    
    test "matches UPDATE with concatenation", %{pattern: pattern} do
      vulnerable_code = [
        ~S|$sql = "UPDATE users SET status = 'active' WHERE id = " . $_GET['user'];|,
        ~S|$query = 'UPDATE products SET price = ' . $_POST['price'] . ' WHERE id = 1';|
      ]
      
      for code <- vulnerable_code do
        assert Regex.match?(pattern.regex, code),
               "Should match: #{code}"
      end
    end
    
    test "matches INSERT with concatenation", %{pattern: pattern} do
      vulnerable_code = [
        ~S|$sql = "INSERT INTO logs (message) VALUES ('" . $_GET['msg'] . "')";|,
        ~S|$query = 'INSERT INTO users (name, email) VALUES (' . $_POST['data'] . ')';|
      ]
      
      for code <- vulnerable_code do
        assert Regex.match?(pattern.regex, code),
               "Should match: #{code}"
      end
    end
    
    test "matches case insensitive", %{pattern: pattern} do
      vulnerable_code = [
        ~S|$query = "select * from users where id = " . $_GET['id'];|,
        ~S|$sql = "Select name From products Where category = " . $_POST['cat'];|,
        ~S|$q = "DeLeTe FROM posts WHERE id = " . $_REQUEST['id'];|
      ]
      
      for code <- vulnerable_code do
        assert Regex.match?(pattern.regex, code),
               "Should match case insensitive: #{code}"
      end
    end
    
    test "does not match safe prepared statements", %{pattern: pattern} do
      safe_code = [
        ~S|$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");|,
        ~S|$stmt = $mysqli->prepare("DELETE FROM posts WHERE author = ?");|,
        ~S|$query = "SELECT * FROM users WHERE id = :id"; // PDO named params|,
        ~S|// Comment: SELECT * FROM users WHERE id = $_GET['id']|
      ]
      
      for code <- safe_code do
        refute Regex.match?(pattern.regex, code),
               "Should not match: #{code}"
      end
    end
    
    test "matches even in comments (AST will filter)", %{pattern: pattern} do
      # Regex patterns can't easily distinguish comments
      # AST analysis handles this in production
      comment_code = [
        ~S|// $query = "SELECT * FROM users WHERE id = " . $_GET['id'];|
      ]
      
      for code <- comment_code do
        # Comments with the actual pattern will match
        assert Regex.match?(pattern.regex, code),
               "Regex matches comments (filtered by AST): #{code}"
      end
    end
  end
  
  describe "test_cases/0" do
    test "all positive cases match" do
      pattern = SqlInjectionConcat.pattern()
      test_cases = SqlInjectionConcat.test_cases()
      
      for test_case <- test_cases.positive do
        assert Regex.match?(pattern.regex, test_case.code),
               "Failed to match positive case: #{test_case.description}"
      end
    end
    
    test "negative cases are documented correctly" do
      test_cases = SqlInjectionConcat.test_cases()
      
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
      enhancement = SqlInjectionConcat.ast_enhancement()
      
      assert enhancement.min_confidence == 0.9
      assert length(enhancement.ast_rules) == 3
      
      db_context_rule = Enum.find(enhancement.ast_rules, &(&1.type == "database_context"))
      assert "query" in db_context_rule.patterns
      assert "sql" in db_context_rule.patterns
      
      sanitization_rule = Enum.find(enhancement.ast_rules, &(&1.type == "input_sanitization"))
      assert "mysqli_real_escape_string" in sanitization_rule.safe_functions
      assert "addslashes" in sanitization_rule.safe_functions
      
      prepared_stmt_rule = Enum.find(enhancement.ast_rules, &(&1.type == "prepared_statement_check"))
      assert "prepare" in prepared_stmt_rule.safe_patterns
      assert "bindParam" in prepared_stmt_rule.safe_patterns
    end
  end
  
  describe "pattern metadata" do
    test "has proper OWASP reference" do
      pattern = SqlInjectionConcat.pattern()
      assert pattern.owasp_category == "A03:2021"
    end
    
    test "has educational content" do
      desc = SqlInjectionConcat.vulnerability_description()
      assert desc =~ "CVE"
      assert desc =~ "SQL injection"
      assert desc =~ "concatenation"
    end
    
    test "provides safe alternatives" do
      examples = SqlInjectionConcat.examples()
      assert Map.has_key?(examples.fixed, "PDO with prepared statements")
      assert Map.has_key?(examples.fixed, "MySQLi with prepared statements")
    end
  end
  
  # Helper functions for cleaner tests
  defp assert_vulnerable(pattern, code_samples) do
    for code <- code_samples do
      assert Regex.match?(pattern.regex, code), 
             "Should match vulnerable code: #{code}"
    end
  end
  
  defp refute_safe(pattern, code_samples) do
    for code <- code_samples do
      refute Regex.match?(pattern.regex, code), 
             "Should not match safe code: #{code}"
    end
  end
end