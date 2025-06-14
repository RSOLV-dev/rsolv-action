defmodule RsolvApi.Security.Patterns.Php.SqlInjectionInterpolationTest do
  use ExUnit.Case, async: true
  
  alias RsolvApi.Security.Patterns.Php.SqlInjectionInterpolation
  alias RsolvApi.Security.Pattern
  
  describe "pattern/0" do
    test "returns a valid pattern struct" do
      pattern = SqlInjectionInterpolation.pattern()
      
      assert %Pattern{} = pattern
      assert pattern.id == "php-sql-injection-interpolation"
      assert pattern.name == "SQL Injection via Variable Interpolation"
      assert pattern.severity == :critical
      assert pattern.type == :sql_injection
      assert pattern.languages == ["php"]
    end
    
    test "includes CWE and OWASP references" do
      pattern = SqlInjectionInterpolation.pattern()
      
      assert pattern.cwe_id == "CWE-89"
      assert pattern.owasp_category == "A03:2021"
    end
  end
  
  describe "regex matching" do
    setup do
      pattern = SqlInjectionInterpolation.pattern()
      {:ok, pattern: pattern}
    end
    
    test "matches SELECT with interpolation", %{pattern: pattern} do
      vulnerable_code = [
        ~S|$query = "SELECT * FROM users WHERE name = '$_GET[name]'";|,
        ~S|$sql = "SELECT * FROM products WHERE id = $_POST[id]";|,
        ~S|$q = "SELECT email FROM users WHERE status = '$_REQUEST[status]'";|,
        ~S|$query = "SELECT * FROM sessions WHERE token = '$_COOKIE[session]'";|
      ]
      
      for code <- vulnerable_code do
        assert Regex.match?(pattern.regex, code),
               "Should match: #{code}"
      end
    end
    
    test "matches DELETE with interpolation", %{pattern: pattern} do
      vulnerable_code = [
        ~S|$sql = "DELETE FROM comments WHERE id = $_GET[comment_id]";|,
        ~S|$query = "DELETE FROM posts WHERE author_id = $_POST[author]";|
      ]
      
      for code <- vulnerable_code do
        assert Regex.match?(pattern.regex, code),
               "Should match: #{code}"
      end
    end
    
    test "matches UPDATE with interpolation", %{pattern: pattern} do
      vulnerable_code = [
        ~S|$sql = "UPDATE users SET email = '$_POST[email]' WHERE id = $id";|,
        ~S|$query = "UPDATE products SET price = $_REQUEST[price] WHERE sku = '$sku'";|
      ]
      
      for code <- vulnerable_code do
        assert Regex.match?(pattern.regex, code),
               "Should match: #{code}"
      end
    end
    
    test "matches INSERT with interpolation", %{pattern: pattern} do
      vulnerable_code = [
        ~S|$sql = "INSERT INTO logs (ip, action) VALUES ('$_SERVER[REMOTE_ADDR]', '$_GET[action]')";|,
        ~S|$query = "INSERT INTO users (name) VALUES ('$_POST[username]')";|
      ]
      
      for code <- vulnerable_code do
        assert Regex.match?(pattern.regex, code),
               "Should match: #{code}"
      end
    end
    
    test "matches with mysqli_query and mysql_query", %{pattern: pattern} do
      vulnerable_code = [
        ~S|mysqli_query($conn, "SELECT * FROM users WHERE name = '$_GET[name]'");|,
        ~S|mysql_query("UPDATE users SET email = '$_POST[email]' WHERE id = $id");|
      ]
      
      for code <- vulnerable_code do
        assert Regex.match?(pattern.regex, code),
               "Should match: #{code}"
      end
    end
    
    test "matches complex interpolation with brackets", %{pattern: pattern} do
      vulnerable_code = [
        ~S|$query = "SELECT * FROM users WHERE name = '{$_GET['name']}'";|,
        ~S|$sql = "DELETE FROM posts WHERE id = {$_POST['id']}";|
      ]
      
      for code <- vulnerable_code do
        assert Regex.match?(pattern.regex, code),
               "Should match: #{code}"
      end
    end
    
    test "matches case insensitive SQL keywords", %{pattern: pattern} do
      vulnerable_code = [
        ~S|$query = "select * from users where id = $_GET[id]";|,
        ~S|$sql = "Select name From products Where category = '$_POST[cat]'";|,
        ~S|$q = "DeLeTe FROM posts WHERE id = $_REQUEST[id]";|
      ]
      
      for code <- vulnerable_code do
        assert Regex.match?(pattern.regex, code),
               "Should match case insensitive: #{code}"
      end
    end
    
    test "does not match safe prepared statements", %{pattern: pattern} do
      safe_code = [
        ~S|$stmt = $pdo->prepare("SELECT * FROM users WHERE name = :name");|,
        ~S|$stmt = $mysqli->prepare("DELETE FROM posts WHERE author = ?");|,
        ~S|$query = "SELECT * FROM users WHERE role = 'admin'";|,
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
        ~S|// $query = "SELECT * FROM users WHERE id = $_GET[id]";|
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
      pattern = SqlInjectionInterpolation.pattern()
      test_cases = SqlInjectionInterpolation.test_cases()
      
      for test_case <- test_cases.positive do
        assert Regex.match?(pattern.regex, test_case.code),
               "Failed to match positive case: #{test_case.description}"
      end
    end
    
    test "negative cases are documented correctly" do
      test_cases = SqlInjectionInterpolation.test_cases()
      
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
      enhancement = SqlInjectionInterpolation.ast_enhancement()
      
      assert enhancement.min_confidence == 0.9
      assert length(enhancement.rules) == 3
      
      interpolation_rule = Enum.find(enhancement.rules, &(&1.type == "interpolation_detection"))
      assert "double_quotes" in interpolation_rule.string_types
      assert "curly_braces" in interpolation_rule.string_types
      
      db_context_rule = Enum.find(enhancement.rules, &(&1.type == "database_context"))
      assert "query" in db_context_rule.patterns
      assert "sql" in db_context_rule.patterns
      
      sanitization_rule = Enum.find(enhancement.rules, &(&1.type == "input_escaping"))
      assert "mysqli_real_escape_string" in sanitization_rule.escape_functions
      assert "htmlspecialchars" not in sanitization_rule.escape_functions  # Wrong type of escaping
    end
  end
  
  describe "pattern metadata" do
    test "has proper OWASP reference" do
      pattern = SqlInjectionInterpolation.pattern()
      assert pattern.owasp_category == "A03:2021"
    end
    
    test "has educational content" do
      desc = SqlInjectionInterpolation.vulnerability_description()
      assert desc =~ "CVE"
      assert desc =~ "interpolation"
      assert desc =~ "double quotes"
    end
    
    test "provides safe alternatives" do
      examples = SqlInjectionInterpolation.examples()
      assert Map.has_key?(examples.fixed, "PDO with named parameters")
      assert Map.has_key?(examples.fixed, "MySQLi with positional placeholders")
    end
  end
end