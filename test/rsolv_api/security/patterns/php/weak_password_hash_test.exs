defmodule RsolvApi.Security.Patterns.Php.WeakPasswordHashTest do
  use ExUnit.Case, async: true
  
  alias RsolvApi.Security.Patterns.Php.WeakPasswordHash
  alias RsolvApi.Security.Pattern
  
  describe "pattern/0" do
    test "returns a valid pattern struct" do
      pattern = WeakPasswordHash.pattern()
      
      assert %Pattern{} = pattern
      assert pattern.id == "php-weak-password-hash"
      assert pattern.name == "Weak Password Hashing"
      assert pattern.severity == :critical
      assert pattern.type == :crypto
      assert pattern.languages == ["php"]
    end
    
    test "includes CWE and OWASP references" do
      pattern = WeakPasswordHash.pattern()
      
      assert pattern.cwe_id == "CWE-916"
      assert pattern.owasp_category == "A02:2021"
    end
  end
  
  describe "regex matching" do
    setup do
      pattern = WeakPasswordHash.pattern()
      {:ok, pattern: pattern}
    end
    
    test "matches MD5 password hashing", %{pattern: pattern} do
      vulnerable_code = [
        ~S|md5($_POST['password']);|,
        ~S|$hash = md5($password);|,
        ~S|md5($_GET['pass'] . $salt);|,
        ~S|$pwd_hash = md5($_REQUEST['password']);|
      ]
      
      for code <- vulnerable_code do
        assert Regex.match?(pattern.regex, code),
               "Should match: #{code}"
      end
    end
    
    test "matches SHA1 password hashing", %{pattern: pattern} do
      vulnerable_code = [
        ~S|sha1($_POST['password']);|,
        ~S|$hash = sha1($password);|,
        ~S|sha1($salt . $_GET['pass']);|,
        ~S|$stored = sha1($_REQUEST['pwd']);|
      ]
      
      for code <- vulnerable_code do
        assert Regex.match?(pattern.regex, code),
               "Should match: #{code}"
      end
    end
    
    test "matches crypt() without proper algorithm", %{pattern: pattern} do
      vulnerable_code = [
        ~S|crypt($_POST['password']);|,
        ~S|crypt($password, $salt);|,
        ~S|$hash = crypt($_GET['pass']);|
      ]
      
      for code <- vulnerable_code do
        assert Regex.match?(pattern.regex, code),
               "Should match: #{code}"
      end
    end
    
    test "matches hash() with weak algorithms", %{pattern: pattern} do
      vulnerable_code = [
        ~S|hash('md5', $_POST['password']);|,
        ~S|hash('sha1', $password);|,
        ~S|hash("md5", $_GET['pass']);|,
        ~S|$h = hash('sha1', $_REQUEST['pwd']);|
      ]
      
      for code <- vulnerable_code do
        assert Regex.match?(pattern.regex, code),
               "Should match: #{code}"
      end
    end
    
    test "does not match secure password hashing", %{pattern: pattern} do
      safe_code = [
        ~S|password_hash($_POST['password'], PASSWORD_BCRYPT);|,
        ~S|password_hash($password, PASSWORD_DEFAULT);|,
        ~S|password_hash($_GET['pass'], PASSWORD_ARGON2I);|,
        ~S|crypt($password, '$2y$10$' . $salt);|,  # Bcrypt prefix
        ~S|hash('sha256', $non_password_data);|,  # Not password
        ~S|md5_file('document.pdf');|  # File hashing, not password
      ]
      
      for code <- safe_code do
        refute Regex.match?(pattern.regex, code),
               "Should not match: #{code}"
      end
    end
  end
  
  describe "test_cases/0" do
    test "all positive cases match" do
      pattern = WeakPasswordHash.pattern()
      test_cases = WeakPasswordHash.test_cases()
      
      for test_case <- test_cases.positive do
        assert Regex.match?(pattern.regex, test_case.code),
               "Failed to match positive case: #{test_case.description}"
      end
    end
    
    test "negative cases are documented correctly" do
      test_cases = WeakPasswordHash.test_cases()
      
      assert length(test_cases.negative) > 0
      
      for test_case <- test_cases.negative do
        assert Map.has_key?(test_case, :code)
        assert Map.has_key?(test_case, :description)
      end
    end
  end
  
  describe "ast_enhancement/0" do
    test "returns proper enhancement rules" do
      enhancement = WeakPasswordHash.ast_enhancement()
      
      assert enhancement.min_confidence >= 0.8
      assert length(enhancement.ast_rules) >= 3
      
      hash_context_rule = Enum.find(enhancement.ast_rules, &(&1.type == "hash_context"))
      assert hash_context_rule
      assert "md5" in hash_context_rule.weak_algorithms
      
      password_indicators_rule = Enum.find(enhancement.ast_rules, &(&1.type == "password_indicators"))
      assert password_indicators_rule
      assert "password" in password_indicators_rule.patterns
    end
  end
  
  describe "pattern metadata" do
    test "has proper OWASP reference" do
      pattern = WeakPasswordHash.pattern()
      assert pattern.owasp_category == "A02:2021"
    end
    
    test "has educational content" do
      desc = WeakPasswordHash.vulnerability_description()
      assert desc =~ "password"
      assert desc =~ "MD5"
      assert desc =~ "bcrypt"
      assert String.downcase(desc) =~ "rainbow table"
    end
    
    test "provides safe alternatives" do
      examples = WeakPasswordHash.examples()
      assert Map.has_key?(examples.fixed, "Using password_hash()")
      assert Map.has_key?(examples.fixed, "Migration from MD5")
    end
  end
end