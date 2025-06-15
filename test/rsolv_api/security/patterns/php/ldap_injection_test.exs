defmodule RsolvApi.Security.Patterns.Php.LdapInjectionTest do
  use ExUnit.Case, async: true
  
  alias RsolvApi.Security.Patterns.Php.LdapInjection
  alias RsolvApi.Security.Pattern
  
  describe "pattern/0" do
    test "returns a valid pattern struct" do
      pattern = LdapInjection.pattern()
      
      assert %Pattern{} = pattern
      assert pattern.id == "php-ldap-injection"
      assert pattern.name == "LDAP Injection"
      assert pattern.severity == :high
      assert pattern.type == :ldap_injection
      assert pattern.languages == ["php"]
    end
    
    test "includes CWE and OWASP references" do
      pattern = LdapInjection.pattern()
      
      assert pattern.cwe_id == "CWE-90"
      assert pattern.owasp_category == "A03:2021"
    end
  end
  
  describe "regex matching" do
    setup do
      pattern = LdapInjection.pattern()
      {:ok, pattern: pattern}
    end
    
    test "matches ldap_search with direct user input", %{pattern: pattern} do
      vulnerable_code = [
        ~S|ldap_search($ds, $dn, "(uid=$_GET[username])");|,
        ~S|ldap_search($conn, $base, "(cn=$_POST[name])");|,
        ~S|ldap_search($link, $basedn, "(mail=$_REQUEST[email])");|,
        ~S|ldap_search($ldap, $dn, "(sn=$_COOKIE[surname])");|
      ]
      
      for code <- vulnerable_code do
        assert Regex.match?(pattern.regex, code),
               "Should match: #{code}"
      end
    end
    
    test "matches ldap_list with user input", %{pattern: pattern} do
      vulnerable_code = [
        ~S|ldap_list($ds, $dn, "(uid=$_GET[id])");|,
        ~S|ldap_list($conn, $base, "(cn=$_POST[search])");|,
        ~S|ldap_list($link, $basedn, "(cn=$_GET[name])");|
      ]
      
      for code <- vulnerable_code do
        assert Regex.match?(pattern.regex, code),
               "Should match: #{code}"
      end
    end
    
    test "matches ldap_read with user input", %{pattern: pattern} do
      vulnerable_code = [
        ~S|ldap_read($ds, $dn, "(uid=$_GET[user])");|,
        ~S|ldap_read($conn, $base, "(cn=$_POST[username])");|,
        ~S|ldap_read($link, $basedn, "(mail=$_REQUEST[email])");|
      ]
      
      for code <- vulnerable_code do
        assert Regex.match?(pattern.regex, code),
               "Should match: #{code}"
      end
    end
    
    test "matches various LDAP filter constructions", %{pattern: pattern} do
      vulnerable_code = [
        ~S|ldap_search($ds, $dn, "(cn=$_GET[name])");|,
        ~S|ldap_search($ds, $dn, "(uid=$_POST[id])");|,
        ~S|ldap_search($ds, $dn, "(!(cn=$_GET[exclude]))");|,
        ~S|ldap_list($ds, $dn, "(department=$_REQUEST[dept])");|
      ]
      
      for code <- vulnerable_code do
        assert Regex.match?(pattern.regex, code),
               "Should match: #{code}"
      end
    end
    
    test "matches various spacing and formatting", %{pattern: pattern} do
      vulnerable_code = [
        ~S|ldap_search( $ds, $dn, "(uid=$_GET[username])" );|,
        ~S|ldap_search($ds,$dn,"(cn=$_POST[name])");|,
        ~S|ldap_list($ds, $dn, "(mail=" . $_GET['email'] . ")");|,
        ~S|ldap_read($conn, $base, "(sn=" . $_REQUEST['surname'] . ")");|
      ]
      
      for code <- vulnerable_code do
        assert Regex.match?(pattern.regex, code),
               "Should match: #{code}"
      end
    end
    
    test "does not match safe operations", %{pattern: pattern} do
      safe_code = [
        ~S|ldap_search($ds, $dn, "(uid=safe_value)");|,
        ~S|ldap_search($ds, $dn, $safe_filter);|,
        ~S|ldap_bind($ds, $username, $password);|,
        ~S|ldap_connect('ldap://example.com');|,
        ~S|echo "LDAP search: " . $_GET['query'];|,
        ~S|ldap_search($ds, $dn, "(cn=hardcoded)");|
      ]
      
      for code <- safe_code do
        refute Regex.match?(pattern.regex, code),
               "Should not match: #{code}"
      end
    end
    
    test "matches real-world vulnerable patterns", %{pattern: pattern} do
      vulnerable_code = [
        ~S|ldap_search($ldap_conn, "ou=users,dc=example,dc=com", "(cn=$_GET[search_term])");|,
        ~S|ldap_search($ds, $dn, "(uid=$_POST[query])");|,
        ~S|ldap_read($conn, $base, "(mail=$_REQUEST[user_email])");|
      ]
      
      for code <- vulnerable_code do
        assert Regex.match?(pattern.regex, code),
               "Should match: #{code}"
      end
    end
  end
  
  describe "test_cases/0" do
    test "all positive cases match" do
      pattern = LdapInjection.pattern()
      test_cases = LdapInjection.test_cases()
      
      for test_case <- test_cases.positive do
        assert Regex.match?(pattern.regex, test_case.code),
               "Failed to match positive case: #{test_case.description}"
      end
    end
    
    test "negative cases are documented correctly" do
      test_cases = LdapInjection.test_cases()
      
      assert length(test_cases.negative) > 0
      
      for test_case <- test_cases.negative do
        assert Map.has_key?(test_case, :code)
        assert Map.has_key?(test_case, :description)
      end
    end
  end
  
  describe "ast_enhancement/0" do
    test "returns proper enhancement rules" do
      enhancement = LdapInjection.ast_enhancement()
      
      assert enhancement.min_confidence >= 0.7
      assert length(enhancement.rules) >= 3
      
      ldap_functions_rule = Enum.find(enhancement.rules, &(&1.type == "ldap_functions"))
      assert ldap_functions_rule
      assert "ldap_search" in ldap_functions_rule.functions
      assert "ldap_list" in ldap_functions_rule.functions
      assert "ldap_read" in ldap_functions_rule.functions
      
      user_input_rule = Enum.find(enhancement.rules, &(&1.type == "user_input_analysis"))
      assert user_input_rule
      assert "$_GET" in user_input_rule.dangerous_sources
      assert "$_POST" in user_input_rule.dangerous_sources
    end
  end
  
  describe "pattern metadata" do
    test "has proper OWASP reference" do
      pattern = LdapInjection.pattern()
      assert pattern.owasp_category == "A03:2021"
    end
    
    test "has educational content" do
      desc = LdapInjection.vulnerability_description()
      assert desc =~ "LDAP injection"
      assert desc =~ "ldap_escape"
      assert desc =~ "filter"
    end
    
    test "provides safe alternatives" do
      examples = LdapInjection.examples()
      assert Map.has_key?(examples.fixed, "Escaped filter")
      assert Map.has_key?(examples.fixed, "Parameterized query")
    end
  end
end