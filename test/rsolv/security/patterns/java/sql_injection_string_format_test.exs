defmodule Rsolv.Security.Patterns.Java.SqlInjectionStringFormatTest do
  use ExUnit.Case, async: true
  
  alias Rsolv.Security.Patterns.Java.SqlInjectionStringFormat
  alias Rsolv.Security.Pattern
  
  describe "pattern/0" do
    test "returns a valid pattern struct" do
      pattern = SqlInjectionStringFormat.pattern()
      
      assert %Pattern{} = pattern
      assert pattern.id == "java-sql-injection-string-format"
      assert pattern.name == "SQL Injection via String.format"
      assert pattern.severity == :high
      assert pattern.type == :sql_injection
      assert pattern.languages == ["java"]
    end
    
    test "includes CWE and OWASP references" do
      pattern = SqlInjectionStringFormat.pattern()
      
      assert pattern.cwe_id == "CWE-89"
      assert pattern.owasp_category == "A03:2021"
    end
    
    test "has multiple regex patterns" do
      pattern = SqlInjectionStringFormat.pattern()
      
      assert is_list(pattern.regex)
      assert length(pattern.regex) >= 4
    end
  end
  
  describe "regex matching" do
    setup do
      pattern = SqlInjectionStringFormat.pattern()
      {:ok, pattern: pattern}
    end
    
    test "matches String.format with %s in SQL", %{pattern: pattern} do
      vulnerable_code = [
        ~S|executeQuery(String.format("SELECT * FROM users WHERE id = %s", userId))|,
        ~S|stmt.executeQuery(String.format("SELECT * FROM products WHERE name = '%s'", productName))|,
        ~S|rs = statement.executeQuery(String.format("DELETE FROM posts WHERE author = '%s'", author))|,
        ~S|connection.executeQuery(String.format("SELECT * FROM accounts WHERE number = %s", accountNum))|
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Should match: #{code}"
      end
    end
    
    test "matches String.format with %d in SQL", %{pattern: pattern} do
      vulnerable_code = [
        ~S|executeUpdate(String.format("UPDATE users SET age = %d WHERE id = %s", age, userId))|,
        ~S|stmt.execute(String.format("DELETE FROM records WHERE count > %d", threshold))|,
        ~S|prepareStatement(String.format("INSERT INTO logs VALUES (%d, '%s')", id, message))|
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Should match: #{code}"
      end
    end
    
    test "matches String.format in Connection/Statement methods", %{pattern: pattern} do
      vulnerable_code = [
        ~S|conn.prepareStatement(String.format("SELECT * FROM users WHERE email = '%s'", email))|,
        ~S|connection.createStatement().execute(String.format("DROP TABLE %s", tableName))|,
        ~S|jdbcTemplate.query(String.format("SELECT * FROM %s WHERE active = true", table))|
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Should match: #{code}"
      end
    end
    
    test "matches queries built with String.format", %{pattern: pattern} do
      vulnerable_code = [
        ~S|String query = String.format("SELECT * FROM users WHERE role = '%s'", role);
stmt.executeQuery(query);|,
        ~S|String sql = String.format("UPDATE accounts SET balance = %f WHERE id = %s", balance, id);
connection.execute(sql);|
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Should match: #{code}"
      end
    end
    
    test "does not match safe parameterized queries", %{pattern: pattern} do
      safe_code = [
        ~S|PreparedStatement pstmt = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
pstmt.setString(1, userId);|,
        ~S|String.format("User %s logged in at %s", username, timestamp)|,
        ~S|logger.info(String.format("Processing %d records", count))|,
        ~S|return String.format("Hello, %s!", name)|,
        ~S|// Comment about String.format usage|
      ]
      
      for code <- safe_code do
        refute Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Should not match: #{code}"
      end
    end
    
    test "matches MessageFormat.format SQL patterns", %{pattern: pattern} do
      vulnerable_code = [
        ~S|executeQuery(MessageFormat.format("SELECT * FROM users WHERE id = {0}", userId))|,
        ~S|stmt.execute(MessageFormat.format("DELETE FROM {0} WHERE id = {1}", table, id))|
      ]
      
      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Should match: #{code}"
      end
    end
  end
  
  describe "vulnerability_metadata/0" do
    test "returns comprehensive metadata" do
      metadata = SqlInjectionStringFormat.vulnerability_metadata()
      
      assert metadata.description =~ "String.format"
      assert length(metadata.references) >= 4
      assert length(metadata.attack_vectors) >= 5
      assert length(metadata.real_world_impact) >= 3
      assert length(metadata.cve_examples) >= 3
    end
    
    test "includes CVE examples from research" do
      metadata = SqlInjectionStringFormat.vulnerability_metadata()
      
      cve_ids = Enum.map(metadata.cve_examples, & &1.id)
      assert Enum.any?(cve_ids, &String.contains?(&1, "CVE-"))
    end
    
    test "includes proper security references" do
      metadata = SqlInjectionStringFormat.vulnerability_metadata()
      
      ref_types = Enum.map(metadata.references, & &1.type)
      assert :cwe in ref_types
      assert :owasp in ref_types
      assert :research in ref_types
    end
  end
  
  describe "ast_enhancement/0" do
    test "returns proper enhancement rules" do
      enhancement = SqlInjectionStringFormat.ast_enhancement()
      
      assert Map.has_key?(enhancement, :ast_rules)
      assert Map.has_key?(enhancement, :context_rules)
      assert Map.has_key?(enhancement, :confidence_rules)
      assert Map.has_key?(enhancement, :min_confidence)
      
      assert enhancement.min_confidence >= 0.6
    end
    
    test "includes format method analysis" do
      enhancement = SqlInjectionStringFormat.ast_enhancement()
      
      assert enhancement.ast_rules.node_type == "MethodInvocation"
      assert enhancement.ast_rules.format_analysis.check_format_methods
      assert enhancement.ast_rules.format_analysis.format_methods
      assert enhancement.ast_rules.format_analysis.check_format_specifiers
    end
    
    test "has SQL context detection" do
      enhancement = SqlInjectionStringFormat.ast_enhancement()
      
      assert enhancement.ast_rules.sql_context.check_parent_call
      assert enhancement.ast_rules.sql_context.sql_methods
      assert enhancement.ast_rules.sql_context.check_variable_usage
    end
    
    test "includes argument analysis" do
      enhancement = SqlInjectionStringFormat.ast_enhancement()
      
      assert enhancement.context_rules.check_format_arguments
      assert enhancement.context_rules.safe_format_types
      assert enhancement.context_rules.unsafe_format_types
    end
  end
end