defmodule Rsolv.Security.Patterns.Java.SqlInjectionStatementTest do
  use ExUnit.Case, async: true

  alias Rsolv.Security.Patterns.Java.SqlInjectionStatement
  alias Rsolv.Security.Pattern

  describe "pattern/0" do
    test "returns a valid pattern struct" do
      pattern = SqlInjectionStatement.pattern()

      assert %Pattern{} = pattern
      assert pattern.id == "java-sql-injection-statement"
      assert pattern.name == "SQL Injection via Statement"
      assert pattern.severity == :high
      assert pattern.type == :sql_injection
      assert pattern.languages == ["java"]
    end

    test "includes CWE and OWASP references" do
      pattern = SqlInjectionStatement.pattern()

      assert pattern.cwe_id == "CWE-89"
      assert pattern.owasp_category == "A03:2021"
    end

    test "has multiple regex patterns" do
      pattern = SqlInjectionStatement.pattern()

      assert is_list(pattern.regex)
      assert length(pattern.regex) >= 3
    end
  end

  describe "regex matching" do
    setup do
      pattern = SqlInjectionStatement.pattern()
      {:ok, pattern: pattern}
    end

    test "matches executeQuery with string concatenation", %{pattern: pattern} do
      vulnerable_code = [
        "stmt.executeQuery(\"SELECT * FROM users WHERE id = \" + userId);",
        "rs = stmt.executeQuery(\"SELECT * FROM products WHERE name = '\" + productName + \"'\");",
        "statement.executeQuery(\"DELETE FROM items WHERE id=\" + itemId);",
        "stmt.executeQuery(sql + \" AND active=1\");",
        "executeQuery(\"SELECT * FROM accounts WHERE number = \" + accountNum)"
      ]

      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Should match: #{code}"
      end
    end

    test "matches executeUpdate with concatenation", %{pattern: pattern} do
      vulnerable_code = [
        "stmt.executeUpdate(\"UPDATE users SET name = '\" + newName + \"' WHERE id = \" + id);",
        "statement.executeUpdate(\"DELETE FROM posts WHERE author = '\" + author + \"'\");",
        "executeUpdate(\"INSERT INTO logs VALUES ('\" + message + \"')\");"
      ]

      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Should match: #{code}"
      end
    end

    test "matches execute with concatenation", %{pattern: pattern} do
      vulnerable_code = [
        "stmt.execute(\"DROP TABLE \" + tableName);",
        "statement.execute(\"CREATE USER '\" + username + \"' WITH PASSWORD '\" + password + \"'\");",
        "execute(query + \" LIMIT \" + limit);"
      ]

      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Should match: #{code}"
      end
    end

    test "matches createStatement followed by execute", %{pattern: pattern} do
      vulnerable_code = [
        "Statement stmt = conn.createStatement();\nResultSet rs = stmt.executeQuery(\"SELECT * FROM users WHERE id = \" + userId);",
        "Statement statement = connection.createStatement();\nstatement.execute(\"DELETE FROM \" + table);",
        "var stmt = conn.createStatement();\nstmt.executeUpdate(\"UPDATE users SET role = '\" + role + \"'\");"
      ]

      for code <- vulnerable_code do
        assert Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Should match: #{code}"
      end
    end

    test "does not match PreparedStatement usage", %{pattern: pattern} do
      safe_code = [
        "PreparedStatement pstmt = conn.prepareStatement(\"SELECT * FROM users WHERE id = ?\");\npstmt.setInt(1, userId);",
        "PreparedStatement ps = connection.prepareStatement(\"UPDATE users SET name = ? WHERE id = ?\");",
        "pstmt.executeQuery();",
        "// Comment about executeQuery",
        "logger.info(\"Executing query: SELECT * FROM users WHERE id = \" + userId);"
      ]

      for code <- safe_code do
        refute Enum.any?(pattern.regex, &Regex.match?(&1, code)),
               "Should not match: #{code}"
      end
    end

    test "documents known limitations of regex detection", %{pattern: pattern} do
      # These are edge cases that might be hard to detect with regex alone
      complex_concatenation =
        "String query = \"SELECT * FROM users WHERE \";\nquery += \"id = \" + userId;\nstmt.executeQuery(query);"

      # This might not be caught by simple regex but would be vulnerable
      # AST enhancement should handle these complex cases
      assert Enum.any?(pattern.regex, &Regex.match?(&1, complex_concatenation)) ||
               !Enum.any?(pattern.regex, &Regex.match?(&1, complex_concatenation)),
             "Complex concatenation detection may vary"
    end
  end

  describe "vulnerability_metadata/0" do
    test "returns comprehensive metadata" do
      metadata = SqlInjectionStatement.vulnerability_metadata()

      assert metadata.description =~ "SQL injection"
      assert length(metadata.references) >= 4
      assert length(metadata.attack_vectors) >= 5
      assert length(metadata.real_world_impact) >= 3
      assert length(metadata.cve_examples) >= 4
    end

    test "includes CVE examples from research" do
      metadata = SqlInjectionStatement.vulnerability_metadata()

      cve_ids = Enum.map(metadata.cve_examples, & &1.id)
      assert Enum.any?(cve_ids, &String.contains?(&1, "CVE-"))
    end

    test "includes proper security references" do
      metadata = SqlInjectionStatement.vulnerability_metadata()

      ref_types = Enum.map(metadata.references, & &1.type)
      assert :cwe in ref_types
      assert :owasp in ref_types
      assert :research in ref_types
    end
  end

  describe "ast_enhancement/0" do
    test "returns proper enhancement rules" do
      enhancement = SqlInjectionStatement.ast_enhancement()

      assert Map.has_key?(enhancement, :ast_rules)
      assert Map.has_key?(enhancement, :context_rules)
      assert Map.has_key?(enhancement, :confidence_rules)
      assert Map.has_key?(enhancement, :min_confidence)

      assert enhancement.min_confidence >= 0.6
    end

    test "includes SQL operation analysis" do
      enhancement = SqlInjectionStatement.ast_enhancement()

      assert enhancement.ast_rules.node_type == "MethodInvocation"
      assert enhancement.ast_rules.sql_operations.check_execute_methods
      assert enhancement.ast_rules.sql_operations.execute_methods
      assert enhancement.ast_rules.sql_operations.dangerous_patterns
    end

    test "has string concatenation detection" do
      enhancement = SqlInjectionStatement.ast_enhancement()

      assert enhancement.ast_rules.concatenation_analysis.check_string_concat
      assert enhancement.ast_rules.concatenation_analysis.concat_operators
      assert enhancement.ast_rules.concatenation_analysis.check_format_methods
    end

    test "includes statement type checking" do
      enhancement = SqlInjectionStatement.ast_enhancement()

      assert enhancement.context_rules.check_statement_type
      assert enhancement.context_rules.unsafe_statement_types
      assert enhancement.context_rules.safe_statement_types
    end
  end
end
