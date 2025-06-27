defmodule RsolvApi.Security.Patterns.Python.SqlInjectionFormatTest do
  use RsolvApi.DataCase
  alias RsolvApi.Security.Patterns.Python.SqlInjectionFormat
  alias RsolvApi.Security.Pattern

  describe "pattern/0" do
    test "returns correct pattern structure" do
      pattern = SqlInjectionFormat.pattern()
      
      assert %Pattern{} = pattern
      assert pattern.id == "python-sql-injection-format"
      assert pattern.name == "SQL Injection via String Formatting"
      assert pattern.type == :sql_injection
      assert pattern.severity == :high
      assert pattern.languages == ["python"]
      assert pattern.cwe_id == "CWE-89"
      assert pattern.owasp_category == "A03:2021"
    end
  end

  describe "vulnerability detection" do
    test "detects % string formatting in execute calls" do
      pattern = SqlInjectionFormat.pattern()
      
      vulnerable_code = [
        ~S|cursor.execute("SELECT * FROM users WHERE id = %s" % user_id)|,
        ~S|db.execute("DELETE FROM posts WHERE author = '%s'" % username)|,
        ~S|conn.execute("UPDATE accounts SET balance = %s WHERE id = %s" % (amount, account_id))|,
        ~S|cursor.execute("INSERT INTO logs VALUES (%s, %s)" % (time, message))|,
        ~S|db.execute('SELECT * FROM products WHERE name = "%s"' % product_name)|
      ]
      
      for code <- vulnerable_code do
        assert Regex.match?(pattern.regex, code), "Should match vulnerable code: #{code}"
      end
    end

    test "detects % formatting with format string variables" do
      pattern = SqlInjectionFormat.pattern()
      
      vulnerable_code = [
        ~S|query = "SELECT * FROM users WHERE id = %s" % user_id; cursor.execute(query)|,
        ~S|sql = "DELETE FROM posts WHERE id = %d" % post_id; db.execute(sql)|,
        ~S|update_query = "UPDATE users SET name = '%s'" % name; conn.execute(update_query)|
      ]
      
      for code <- vulnerable_code do
        assert Regex.match?(pattern.regex, code), "Should match vulnerable code: #{code}"
      end
    end

    test "ignores safe parameterized queries" do
      pattern = SqlInjectionFormat.pattern()
      
      safe_code = [
        ~S|cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))|,
        ~S|db.execute("DELETE FROM posts WHERE author = %s", [username])|,
        ~S|conn.execute("UPDATE accounts SET balance = %s WHERE id = %s", (amount, account_id))|,
        ~S|cursor.execute("INSERT INTO logs VALUES (%s, %s)", (time, message))|,
        ~S|# Comment: Use %s formatting safely|
      ]
      
      for code <- safe_code do
        refute Regex.match?(pattern.regex, code), "Should NOT match safe code: #{code}"
      end
    end

    test "ignores non-SQL % formatting" do
      pattern = SqlInjectionFormat.pattern()
      
      safe_code = [
        ~S|print("User %s logged in" % username)|,
        ~S|logger.info("Processing %d items" % count)|,
        ~S|message = "Hello %s!" % name|,
        ~S|url = "https://api.example.com/users/%s" % user_id|
      ]
      
      for code <- safe_code do
        refute Regex.match?(pattern.regex, code), "Should NOT match safe code: #{code}"
      end
    end
  end

  describe "vulnerability_metadata/0" do
    test "returns comprehensive vulnerability metadata" do
      metadata = SqlInjectionFormat.vulnerability_metadata()
      
      assert is_map(metadata)
      assert is_binary(metadata.description)
      assert is_list(metadata.references)
      assert length(metadata.references) > 0
      assert is_list(metadata.attack_vectors)
      assert length(metadata.attack_vectors) > 0
      assert is_list(metadata.real_world_impact)
      assert is_list(metadata.cve_examples)
      assert is_binary(metadata.detection_notes)
      assert is_list(metadata.safe_alternatives)
    end

    test "includes relevant CWE and OWASP references" do
      metadata = SqlInjectionFormat.vulnerability_metadata()
      
      cwe_ref = Enum.find(metadata.references, &(&1.type == :cwe))
      assert cwe_ref
      assert cwe_ref.id == "CWE-89"
      
      owasp_ref = Enum.find(metadata.references, &(&1.type == :owasp))
      assert owasp_ref
      assert owasp_ref.id == "A03:2021"
    end
  end

  describe "ast_enhancement/0" do
    test "returns AST enhancement rules" do
      enhancement = SqlInjectionFormat.ast_enhancement()
      
      assert is_map(enhancement)
      assert Map.has_key?(enhancement, :ast_rules)
      assert Map.has_key?(enhancement, :context_rules)
      assert Map.has_key?(enhancement, :confidence_rules)
      assert Map.has_key?(enhancement, :min_confidence)
    end

    test "AST rules target appropriate node types" do
      enhancement = SqlInjectionFormat.ast_enhancement()
      
      assert enhancement.ast_rules.node_type == "BinaryOp"
      assert enhancement.ast_rules.op == "%"
      assert is_map(enhancement.ast_rules.sql_context)
    end

    test "includes database context detection" do
      enhancement = SqlInjectionFormat.ast_enhancement()
      
      assert enhancement.context_rules.database_methods == ["execute", "executemany", "executescript"]
      assert enhancement.context_rules.exclude_if_parameterized == true
    end

    test "confidence scoring reduces false positives" do
      enhancement = SqlInjectionFormat.ast_enhancement()
      
      assert enhancement.min_confidence == 0.7
      assert enhancement.confidence_rules.base == 0.5
      assert enhancement.confidence_rules.adjustments["has_sql_keywords"] == 0.3
      assert enhancement.confidence_rules.adjustments["in_test_code"] == -1.0
    end
  end

  describe "enhanced_pattern/0" do
    test "uses AST enhancement" do
      enhanced = SqlInjectionFormat.enhanced_pattern()
      
      assert enhanced.id == "python-sql-injection-format"
      assert enhanced.ast_rules
      assert enhanced.min_confidence == 0.7
    end
  end

  describe "applies_to_file?/1" do
    test "applies to Python files" do
      assert SqlInjectionFormat.applies_to_file?("app.py")
      assert SqlInjectionFormat.applies_to_file?("models/user.py")
      assert SqlInjectionFormat.applies_to_file?("src/database.py")
      
      refute SqlInjectionFormat.applies_to_file?("app.js")
      refute SqlInjectionFormat.applies_to_file?("config.rb")
      refute SqlInjectionFormat.applies_to_file?("README.md")
    end
  end
end