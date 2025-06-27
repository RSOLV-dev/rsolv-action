defmodule RsolvApi.Security.Patterns.Python.SqlInjectionFstringTest do
  use RsolvApi.DataCase
  alias RsolvApi.Security.Patterns.Python.SqlInjectionFstring
  alias RsolvApi.Security.Pattern

  describe "pattern/0" do
    test "returns correct pattern structure" do
      pattern = SqlInjectionFstring.pattern()
      
      assert %Pattern{} = pattern
      assert pattern.id == "python-sql-injection-fstring"
      assert pattern.name == "SQL Injection via F-String Formatting"
      assert pattern.type == :sql_injection
      assert pattern.severity == :high
      assert pattern.languages == ["python"]
      assert pattern.cwe_id == "CWE-89"
      assert pattern.owasp_category == "A03:2021"
    end
  end

  describe "vulnerability detection" do
    setup do
      {:ok, pattern: SqlInjectionFstring.pattern()}
    end

    test "detects f-string formatting in execute calls", %{pattern: pattern} do
      vulnerable_code = [
        ~S|cursor.execute(f"SELECT * FROM users WHERE name = '{name}'")|,
        ~S|db.execute(f"DELETE FROM posts WHERE id = {post_id}")|,
        ~S|conn.execute(f"UPDATE users SET email = '{email}' WHERE id = {user_id}")|,
        ~S|cursor.execute(f'INSERT INTO logs VALUES ({id}, "{message}")')|,
        ~S|db.execute(f'''SELECT * FROM products WHERE category = '{category}' ''')|
      ]
      
      for code <- vulnerable_code do
        assert Regex.match?(pattern.regex, code), "Should match vulnerable code: #{code}"
      end
    end

    test "detects f-string formatting with format string variables", %{pattern: pattern} do
      vulnerable_code = [
        ~S|query = f"SELECT * FROM users WHERE id = {user_id}"; cursor.execute(query)|,
        ~S|sql = f"DELETE FROM posts WHERE author = '{author}'"; db.execute(sql)|,
        ~S|update_query = f"UPDATE users SET status = '{status}'"; conn.execute(update_query)|
      ]
      
      for code <- vulnerable_code do
        assert Regex.match?(pattern.regex, code), "Should match vulnerable code: #{code}"
      end
    end

    test "ignores safe parameterized queries", %{pattern: pattern} do
      safe_code = [
        ~S|cursor.execute("SELECT * FROM users WHERE name = %s", (name,))|,
        ~S|db.execute("DELETE FROM posts WHERE id = ?", [post_id])|,
        ~S|conn.execute("UPDATE users SET email = :email WHERE id = :id", {"email": email, "id": user_id})|,
        ~S|cursor.execute("INSERT INTO logs VALUES (?, ?)", (id, message))|,
        ~S|# Use f-strings for logging, not SQL|
      ]
      
      for code <- safe_code do
        refute Regex.match?(pattern.regex, code), "Should NOT match safe code: #{code}"
      end
    end

    test "ignores non-SQL f-string usage", %{pattern: pattern} do
      safe_code = [
        ~S|print(f"User {username} logged in")|,
        ~S|logger.info(f"Processing {count} items")|,
        ~S|message = f"Hello {name}!"|,
        ~S|url = f"https://api.example.com/users/{user_id}"|
      ]
      
      for code <- safe_code do
        refute Regex.match?(pattern.regex, code), "Should NOT match safe code: #{code}"
      end
    end
  end

  describe "vulnerability_metadata/0" do
    test "returns comprehensive vulnerability metadata" do
      metadata = SqlInjectionFstring.vulnerability_metadata()
      
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
      metadata = SqlInjectionFstring.vulnerability_metadata()
      
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
      enhancement = SqlInjectionFstring.ast_enhancement()
      
      assert is_map(enhancement)
      assert Map.has_key?(enhancement, :ast_rules)
      assert Map.has_key?(enhancement, :context_rules)
      assert Map.has_key?(enhancement, :confidence_rules)
      assert Map.has_key?(enhancement, :min_confidence)
    end

    test "AST rules target appropriate node types" do
      enhancement = SqlInjectionFstring.ast_enhancement()
      
      assert enhancement.ast_rules.node_type == "JoinedStr"
      assert enhancement.ast_rules.format_type == "f-string"
      assert is_map(enhancement.ast_rules.sql_context)
    end

    test "includes database context detection" do
      enhancement = SqlInjectionFstring.ast_enhancement()
      
      assert enhancement.context_rules.database_methods == ["execute", "executemany", "executescript"]
      assert enhancement.context_rules.exclude_if_parameterized == true
    end

    test "confidence scoring reduces false positives" do
      enhancement = SqlInjectionFstring.ast_enhancement()
      
      assert enhancement.min_confidence == 0.7
      assert enhancement.confidence_rules.base == 0.5
      assert enhancement.confidence_rules.adjustments["has_sql_keywords"] == 0.3
      assert enhancement.confidence_rules.adjustments["in_test_code"] == -1.0
    end
  end

  describe "enhanced_pattern/0" do
    test "uses AST enhancement" do
      enhanced = SqlInjectionFstring.enhanced_pattern()
      
      assert enhanced.id == "python-sql-injection-fstring"
      assert enhanced.ast_rules
      assert enhanced.min_confidence == 0.7
    end
  end

  describe "applies_to_file?/1" do
    test "applies to Python files" do
      assert SqlInjectionFstring.applies_to_file?("app.py")
      assert SqlInjectionFstring.applies_to_file?("models/user.py")
      assert SqlInjectionFstring.applies_to_file?("src/database.py")
      
      refute SqlInjectionFstring.applies_to_file?("app.js")
      refute SqlInjectionFstring.applies_to_file?("config.rb")
      refute SqlInjectionFstring.applies_to_file?("README.md")
    end
  end
end