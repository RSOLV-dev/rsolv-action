defmodule Rsolv.Security.Patterns.Python.SqlInjectionConcatTest do
  use ExUnit.Case
  alias Rsolv.Security.Patterns.Python.SqlInjectionConcat
  alias Rsolv.Security.Pattern

  # Helper functions for cleaner test code
  defp assert_vulnerable(pattern, code_samples) do
    for code <- code_samples do
      assert Regex.match?(pattern.regex, code),
             "Should match vulnerable code: #{code}"
    end
  end

  defp assert_safe(pattern, code_samples) do
    for code <- code_samples do
      refute Regex.match?(pattern.regex, code),
             "Should NOT match safe code: #{code}"
    end
  end

  describe "pattern/0" do
    test "returns correct pattern structure" do
      pattern = SqlInjectionConcat.pattern()

      assert %Pattern{} = pattern
      assert pattern.id == "python-sql-injection-concat"
      assert pattern.name == "SQL Injection via String Concatenation"
      assert pattern.type == :sql_injection
      assert pattern.severity == :high
      assert pattern.languages == ["python"]
      assert pattern.cwe_id == "CWE-89"
      assert pattern.owasp_category == "A03:2021"
    end
  end

  describe "vulnerability detection" do
    setup do
      {:ok, pattern: SqlInjectionConcat.pattern()}
    end

    test "detects string concatenation with + operator in execute calls", %{pattern: pattern} do
      assert_vulnerable(pattern, [
        ~S|cursor.execute("SELECT * FROM users WHERE id = " + user_id)|,
        ~S|db.execute("DELETE FROM posts WHERE author = '" + username + "'")|,
        ~S|conn.execute("UPDATE users SET status = '" + status + "' WHERE id = " + str(id))|,
        ~S|cursor.execute('INSERT INTO logs VALUES (' + log_id + ', "' + message + '")')|,
        ~S|db.execute("SELECT * FROM products WHERE price > " + price)|
      ])
    end

    test "detects concatenation with variable assignment", %{pattern: pattern} do
      assert_vulnerable(pattern, [
        ~S|query = "SELECT * FROM users WHERE id = " + user_id; cursor.execute(query)|,
        ~S|sql = "DELETE FROM posts WHERE author = '" + username + "'"; db.execute(sql)|,
        ~S|update_query = "UPDATE users SET status = '" + status + "'"; conn.execute(update_query)|
      ])
    end

    test "detects multi-line concatenation", %{pattern: pattern} do
      assert_vulnerable(pattern, [
        ~S|query = "SELECT * FROM users WHERE " + "name = '" + name + "' AND " + "age > " + str(age)|,
        ~S|sql = ("DELETE FROM posts " + "WHERE author = '" + author + "'")|
      ])
    end

    test "ignores safe parameterized queries", %{pattern: pattern} do
      assert_safe(pattern, [
        ~S|cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))|,
        ~S|db.execute("DELETE FROM posts WHERE author = ?", [username])|,
        ~S|conn.execute("UPDATE users SET status = :status WHERE id = :id", {"status": status, "id": user_id})|,
        ~S|cursor.execute("INSERT INTO logs VALUES (?, ?)", (log_id, message))|,
        ~S|# String concatenation for non-SQL purposes is fine|
      ])
    end

    test "ignores non-SQL string concatenation", %{pattern: pattern} do
      assert_safe(pattern, [
        ~S|message = "Hello " + username + "!"|,
        ~S|log_entry = timestamp + ": " + event_type|,
        ~S|full_name = first_name + " " + last_name|,
        ~S|url = base_url + "/api/users/" + user_id|
      ])
    end
  end

  describe "vulnerability_metadata/0" do
    test "returns comprehensive vulnerability metadata" do
      metadata = SqlInjectionConcat.vulnerability_metadata()

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
      metadata = SqlInjectionConcat.vulnerability_metadata()

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
      enhancement = SqlInjectionConcat.ast_enhancement()

      assert is_map(enhancement)
      assert Map.has_key?(enhancement, :ast_rules)
      assert Map.has_key?(enhancement, :context_rules)
      assert Map.has_key?(enhancement, :confidence_rules)
      assert Map.has_key?(enhancement, :min_confidence)
    end

    test "AST rules target appropriate node types" do
      enhancement = SqlInjectionConcat.ast_enhancement()

      assert enhancement.ast_rules.node_type == "BinOp"
      assert enhancement.ast_rules.op == "Add"
      assert is_map(enhancement.ast_rules.sql_context)
    end

    test "includes database context detection" do
      enhancement = SqlInjectionConcat.ast_enhancement()

      assert enhancement.context_rules.database_methods == [
               "execute",
               "executemany",
               "executescript"
             ]

      assert enhancement.context_rules.exclude_if_parameterized == true
    end

    test "confidence scoring reduces false positives" do
      enhancement = SqlInjectionConcat.ast_enhancement()

      assert enhancement.min_confidence == 0.4
      assert enhancement.confidence_rules.base == 0.5
      assert enhancement.confidence_rules.adjustments["has_sql_keywords"] == 0.3
      assert enhancement.confidence_rules.adjustments["in_test_code"] == -1.0
    end
  end

  describe "enhanced_pattern/0" do
    test "uses AST enhancement" do
      enhanced = SqlInjectionConcat.enhanced_pattern()

      assert enhanced.id == "python-sql-injection-concat"
      assert enhanced.ast_rules
      assert enhanced.min_confidence == 0.4
    end
  end

  describe "applies_to_file?/1" do
    test "applies to Python files" do
      assert SqlInjectionConcat.applies_to_file?("app.py", nil)
      assert SqlInjectionConcat.applies_to_file?("models/user.py", nil)
      assert SqlInjectionConcat.applies_to_file?("src/database.py", nil)

      refute SqlInjectionConcat.applies_to_file?("app.js", nil)
      refute SqlInjectionConcat.applies_to_file?("config.rb", nil)
      refute SqlInjectionConcat.applies_to_file?("README.md", nil)
    end
  end
end
