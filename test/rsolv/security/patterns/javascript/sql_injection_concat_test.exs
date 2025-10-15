defmodule Rsolv.Security.Patterns.Javascript.SqlInjectionConcatTest do
  use ExUnit.Case, async: true
  alias Rsolv.Security.Pattern
  alias Rsolv.Security.Patterns.Javascript.SqlInjectionConcat

  doctest SqlInjectionConcat

  describe "pattern/0" do
    test "returns correct pattern structure" do
      pattern = SqlInjectionConcat.pattern()

      assert %Pattern{} = pattern
      assert pattern.id == "js-sql-injection-concat"
      assert pattern.name == "SQL Injection via String Concatenation"
      assert pattern.type == :sql_injection
      assert pattern.severity == :critical
      assert pattern.languages == ["javascript", "typescript"]
      assert pattern.cwe_id == "CWE-89"
      assert pattern.owasp_category == "A03:2021"
    end

    test "pattern has required metadata" do
      pattern = SqlInjectionConcat.pattern()

      assert pattern.description =~ "SQL query"
      assert pattern.recommendation =~ "parameterized"
      assert is_map(pattern.test_cases)
      assert is_list(pattern.test_cases.vulnerable)
      assert is_list(pattern.test_cases.safe)
    end
  end

  describe "vulnerability_metadata/0" do
    test "returns comprehensive vulnerability metadata" do
      metadata = SqlInjectionConcat.vulnerability_metadata()

      assert is_map(metadata)
      assert is_binary(metadata.description)
      assert is_list(metadata.references)
      assert is_list(metadata.attack_vectors)
      assert is_list(metadata.real_world_impact)
      assert is_list(metadata.cve_examples)
    end

    test "metadata includes required reference types" do
      metadata = SqlInjectionConcat.vulnerability_metadata()
      references = metadata.references

      assert Enum.any?(references, &(&1.type == :cwe))
      assert Enum.any?(references, &(&1.type == :owasp))
    end

    test "metadata includes real CVE examples" do
      metadata = SqlInjectionConcat.vulnerability_metadata()

      assert length(metadata.cve_examples) >= 2

      for cve <- metadata.cve_examples do
        assert cve.id =~ ~r/^CVE-\d{4}-\d+$/
        assert is_binary(cve.description)
        assert cve.severity in ["critical", "high", "medium", "low"]
        assert is_float(cve.cvss) or is_integer(cve.cvss)
      end
    end
  end

  describe "detection tests" do
    test "detects SQL injection via string concatenation" do
      pattern = SqlInjectionConcat.pattern()

      vulnerable_codes = [
        ~S|db.query("SELECT * FROM users WHERE id = " + req.params.id)|,
        ~S|const sql = "SELECT * FROM users WHERE name = '" + userName + "'"|,
        ~S|connection.execute("DELETE FROM posts WHERE id = " + postId)|
      ]

      for code <- vulnerable_codes do
        assert Regex.match?(pattern.regex, code), "Should detect: #{code}"
      end
    end

    test "detects concatenation with various SQL keywords" do
      pattern = SqlInjectionConcat.pattern()

      vulnerable_codes = [
        ~S|"INSERT INTO logs VALUES ('" + userInput + "')")|,
        ~S|"UPDATE users SET name = '" + name + "' WHERE id = " + id|,
        ~S|"DELETE FROM sessions WHERE token = '" + token + "'"|
      ]

      for code <- vulnerable_codes do
        assert Regex.match?(pattern.regex, code), "Should detect: #{code}"
      end
    end
  end

  describe "safe code validation" do
    test "does not match parameterized queries" do
      pattern = SqlInjectionConcat.pattern()

      safe_codes = [
        ~S|db.query("SELECT * FROM users WHERE id = ?", [req.params.id])|,
        ~S|db.query("SELECT * FROM users WHERE id = $1", [userId])|,
        ~S|const stmt = db.prepare("SELECT * FROM users WHERE name = ?")|
      ]

      for code <- safe_codes do
        refute Regex.match?(pattern.regex, code), "Should not match: #{code}"
      end
    end
  end

  describe "ast_enhancement/0" do
    test "returns comprehensive AST enhancement rules" do
      enhancement = SqlInjectionConcat.ast_enhancement()

      assert is_map(enhancement)

      assert Enum.sort(Map.keys(enhancement)) ==
               Enum.sort([:ast_rules, :context_rules, :confidence_rules, :min_confidence])
    end

    test "AST rules target binary expressions with concatenation" do
      enhancement = SqlInjectionConcat.ast_enhancement()

      assert enhancement.ast_rules.node_type == "BinaryExpression"
      assert enhancement.ast_rules.operator == "+"
      assert enhancement.ast_rules.context_analysis.contains_sql_keywords == true
      assert enhancement.ast_rules.context_analysis.has_user_input_in_concatenation == true
      # Note: within_db_call was removed as it's now optional for confidence boost
    end

    test "AST rules no longer require ancestor checks" do
      enhancement = SqlInjectionConcat.ast_enhancement()

      # Ancestor requirements were removed as pattern matcher can't effectively
      # track context across multiple statements in current implementation
      refute Map.has_key?(enhancement.ast_rules, :ancestor_requirements)
    end

    test "context rules exclude test files and parameterized queries" do
      enhancement = SqlInjectionConcat.ast_enhancement()

      assert Enum.any?(enhancement.context_rules.exclude_paths, &(&1 == ~r/test/))
      assert enhancement.context_rules.exclude_if_parameterized == true
      assert enhancement.context_rules.exclude_if_uses_orm_builder == true
      assert enhancement.context_rules.exclude_if_logging_only == true
    end

    test "confidence rules heavily penalize parameterized queries and logging" do
      enhancement = SqlInjectionConcat.ast_enhancement()

      assert enhancement.confidence_rules.base == 0.4
      assert enhancement.confidence_rules.adjustments["uses_parameterized_query"] == -0.9
      assert enhancement.confidence_rules.adjustments["is_console_log"] == -1.0
      assert enhancement.confidence_rules.adjustments["direct_req_param_concat"] == 0.4
      assert enhancement.min_confidence == 0.7
    end
  end

  describe "enhanced_pattern/0" do
    test "returns pattern with AST enhancement from ast_enhancement/0" do
      enhanced = SqlInjectionConcat.enhanced_pattern()
      enhancement = SqlInjectionConcat.ast_enhancement()

      # Verify it has all the AST enhancement fields
      assert enhanced.ast_rules == enhancement.ast_rules
      assert enhanced.context_rules == enhancement.context_rules
      assert enhanced.confidence_rules == enhancement.confidence_rules
      assert enhanced.min_confidence == enhancement.min_confidence

      # And still has all the pattern fields
      assert enhanced.id == "js-sql-injection-concat"
      assert enhanced.severity == :critical
    end
  end

  describe "applies_to_file?/2" do
    test "applies to JavaScript files" do
      assert SqlInjectionConcat.applies_to_file?("app.js", nil)
      assert SqlInjectionConcat.applies_to_file?("database/queries.js", nil)
      assert SqlInjectionConcat.applies_to_file?("server.mjs", nil)
    end

    test "applies to TypeScript files" do
      assert SqlInjectionConcat.applies_to_file?("app.ts", nil)
      assert SqlInjectionConcat.applies_to_file?("database/queries.tsx", nil)
      assert SqlInjectionConcat.applies_to_file?("server.ts", nil)
    end

    test "does not apply to files with different extension even with SQL content" do
      # Current behavior: Pattern only matches JS/TS files, not other file types with SQL
      # This is because language check happens before embedded content check
      sql_content = "SELECT * FROM users WHERE id = "
      refute SqlInjectionConcat.applies_to_file?("template.ejs", sql_content)
      refute SqlInjectionConcat.applies_to_file?("query.php", sql_content)
    end

    test "does not apply to non-JS/TS files without SQL" do
      refute SqlInjectionConcat.applies_to_file?("README.md", nil)
      refute SqlInjectionConcat.applies_to_file?("styles.css", nil)
    end
  end
end
