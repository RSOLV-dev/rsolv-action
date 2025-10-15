defmodule Rsolv.Security.Patterns.Javascript.SqlInjectionInterpolationTest do
  use ExUnit.Case, async: true

  alias Rsolv.Security.Patterns.Javascript.SqlInjectionInterpolation
  alias Rsolv.Security.Pattern

  doctest SqlInjectionInterpolation

  describe "pattern/0" do
    test "returns a valid pattern struct" do
      pattern = SqlInjectionInterpolation.pattern()

      assert %Pattern{} = pattern
      assert pattern.id == "js-sql-injection-interpolation"
      assert pattern.name == "SQL Injection via String Interpolation"
      assert pattern.type == :sql_injection
      assert pattern.severity == :critical
      assert pattern.languages == ["javascript", "typescript"]
    end

    test "pattern detects vulnerable template literal SQL queries" do
      pattern = SqlInjectionInterpolation.pattern()

      vulnerable_cases = [
        ~S|const query = `SELECT * FROM users WHERE name = '${userName}'`|,
        ~S|db.query(`DELETE FROM posts WHERE id = ${postId}`)|,
        ~S|const sql = `UPDATE users SET email = '${email}' WHERE id = ${id}`|,
        ~S|`INSERT INTO logs (message, user) VALUES ('${msg}', '${user}')`|
      ]

      for code <- vulnerable_cases do
        assert Regex.match?(pattern.regex, code),
               "Failed to match vulnerable code: #{code}"
      end
    end

    test "pattern does not match safe parameterized queries" do
      pattern = SqlInjectionInterpolation.pattern()

      safe_cases = [
        ~S|db.query("SELECT * FROM users WHERE name = ?", [userName])|,
        ~S|const query = db.prepare("DELETE FROM posts WHERE id = ?")|,
        ~S|await db.execute("UPDATE users SET email = ? WHERE id = ?", [email, id])|,
        ~S|const result = await pool.query('SELECT * FROM users WHERE id = $1', [userId])|
      ]

      for code <- safe_cases do
        refute Regex.match?(pattern.regex, code),
               "Incorrectly matched safe code: #{code}"
      end
    end
  end

  describe "vulnerability_metadata/0" do
    test "returns comprehensive vulnerability information" do
      metadata = SqlInjectionInterpolation.vulnerability_metadata()

      assert is_map(metadata)
      assert is_binary(metadata.description)
      assert is_list(metadata.references)
      assert is_list(metadata.attack_vectors)
      assert is_list(metadata.cve_examples)

      # Check references include important sources
      ref_types = Enum.map(metadata.references, & &1.type)
      assert :cwe in ref_types
      assert :owasp in ref_types
    end

    test "metadata includes template literal specific information" do
      metadata = SqlInjectionInterpolation.vulnerability_metadata()

      # Should specifically mention template literals
      assert metadata.description =~ "template literal"

      # Should have attack vectors specific to template literals
      attack_vector_text = Enum.join(metadata.attack_vectors, " ")
      assert attack_vector_text =~ "template" || attack_vector_text =~ "${"
    end
  end

  describe "applies_to_file?/2" do
    test "applies to JavaScript and TypeScript files" do
      assert SqlInjectionInterpolation.applies_to_file?("app.js", nil)
      assert SqlInjectionInterpolation.applies_to_file?("index.ts", nil)
      assert SqlInjectionInterpolation.applies_to_file?("src/database.jsx", nil)
      assert SqlInjectionInterpolation.applies_to_file?("components/User.tsx", nil)
    end

    test "does not apply to non-JavaScript files" do
      refute SqlInjectionInterpolation.applies_to_file?("app.py", nil)
      refute SqlInjectionInterpolation.applies_to_file?("index.rb", nil)
      refute SqlInjectionInterpolation.applies_to_file?("config.json", nil)
    end
  end

  describe "ast_enhancement/0" do
    test "returns comprehensive AST enhancement rules" do
      enhancement = SqlInjectionInterpolation.ast_enhancement()

      assert is_map(enhancement)

      assert Enum.sort(Map.keys(enhancement)) ==
               Enum.sort([:ast_rules, :context_rules, :confidence_rules, :min_confidence])
    end

    test "AST rules target template literals" do
      enhancement = SqlInjectionInterpolation.ast_enhancement()

      assert enhancement.ast_rules.node_type == "TemplateLiteral"
      assert enhancement.ast_rules.has_expressions == true
      assert enhancement.ast_rules.expression_analysis.contains_user_input == true
      assert enhancement.ast_rules.expression_analysis.contains_sql_keywords == true
    end

    test "AST rules check for database context" do
      enhancement = SqlInjectionInterpolation.ast_enhancement()

      assert enhancement.ast_rules.parent_analysis.is_db_query_argument == true

      assert enhancement.ast_rules.parent_analysis.method_name_matches ==
               ~r/\.(query|execute|exec|run)/
    end

    test "context rules exclude test files and safe patterns" do
      enhancement = SqlInjectionInterpolation.ast_enhancement()

      assert Enum.any?(enhancement.context_rules.exclude_paths, &(&1 == ~r/test/))
      assert enhancement.context_rules.exclude_if_parameterized == true
      assert enhancement.context_rules.exclude_if_tagged_template == true
      assert enhancement.context_rules.exclude_if_uses_escaping == true
    end

    test "confidence rules handle safe patterns appropriately" do
      enhancement = SqlInjectionInterpolation.ast_enhancement()

      assert enhancement.confidence_rules.base == 0.3
      assert enhancement.confidence_rules.adjustments["uses_tagged_template"] == -0.8
      assert enhancement.confidence_rules.adjustments["is_logging_only"] == -1.0
      assert enhancement.confidence_rules.adjustments["template_with_user_input"] == 0.4
      assert enhancement.min_confidence == 0.8
    end
  end

  describe "enhanced_pattern/0" do
    test "returns pattern with AST enhancement from ast_enhancement/0" do
      enhanced = SqlInjectionInterpolation.enhanced_pattern()
      enhancement = SqlInjectionInterpolation.ast_enhancement()

      # Verify it has all the AST enhancement fields
      assert enhanced.ast_rules == enhancement.ast_rules
      assert enhanced.context_rules == enhancement.context_rules
      assert enhanced.confidence_rules == enhancement.confidence_rules
      assert enhanced.min_confidence == enhancement.min_confidence

      # And still has all the pattern fields
      assert enhanced.id == "js-sql-injection-interpolation"
      assert enhanced.severity == :critical
    end
  end
end
