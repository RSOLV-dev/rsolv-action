defmodule Rsolv.Security.ASTPatternTest do
  use ExUnit.Case, async: true

  alias Rsolv.Security.{Pattern, ASTPattern}

  describe "enhance/1" do
    test "converts a standard pattern to AST-enhanced pattern" do
      standard_pattern = %Pattern{
        id: "js-sql-injection",
        type: :sql_injection,
        name: "SQL Injection",
        description: "Detects SQL injection vulnerabilities",
        severity: :high,
        languages: ["javascript"],
        regex: ~r/SELECT.*FROM/i,
        recommendation: "Use parameterized queries",
        test_cases: %{
          vulnerable: ["db.query('SELECT * FROM users WHERE id = ' + req.params.id)"],
          safe: ["db.query('SELECT * FROM users WHERE id = ?', [req.params.id])"]
        }
      }

      enhanced = ASTPattern.enhance(standard_pattern)

      assert %ASTPattern{} = enhanced
      assert enhanced.id == "js-sql-injection"
      assert enhanced.ast_rules != nil
      assert enhanced.context_rules != nil
      assert enhanced.confidence_rules != nil
      assert enhanced.min_confidence == 0.7
    end

    test "sql injection pattern gets proper AST rules" do
      pattern = %Pattern{
        id: "test-sql",
        name: "Test SQL",
        type: :sql_injection,
        regex: ~r/query/,
        description: "Test pattern",
        severity: :high,
        languages: ["javascript"],
        recommendation: "Use parameterized queries",
        test_cases: %{vulnerable: ["bad"], safe: ["good"]}
      }

      enhanced = ASTPattern.enhance(pattern)

      assert enhanced.ast_rules.parent_node.type == "CallExpression"
      assert enhanced.ast_rules.contains_sql == true
      assert enhanced.ast_rules.has_user_input == true
      assert enhanced.context_rules.exclude_if_parameterized == true
    end

    test "logging pattern gets lower base confidence" do
      pattern = %Pattern{
        id: "test-logging",
        name: "Test Logging",
        type: :logging,
        regex: ~r/login/,
        description: "Test pattern",
        severity: :medium,
        languages: ["javascript"],
        recommendation: "Add logging",
        test_cases: %{vulnerable: ["bad"], safe: ["good"]}
      }

      enhanced = ASTPattern.enhance(pattern)

      assert enhanced.confidence_rules.base == 0.5
      assert enhanced.min_confidence == 0.75
      assert enhanced.ast_rules.node_type == "FunctionDeclaration"
    end

    test "nosql injection pattern checks for dangerous operators" do
      pattern = %Pattern{
        id: "test-nosql",
        name: "Test NoSQL",
        type: :nosql_injection,
        regex: ~r/find/,
        description: "Test pattern",
        severity: :high,
        languages: ["javascript"],
        recommendation: "Sanitize inputs",
        test_cases: %{vulnerable: ["bad"], safe: ["good"]}
      }

      enhanced = ASTPattern.enhance(pattern)

      assert enhanced.ast_rules.argument_contains.dangerous_keys == [
               "$where",
               "$expr",
               "$function"
             ]

      assert enhanced.context_rules.safe_if_uses == ["mongoose.Schema", "sanitize", "validate"]
    end
  end

  describe "get_patterns/3" do
    test "returns standard patterns by default" do
      patterns = ASTPattern.get_patterns("javascript", :public, :standard)

      assert is_list(patterns)
      assert Enum.all?(patterns, &match?(%Pattern{}, &1))
    end

    test "returns enhanced patterns when requested" do
      patterns = ASTPattern.get_patterns("javascript", :public, :enhanced)

      assert is_list(patterns)
      assert Enum.all?(patterns, &match?(%ASTPattern{}, &1))
      # Some patterns have AST rules, others don't yet
      assert Enum.any?(patterns, &(&1.ast_rules != nil))
      # All patterns have context rules
      assert Enum.all?(patterns, &(&1.context_rules != nil))
    end

    test "enhanced patterns have minimum confidence thresholds" do
      patterns = ASTPattern.get_patterns("javascript", :protected, :enhanced)

      assert Enum.all?(patterns, &(&1.min_confidence >= 0.5))
    end
  end

  describe "false positive reduction" do
    test "sql injection pattern excludes test files" do
      pattern = %Pattern{
        id: "test-sql-2",
        name: "Test SQL 2",
        type: :sql_injection,
        regex: ~r/query/,
        description: "Test pattern",
        severity: :high,
        languages: ["javascript"],
        recommendation: "Use parameterized queries",
        test_cases: %{vulnerable: ["bad"], safe: ["good"]}
      }

      enhanced = ASTPattern.enhance(pattern)

      assert Regex.match?(~r/test/, "test/models/user_test.js")

      assert enhanced.context_rules.exclude_paths
             |> Enum.any?(&Regex.match?(&1, "test/models/user_test.js"))
    end

    test "logging pattern has test code adjustment" do
      pattern = %Pattern{
        id: "test-logging-2",
        name: "Test Logging 2",
        type: :logging,
        regex: ~r/login/,
        description: "Test pattern",
        severity: :medium,
        languages: ["javascript"],
        recommendation: "Add logging",
        test_cases: %{vulnerable: ["bad"], safe: ["good"]}
      }

      enhanced = ASTPattern.enhance(pattern)

      assert enhanced.confidence_rules.adjustments["is_test_code"] == -1.0
    end

    test "patterns maintain backward compatibility" do
      pattern = %Pattern{
        id: "test",
        name: "Test Pattern",
        description: "Test description",
        type: :sql_injection,
        regex: ~r/test/,
        severity: :high,
        languages: ["javascript"],
        recommendation: "Fix it",
        test_cases: %{vulnerable: ["bad"], safe: ["good"]}
      }

      enhanced = ASTPattern.enhance(pattern)

      # All original fields preserved
      assert enhanced.id == "test"
      assert enhanced.regex == ~r/test/
      assert enhanced.severity == :high
    end
  end
end
