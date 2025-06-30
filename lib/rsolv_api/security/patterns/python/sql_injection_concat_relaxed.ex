defmodule RsolvApi.Security.Patterns.Python.SqlInjectionConcatRelaxed do
  @moduledoc """
  Relaxed version of SQL injection pattern for testing
  """
  
  use RsolvApi.Security.Patterns.PatternBase
  alias RsolvApi.Security.Pattern
  
  def pattern do
    %Pattern{
      id: "python-sql-injection-concat-relaxed",
      name: "SQL Injection via String Concatenation (Relaxed)",
      description: "Detects SQL query construction using string concatenation with user input",
      type: :sql_injection,
      severity: :critical,
      languages: ["python"],
      regex: ~r/(?:SELECT|INSERT|UPDATE|DELETE|FROM|WHERE|JOIN).*?\+/i,
      cwe_id: "CWE-89",
      owasp_category: "A03:2021",
      recommendation: "Use parameterized queries instead of string concatenation",
      test_cases: %{
        vulnerable: [
          ~S|cursor.execute("SELECT * FROM users WHERE id = " + user_id)|,
          ~S|query = "DELETE FROM posts WHERE author = '" + username + "'"|
        ],
        safe: [
          ~S|cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))|,
          ~S|cursor.execute("SELECT * FROM users WHERE id = ?", [user_id])|
        ]
      }
    }
  end
  
  @impl true
  def ast_enhancement do
    %{
      ast_rules: %{
        node_type: "BinOp",
        op: "Add",
        # Relaxed: Just check if it contains SQL, don't require db call context
        sql_context: %{
          left_or_right_is_string: true,
          contains_sql_pattern: true
          # REMOVED: followed_by_db_call: true
        }
      },
      context_rules: %{
        database_methods: ["execute", "executemany", "executescript"],
        exclude_if_parameterized: true,
        exclude_paths: [~r/test/, ~r/spec/, ~r/__tests__/, ~r/migrations/],
        sql_keywords: ["SELECT", "INSERT", "UPDATE", "DELETE", "FROM", "WHERE", "JOIN", "UNION"]
      },
      confidence_rules: %{
        base: 0.4,  # Lower base since we're more permissive
        adjustments: %{
          "has_sql_keywords" => 0.3,
          "in_database_method_call" => 0.3,  # Bonus if we find db call
          "uses_plus_operator" => 0.1,
          "in_test_code" => -1.0,
          "is_logging_statement" => -0.5
        }
      },
      min_confidence: 0.6  # Lower threshold for testing
    }
  end
end