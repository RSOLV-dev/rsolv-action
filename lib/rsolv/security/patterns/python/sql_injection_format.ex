defmodule Rsolv.Security.Patterns.Python.SqlInjectionFormat do
  @moduledoc """
  SQL Injection via Python String Formatting

  Detects dangerous patterns like:
    cursor.execute("SELECT * FROM users WHERE id = %s" % user_id)
    db.execute("DELETE FROM posts WHERE author = '%s'" % username)
    query = "UPDATE accounts SET balance = %s" % amount; cursor.execute(query)
    
  Safe alternatives:
    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
    db.execute("DELETE FROM posts WHERE author = %s", [username])
    cursor.execute("UPDATE accounts SET balance = %s", (amount,))
    
  ## Vulnerability Details

  Python's % string formatting operator creates SQL queries by directly inserting
  values into the query string. This bypasses the database driver's escaping
  mechanisms and allows attackers to inject malicious SQL code.

  The vulnerability occurs when:
  1. SQL query strings use % formatting placeholders
  2. User input is passed via the % operator instead of as query parameters
  3. The formatted string is then executed as SQL

  This pattern is particularly dangerous because:
  - It looks similar to safe parameterized queries but isn't
  - Python's % formatting doesn't escape SQL metacharacters
  - Attackers can break out of quoted strings and inject arbitrary SQL
  """

  use Rsolv.Security.Patterns.PatternBase
  alias Rsolv.Security.Pattern

  @doc """
  Returns the SQL injection via string formatting pattern.

  This pattern detects usage of Python's % string formatting in SQL queries
  which can lead to SQL injection vulnerabilities.

  ## Examples

      iex> pattern = Rsolv.Security.Patterns.Python.SqlInjectionFormat.pattern()
      iex> pattern.id
      "python-sql-injection-format"
      
      iex> pattern = Rsolv.Security.Patterns.Python.SqlInjectionFormat.pattern()
      iex> pattern.severity
      :high
      
      iex> pattern = Rsolv.Security.Patterns.Python.SqlInjectionFormat.pattern()
      iex> vulnerable = ~S|cursor.execute("SELECT * FROM users WHERE id = %s" % user_id)|
      iex> Regex.match?(pattern.regex, vulnerable)
      true
      
      iex> pattern = Rsolv.Security.Patterns.Python.SqlInjectionFormat.pattern()
      iex> safe = ~S|cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))|
      iex> Regex.match?(pattern.regex, safe)
      false
  """
  @impl true
  def pattern do
    %Pattern{
      id: "python-sql-injection-format",
      name: "SQL Injection via String Formatting",
      description: "Using % string formatting in SQL queries can lead to SQL injection",
      type: :sql_injection,
      severity: :high,
      languages: ["python"],
      regex: ~r/["'`].*%[sdif].*["'`]\s*%.*execute|execute.*["'`].*%[sdif].*["'`]\s*%/s,
      cwe_id: "CWE-89",
      owasp_category: "A03:2021",
      recommendation:
        "Use parameterized queries with execute() method parameters: cursor.execute(query, (param,))",
      test_cases: %{
        vulnerable: [
          ~S|cursor.execute("SELECT * FROM users WHERE id = %s" % user_id)|,
          ~S|db.execute("DELETE FROM posts WHERE author = '%s'" % username)|,
          ~S|conn.execute("UPDATE accounts SET balance = %s WHERE id = %s" % (amount, account_id))|,
          ~S|cursor.execute("INSERT INTO logs VALUES (%s, %s)" % (time, message))|,
          ~S|db.execute('SELECT * FROM products WHERE name = "%s"' % product_name)|
        ],
        safe: [
          ~S|cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))|,
          ~S|db.execute("DELETE FROM posts WHERE author = %s", [username])|,
          ~S|conn.execute("UPDATE accounts SET balance = %s WHERE id = %s", (amount, account_id))|,
          ~S|cursor.execute("INSERT INTO logs VALUES (%s, %s)", (time, message))|,
          ~S|print("User %s logged in" % username)|
        ]
      }
    }
  end

  @impl true
  def vulnerability_metadata do
    %{
      description: """
      SQL injection vulnerability through Python's % string formatting operator.
      When SQL queries are constructed using % formatting, user input is directly
      interpolated into the query string without proper escaping, allowing attackers
      to inject malicious SQL code.

      This vulnerability is particularly dangerous in Python because:
      - The % operator performs simple string substitution without SQL-aware escaping
      - Single quotes in user input can break out of SQL string literals
      - Attackers can inject UNION queries, boolean conditions, or database commands
      - The pattern looks deceptively similar to safe parameterized queries
      """,
      references: [
        %{
          type: :cwe,
          id: "CWE-89",
          title:
            "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
          url: "https://cwe.mitre.org/data/definitions/89.html"
        },
        %{
          type: :owasp,
          id: "A03:2021",
          title: "OWASP Top 10 2021 - A03 Injection",
          url: "https://owasp.org/Top10/A03_2021-Injection/"
        },
        %{
          type: :research,
          id: "python_sql_injection",
          title: "SQL Injection in Python: Examples and Prevention",
          url: "https://realpython.com/prevent-python-sql-injection/"
        }
      ],
      attack_vectors: [
        "Basic injection: user_id = \"1' OR '1'='1\"",
        "Union-based: username = \"admin' UNION SELECT password FROM users--\"",
        "Boolean-based blind: id = \"1' AND (SELECT COUNT(*) FROM users) > 0--\"",
        "Time-based blind: name = \"test' AND SLEEP(5)--\"",
        "Out-of-band: email = \"'; SELECT load_file('/etc/passwd')--\""
      ],
      real_world_impact: [
        "Complete database compromise and data exfiltration",
        "Authentication bypass and privilege escalation",
        "Data manipulation or deletion",
        "Remote code execution through database functions",
        "Lateral movement to other systems via database links"
      ],
      cve_examples: [
        %{
          id: "CVE-2019-9193",
          description:
            "PostgreSQL driver SQL injection via % formatting in several Python applications",
          severity: "critical",
          cvss: 9.8,
          note: "Multiple applications vulnerable due to unsafe % formatting in SQL queries"
        },
        %{
          id: "CVE-2021-23025",
          description: "SQL injection in Django applications using raw() with % formatting",
          severity: "high",
          cvss: 8.8,
          note: "Affected Django apps using Model.objects.raw() with % string formatting"
        }
      ],
      detection_notes: """
      The pattern specifically looks for:
      1. Database execute methods (execute, executemany, executescript)
      2. SQL query strings containing % format specifiers (%s, %d, %i, %f)
      3. The % operator followed by parentheses containing the parameters

      This distinguishes unsafe formatting from safe parameterized queries where
      parameters are passed as a separate argument to the execute method.
      """,
      safe_alternatives: [
        "Use parameterized queries: cursor.execute(\"SELECT * FROM users WHERE id = %s\", (user_id,))",
        "Use query builders: User.objects.filter(id=user_id)",
        "Use prepared statements with named parameters: cursor.execute(\"SELECT * FROM users WHERE id = :id\", {\"id\": user_id})",
        "For dynamic queries, use a query builder library like SQLAlchemy's core API"
      ],
      additional_context: %{
        common_mistakes: [
          "Assuming % formatting is safe because it looks like parameterized queries",
          "Using string formatting for 'trusted' internal values (which may be derived from user input)",
          "Mixing % formatting with parameterized queries in the same codebase",
          "Using format() or f-strings instead of % (equally vulnerable)"
        ],
        secure_patterns: [
          "Always pass parameters as a separate tuple or list argument",
          "Use database-specific parameter placeholders (? for SQLite, %s for MySQL/PostgreSQL)",
          "Enable query logging in development to verify parameterization",
          "Use ORM query methods instead of raw SQL when possible"
        ]
      }
    }
  end

  @doc """
  Returns AST enhancement rules to reduce false positives.

  This enhancement helps distinguish between actual SQL injection vulnerabilities
  and false positives like logging or non-SQL string formatting.

  ## Examples

      iex> enhancement = Rsolv.Security.Patterns.Python.SqlInjectionFormat.ast_enhancement()
      iex> Map.keys(enhancement) |> Enum.sort()
      [:ast_rules, :confidence_rules, :context_rules, :min_confidence]
      
      iex> enhancement = Rsolv.Security.Patterns.Python.SqlInjectionFormat.ast_enhancement()
      iex> enhancement.min_confidence
      0.7
  """
  @impl true
  def ast_enhancement do
    %{
      ast_rules: %{
        node_type: "BinaryOp",
        op: "%",
        sql_context: %{
          left_operand_contains_sql: true,
          within_db_call: true,
          has_sql_placeholders: true
        }
      },
      context_rules: %{
        database_methods: ["execute", "executemany", "executescript"],
        exclude_if_parameterized: true,
        exclude_paths: [~r/test/, ~r/spec/, ~r/__tests__/],
        sql_keywords: ["SELECT", "INSERT", "UPDATE", "DELETE", "FROM", "WHERE", "JOIN"],
        check_variable_assignment: true
      },
      confidence_rules: %{
        base: 0.5,
        adjustments: %{
          "has_sql_keywords" => 0.3,
          "in_database_method_call" => 0.2,
          "has_user_input_variable" => 0.2,
          "in_test_code" => -1.0,
          "is_logging_statement" => -0.5,
          "safe_parameterized_nearby" => -0.3
        }
      },
      min_confidence: 0.7
    }
  end
end
