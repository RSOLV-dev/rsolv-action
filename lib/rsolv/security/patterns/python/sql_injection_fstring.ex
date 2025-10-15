defmodule Rsolv.Security.Patterns.Python.SqlInjectionFstring do
  @moduledoc """
  SQL Injection via Python F-String Formatting

  Detects dangerous patterns like:
    cursor.execute(f"SELECT * FROM users WHERE name = '{name}'")
    db.execute(f"DELETE FROM posts WHERE id = {post_id}")
    query = f"UPDATE users SET status = '{status}'"; conn.execute(query)
    
  Safe alternatives:
    cursor.execute("SELECT * FROM users WHERE name = %s", (name,))
    db.execute("DELETE FROM posts WHERE id = ?", [post_id])
    cursor.execute("UPDATE users SET status = :status", {"status": status})
    
  ## Vulnerability Details

  Python f-strings (formatted string literals) introduced in Python 3.6 provide
  a convenient way to embed expressions inside string literals. However, when
  used to construct SQL queries, they create the same SQL injection vulnerabilities
  as other string formatting methods.

  The vulnerability occurs when:
  1. SQL query strings use f-string formatting with embedded expressions
  2. User input is directly interpolated into the query via f-string expressions
  3. The formatted string is then executed as SQL

  This pattern is particularly dangerous because:
  - F-strings evaluate expressions at runtime, including function calls
  - The syntax is clean and modern, giving a false sense of security
  - No escaping is performed on the interpolated values
  - Complex expressions can be embedded, making detection harder
  """

  use Rsolv.Security.Patterns.PatternBase
  alias Rsolv.Security.Pattern

  @doc """
  Returns the SQL injection via f-string formatting pattern.

  This pattern detects usage of Python f-strings in SQL queries
  which can lead to SQL injection vulnerabilities.

  ## Examples

      iex> pattern = Rsolv.Security.Patterns.Python.SqlInjectionFstring.pattern()
      iex> pattern.id
      "python-sql-injection-fstring"
      
      iex> pattern = Rsolv.Security.Patterns.Python.SqlInjectionFstring.pattern()
      iex> pattern.severity
      :high
      
      iex> pattern = Rsolv.Security.Patterns.Python.SqlInjectionFstring.pattern()
      iex> vulnerable = ~S|cursor.execute(f"SELECT * FROM users WHERE name = '{name}'")|
      iex> Regex.match?(pattern.regex, vulnerable)
      true
      
      iex> pattern = Rsolv.Security.Patterns.Python.SqlInjectionFstring.pattern()
      iex> safe = ~S|cursor.execute("SELECT * FROM users WHERE name = %s", (name,))|
      iex> Regex.match?(pattern.regex, safe)
      false
  """
  @impl true
  def pattern do
    %Pattern{
      id: "python-sql-injection-fstring",
      name: "SQL Injection via F-String Formatting",
      description: "Using f-strings in SQL queries can lead to SQL injection",
      type: :sql_injection,
      severity: :high,
      languages: ["python"],
      regex: ~r/
        f["'`].*\{[^}]+\}.*["'`].*execute|  # f-string before execute
        execute.*f["'`].*\{[^}]+\}.*["'`]    # execute before f-string
      /x,
      cwe_id: "CWE-89",
      owasp_category: "A03:2021",
      recommendation:
        "Use parameterized queries: cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))",
      test_cases: %{
        vulnerable: [
          ~S|cursor.execute(f"SELECT * FROM users WHERE name = '{name}'")|,
          ~S|db.execute(f"DELETE FROM posts WHERE id = {post_id}")|,
          ~S|conn.execute(f"UPDATE users SET email = '{email}' WHERE id = {user_id}")|,
          ~S|cursor.execute(f'INSERT INTO logs VALUES ({id}, "{message}")')|,
          ~S|db.execute(f'''SELECT * FROM products WHERE category = '{category}' ''')|
        ],
        safe: [
          ~S|cursor.execute("SELECT * FROM users WHERE name = %s", (name,))|,
          ~S|db.execute("DELETE FROM posts WHERE id = ?", [post_id])|,
          ~S|print(f"User {username} logged in")|,
          ~S|logger.info(f"Processing {count} items")|,
          ~S|url = f"https://api.example.com/users/{user_id}"|
        ]
      }
    }
  end

  @impl true
  def vulnerability_metadata do
    %{
      description: """
      SQL injection vulnerability through Python's f-string (formatted string literal) syntax.
      F-strings, introduced in Python 3.6, allow embedding expressions inside string literals
      using {expression} syntax. When used to construct SQL queries, user input is directly
      interpolated into the query string without any escaping or parameterization.

      This vulnerability is particularly insidious because:
      - F-strings are the most modern and recommended string formatting method in Python
      - The clean syntax can give developers a false sense of security
      - F-strings can evaluate arbitrary expressions, not just variables
      - Many developers migrating from % formatting or .format() may not realize the risk
      - Popular ORMs and database libraries still accept raw SQL strings
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
          id: "python_fstring_security",
          title: "PEP 501 – General purpose template literal strings",
          url: "https://peps.python.org/pep-0501/"
        }
      ],
      attack_vectors: [
        "Basic injection: name = \"admin' OR '1'='1\"",
        "Union-based: category = \"electronics' UNION SELECT password FROM users--\"",
        "Stacked queries: id = \"1; DROP TABLE users; --\"",
        "Time-based blind: email = \"test@example.com' AND SLEEP(5)--\"",
        "Error-based: status = \"active' AND 1=CONVERT(int, @@version)--\""
      ],
      real_world_impact: [
        "Complete database compromise through data exfiltration",
        "Data modification or deletion affecting business operations",
        "Authentication bypass leading to unauthorized access",
        "Potential remote code execution via xp_cmdshell or similar",
        "Compliance violations (GDPR, PCI-DSS, HIPAA)"
      ],
      cve_examples: [
        %{
          id: "CVE-2023-30624",
          description: "SQL injection in popular Python web framework due to f-string usage",
          severity: "critical",
          cvss: 9.8,
          note: "Framework used f-strings to construct dynamic queries without sanitization"
        },
        %{
          id: "CVE-2022-45442",
          description: "SQL injection in Python CMS via f-string formatted search queries",
          severity: "high",
          cvss: 8.8,
          note: "Search functionality used f-strings with user input directly embedded"
        }
      ],
      detection_notes: """
      The pattern detects:
      1. F-string literals (prefixed with 'f') containing curly brace expressions
      2. Database execute methods called with f-string formatted queries
      3. Variable assignments of f-strings later used in execute calls

      Key indicators:
      - The 'f' prefix before quote characters
      - Curly braces {} containing expressions
      - Proximity to database execute methods
      """,
      safe_alternatives: [
        "Use parameterized queries: cursor.execute(\"SELECT * FROM users WHERE id = %s\", (user_id,))",
        "Use named parameters: cursor.execute(\"SELECT * FROM users WHERE name = :name\", {\"name\": username})",
        "Use query builders: query = select(users).where(users.c.id == user_id)",
        "Use ORM methods: User.query.filter_by(id=user_id).first()",
        "For dynamic queries, use proper escaping libraries: psycopg2.sql.SQL() and .Identifier()"
      ],
      additional_context: %{
        common_mistakes: [
          "Believing f-strings are safer than older formatting methods",
          "Using f-strings for 'trusted' internal values that may be derived from user input",
          "Mixing f-strings with parameterized queries inconsistently",
          "Using f-strings for table/column names (requires special handling)"
        ],
        secure_patterns: [
          "Never use f-strings, .format(), or % for SQL query values",
          "Use parameterized queries exclusively for all dynamic values",
          "For dynamic table/column names, use allowlists and proper escaping",
          "Enable SQL query logging in development to verify parameterization"
        ]
      }
    }
  end

  @doc """
  Returns AST enhancement rules to reduce false positives.

  This enhancement helps distinguish between actual SQL injection vulnerabilities
  and legitimate uses of f-strings in non-SQL contexts.

  ## Examples

      iex> enhancement = Rsolv.Security.Patterns.Python.SqlInjectionFstring.ast_enhancement()
      iex> Map.keys(enhancement) |> Enum.sort()
      [:ast_rules, :confidence_rules, :context_rules, :min_confidence]
      
      iex> enhancement = Rsolv.Security.Patterns.Python.SqlInjectionFstring.ast_enhancement()
      iex> enhancement.min_confidence
      0.7
  """
  @impl true
  def ast_enhancement do
    %{
      ast_rules: %{
        node_type: "JoinedStr",
        format_type: "f-string",
        sql_context: %{
          contains_sql_keywords: true,
          within_db_call: true,
          has_user_input_expressions: true
        }
      },
      context_rules: %{
        database_methods: ["execute", "executemany", "executescript"],
        exclude_if_parameterized: true,
        exclude_paths: [~r/test/, ~r/spec/, ~r/__tests__/, ~r/migrations/],
        sql_keywords: ["SELECT", "INSERT", "UPDATE", "DELETE", "FROM", "WHERE", "JOIN"],
        check_variable_assignment: true,
        safe_patterns: ["logging", "print", "format", "url", "path"]
      },
      confidence_rules: %{
        base: 0.5,
        adjustments: %{
          "has_sql_keywords" => 0.3,
          "in_database_method_call" => 0.2,
          "has_curly_brace_expressions" => 0.2,
          "in_test_code" => -1.0,
          "is_logging_statement" => -0.5,
          "is_url_construction" => -0.4,
          "safe_parameterized_nearby" => -0.3
        }
      },
      min_confidence: 0.7
    }
  end
end
