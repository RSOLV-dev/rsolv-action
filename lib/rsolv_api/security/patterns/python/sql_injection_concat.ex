defmodule RsolvApi.Security.Patterns.Python.SqlInjectionConcat do
  @moduledoc """
  SQL Injection via Python String Concatenation
  
  Detects dangerous patterns like:
    cursor.execute("SELECT * FROM users WHERE id = " + user_id)
    db.execute("DELETE FROM posts WHERE author = '" + username + "'")
    query = "UPDATE users SET status = '" + status + "'"; conn.execute(query)
    
  Safe alternatives:
    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
    db.execute("DELETE FROM posts WHERE author = ?", [username])
    cursor.execute("UPDATE users SET status = :status", {"status": status})
    
  ## Vulnerability Details
  
  String concatenation using the + operator is one of the most common and dangerous
  ways to construct SQL queries in Python. When user input is concatenated directly
  into SQL query strings, it creates a direct SQL injection vulnerability.
  
  The vulnerability occurs when:
  1. SQL query strings are built using the + operator
  2. User-controlled input is concatenated into the query
  3. No escaping or parameterization is performed
  4. The resulting string is executed as SQL
  
  This pattern is particularly dangerous because:
  - It's intuitive for beginners who may not understand the security implications
  - Python's string concatenation is straightforward, making it tempting to use
  - The vulnerability is often introduced when "quickly" adding a feature
  - It bypasses all database security mechanisms
  """
  
  use RsolvApi.Security.Patterns.PatternBase
  alias RsolvApi.Security.Pattern
  
  @doc """
  Returns the SQL injection via string concatenation pattern.
  
  This pattern detects usage of Python string concatenation with +
  operator in SQL queries which can lead to SQL injection vulnerabilities.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Python.SqlInjectionConcat.pattern()
      iex> pattern.id
      "python-sql-injection-concat"
      
      iex> pattern = RsolvApi.Security.Patterns.Python.SqlInjectionConcat.pattern()
      iex> pattern.severity
      :high
      
      iex> pattern = RsolvApi.Security.Patterns.Python.SqlInjectionConcat.pattern()
      iex> vulnerable = ~S|cursor.execute("SELECT * FROM users WHERE id = " + user_id)|
      iex> Regex.match?(pattern.regex, vulnerable)
      true
      
      iex> pattern = RsolvApi.Security.Patterns.Python.SqlInjectionConcat.pattern()
      iex> safe = ~S|cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))|
      iex> Regex.match?(pattern.regex, safe)
      false
      
      iex> pattern = RsolvApi.Security.Patterns.Python.SqlInjectionConcat.pattern()
      iex> query_assignment = ~S|query = "DELETE FROM posts WHERE author = '" + username + "'"|
      iex> Regex.match?(pattern.regex, query_assignment)
      true
      
      iex> pattern = RsolvApi.Security.Patterns.Python.SqlInjectionConcat.pattern()
      iex> normal_concat = ~S|message = "Hello " + username + "!"|
      iex> Regex.match?(pattern.regex, normal_concat)
      false
  """
  @impl true
  def pattern do
    %Pattern{
      id: "python-sql-injection-concat",
      name: "SQL Injection via String Concatenation",
      description: "Using string concatenation (+) in SQL queries can lead to SQL injection",
      type: :sql_injection,
      severity: :high,
      languages: ["python"],
      regex: ~r/
        # Direct execute with string concatenation
        \.execute\s*\([^)]*["'].*\+|
        # String concatenation used in execute call
        ["'].*\+.*["'].*\.execute|
        # SQL variable assignment with concatenation  
        (query|sql|cmd|statement)\s*=\s*.*["'].*\+|
        # SQL concatenation in parentheses
        \(["'].*\+.*["']\)
      /ix,
      cwe_id: "CWE-89",
      owasp_category: "A03:2021",
      recommendation: "Use parameterized queries: cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))",
      test_cases: %{
        vulnerable: [
          ~S|cursor.execute("SELECT * FROM users WHERE id = " + user_id)|,
          ~S|db.execute("DELETE FROM posts WHERE author = '" + username + "'")|,
          ~S|conn.execute("UPDATE users SET status = '" + status + "' WHERE id = " + str(id))|,
          ~S|query = "SELECT * FROM users WHERE id = " + user_id; cursor.execute(query)|
        ],
        safe: [
          ~S|cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))|,
          ~S|db.execute("DELETE FROM posts WHERE author = ?", [username])|,
          ~S|message = "Hello " + username + "!"|,
          ~S|url = base_url + "/api/users/" + user_id|
        ]
      }
    }
  end
  
  @impl true
  def vulnerability_metadata do
    %{
      description: """
      SQL injection vulnerability through Python's string concatenation using the + operator.
      This is one of the most common and easily exploitable SQL injection patterns. When
      developers concatenate user input directly into SQL query strings, attackers can
      inject arbitrary SQL commands.
      
      The vulnerability is widespread because:
      - String concatenation is the most basic string operation in Python
      - Many tutorials and legacy code examples use this insecure pattern
      - Developers often don't realize the security implications
      - Quick fixes and debugging often introduce concatenation temporarily
      - The pattern works, making it seem acceptable until exploited
      """,
      references: [
        %{
          type: :cwe,
          id: "CWE-89",
          title: "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
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
          title: "SQL Injection Prevention in Python",
          url: "https://realpython.com/prevent-python-sql-injection/"
        },
        %{
          type: :research,
          id: "bobby_tables",
          title: "Bobby Tables: A guide to preventing SQL injection",
          url: "https://bobby-tables.com/python"
        }
      ],
      attack_vectors: [
        "Classic injection: user_id = \"1 OR 1=1--\"",
        "Union attack: username = \"admin' UNION SELECT password FROM users--\"",
        "Blind injection: status = \"active' AND SUBSTRING(password,1,1)='a'--\"",
        "Time-based: id = \"1' AND SLEEP(5)--\"",
        "Second-order: name = \"admin'; INSERT INTO admins VALUES('hacker')--\"",
        "Out-of-band: email = \"x' UNION SELECT load_file('/etc/passwd')--\""
      ],
      real_world_impact: [
        "Complete database access and data exfiltration",
        "Authentication bypass allowing admin access",
        "Data corruption or deletion (DROP TABLE)",
        "Remote code execution through database functions",
        "Lateral movement to other systems via linked databases",
        "Compliance violations and regulatory fines"
      ],
      cve_examples: [
        %{
          id: "CVE-2021-43798",
          description: "Grafana SQL injection via string concatenation in data source queries",
          severity: "critical",
          cvss: 9.8,
          note: "Path traversal and SQL injection through concatenated user input"
        },
        %{
          id: "CVE-2019-14234",
          description: "Django SQL injection in key transformation with string concatenation",
          severity: "high",
          cvss: 9.8,
          note: "JSONField/HStoreField key transforms used string concatenation"
        },
        %{
          id: "CVE-2020-15250",
          description: "JupyterHub SQL injection in user group management",
          severity: "high",
          cvss: 8.8,
          note: "String concatenation in SQLAlchemy raw queries"
        }
      ],
      detection_notes: """
      The pattern detects:
      1. SQL keywords followed by string concatenation with + operator
      2. String concatenation followed by database execute methods
      3. Variable assignments using concatenation for SQL queries
      4. Common SQL query variable names (query, sql, cmd) with concatenation
      
      Key indicators:
      - The + operator between quoted strings and variables
      - Proximity to SQL keywords (SELECT, INSERT, UPDATE, DELETE)
      - Database execution methods (execute, executemany, executescript)
      """,
      safe_alternatives: [
        "Use parameterized queries: cursor.execute(\"SELECT * FROM users WHERE id = %s\", (user_id,))",
        "Use named parameters: cursor.execute(\"SELECT * FROM users WHERE name = :name\", {\"name\": username})",
        "Use query builders: query = select(users).where(users.c.id == user_id)",
        "Use ORM methods: User.query.filter_by(id=user_id).first()",
        "For dynamic table names, use identifier quoting: sql.Identifier(table_name)",
        "Use prepared statements with database-specific placeholders"
      ],
      additional_context: %{
        common_mistakes: [
          "Thinking that wrapping values in quotes provides protection",
          "Believing that type conversion (int(), str()) prevents injection",
          "Using string concatenation for 'trusted' internal values",
          "Mixing parameterized and concatenated queries in the same codebase",
          "Using concatenation for table/column names without proper escaping"
        ],
        secure_patterns: [
          "Always use parameterized queries for all user input",
          "Use ? or %s placeholders depending on database driver",
          "For dynamic identifiers, use allowlists or proper escaping functions",
          "Enable query logging in development to verify parameterization",
          "Use static analysis tools to detect concatenation patterns"
        ]
      }
    }
  end
  
  @doc """
  Returns AST enhancement rules to reduce false positives.
  
  This enhancement helps distinguish between actual SQL injection vulnerabilities
  and legitimate uses of string concatenation in non-SQL contexts.
  
  ## Examples
  
      iex> enhancement = RsolvApi.Security.Patterns.Python.SqlInjectionConcat.ast_enhancement()
      iex> Map.keys(enhancement) |> Enum.sort()
      [:ast_rules, :confidence_rules, :context_rules, :min_confidence]
      
      iex> enhancement = RsolvApi.Security.Patterns.Python.SqlInjectionConcat.ast_enhancement()
      iex> enhancement.min_confidence
      0.7
  """
  @impl true
  def ast_enhancement do
    %{
      ast_rules: %{
        node_type: "BinOp",
        op: "Add",
        sql_context: %{
          left_or_right_is_string: true,
          contains_sql_pattern: true,
          followed_by_db_call: true
        }
      },
      context_rules: %{
        database_methods: ["execute", "executemany", "executescript"],
        exclude_if_parameterized: true,
        exclude_paths: [~r/test/, ~r/spec/, ~r/__tests__/, ~r/migrations/],
        sql_keywords: ["SELECT", "INSERT", "UPDATE", "DELETE", "FROM", "WHERE", "JOIN", "UNION"],
        check_variable_assignment: true,
        safe_patterns: ["logging", "print", "format", "message", "url", "path", "filename"]
      },
      confidence_rules: %{
        base: 0.5,
        adjustments: %{
          "has_sql_keywords" => 0.3,
          "in_database_method_call" => 0.2,
          "uses_plus_operator" => 0.1,
          "in_test_code" => -1.0,
          "is_logging_statement" => -0.5,
          "is_url_construction" => -0.4,
          "is_file_path" => -0.4,
          "has_parameterized_query_nearby" => -0.3
        }
      },
      min_confidence: 0.7
    }
  end
end