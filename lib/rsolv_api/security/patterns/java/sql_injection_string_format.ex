defmodule RsolvApi.Security.Patterns.Java.SqlInjectionStringFormat do
  @moduledoc """
  SQL Injection via String.format pattern for Java code.
  
  Detects SQL injection vulnerabilities where String.format() or MessageFormat.format()
  are used to build SQL queries. These methods perform string interpolation without
  any SQL-specific sanitization, making them vulnerable to injection attacks.
  
  ## Vulnerability Details
  
  String.format() uses format specifiers like %s, %d, %f to inject values into strings.
  When used to build SQL queries, attackers can inject malicious SQL code through
  these format parameters. While %d (integer) provides some protection, %s (string)
  allows arbitrary input.
  
  ### Attack Example
  
  ```java
  // Vulnerable code
  String userId = request.getParameter("id");
  String query = String.format("SELECT * FROM users WHERE id = %s", userId);
  stmt.executeQuery(query);
  
  // Attack input: userId = "1 OR 1=1 --"
  // Results in: SELECT * FROM users WHERE id = 1 OR 1=1 --
  // Returns all users instead of just one
  ```
  
  ### Real-World Impact
  
  Many developers mistakenly believe String.format() provides some security benefit over
  simple concatenation, but it offers no protection against SQL injection. This has led
  to numerous vulnerabilities in production applications.
  
  ## References
  
  - CWE-89: Improper Neutralization of Special Elements used in an SQL Command
  - OWASP A03:2021 - Injection
  """
  
  use RsolvApi.Security.Patterns.PatternBase
  alias RsolvApi.Security.Pattern
  
  @impl true
  def pattern do
    %Pattern{
      id: "java-sql-injection-string-format",
      name: "SQL Injection via String.format",
      description: "SQL injection through String.format() in queries",
      type: :sql_injection,
      severity: :high,
      languages: ["java"],
      regex: [
        # executeQuery with String.format
        ~r/executeQuery\s*\(\s*String\.format\s*\(/,
        # executeUpdate with String.format
        ~r/executeUpdate\s*\(\s*String\.format\s*\(/,
        # execute with String.format
        ~r/execute\s*\(\s*String\.format\s*\(/,
        # prepareStatement with String.format
        ~r/prepareStatement\s*\(\s*String\.format\s*\(/,
        # createStatement().execute* with String.format
        ~r/createStatement\s*\(\s*\)\.execute[^(]*\(\s*String\.format\s*\(/,
        # jdbcTemplate methods with String.format
        ~r/jdbcTemplate\.\w+\s*\(\s*String\.format\s*\(/,
        # MessageFormat.format in SQL context
        ~r/execute(?:Query|Update)?\s*\(\s*MessageFormat\.format\s*\(/,
        # Variables assigned with String.format then used in SQL
        ~r/String\s+\w+\s*=\s*String\.format\s*\([^)]*(?:SELECT|INSERT|UPDATE|DELETE)/i
      ],
      default_tier: :protected,
      cwe_id: "CWE-89",
      owasp_category: "A03:2021",
      recommendation: "Use PreparedStatement with setString(), setInt(), etc. instead of String.format()",
      test_cases: %{
        vulnerable: [
          ~S|executeQuery(String.format("SELECT * FROM users WHERE id = %s", userId))|,
          ~S|stmt.executeQuery(String.format("SELECT * FROM products WHERE name = '%s'", productName))|,
          ~S|connection.prepareStatement(String.format("SELECT * FROM users WHERE email = '%s'", email))|,
          ~S|String query = String.format("SELECT * FROM users WHERE role = '%s'", role);
stmt.executeQuery(query);|
        ],
        safe: [
          ~S|PreparedStatement pstmt = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
pstmt.setString(1, userId);|,
          ~S|String.format("User %s logged in at %s", username, timestamp)|,
          ~S|logger.info(String.format("Processing %d records", count))|
        ]
      }
    }
  end
  
  @impl true
  def vulnerability_metadata do
    %{
      description: """
      SQL injection occurs when String.format() or MessageFormat.format() are used to build
      SQL queries. These formatting methods perform simple string interpolation without any
      SQL-specific escaping or validation. While format specifiers like %d provide type
      checking, they don't prevent SQL injection in numeric contexts, and %s allows arbitrary
      string injection.
      
      This vulnerability is particularly dangerous because developers often mistakenly believe
      that using String.format() is safer than simple concatenation, when in fact it provides
      no additional security benefits for SQL query construction.
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
          id: "java_string_format_security",
          title: "Testing for Format String Injection - OWASP",
          url: "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/13-Testing_for_Format_String_Injection"
        },
        %{
          type: :article,
          id: "sql_injection_prevention",
          title: "SQL Injection Prevention Cheat Sheet",
          url: "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"
        }
      ],
      attack_vectors: [
        "String injection: String.format(\"WHERE name = '%s'\", \"admin' OR '1'='1\")",
        "Integer overflow: String.format(\"WHERE id = %d\", \"999999999999999999999\")",
        "Format specifier injection: String.format(query, \"%s %s %s\")",
        "Union-based: String.format(\"WHERE id = %s\", \"1 UNION SELECT password FROM users\")",
        "Boolean-based blind: String.format(\"WHERE id = %s\", \"1 AND 1=1\")",
        "Time-based blind: String.format(\"WHERE id = %s\", \"1; WAITFOR DELAY '00:00:05'\")"
      ],
      real_world_impact: [
        "Full database compromise through arbitrary query execution",
        "Data exfiltration using UNION-based attacks",
        "Authentication bypass by manipulating WHERE clauses",
        "Data corruption through injected UPDATE/DELETE statements",
        "Denial of service through resource-intensive queries",
        "Privilege escalation by modifying user roles"
      ],
      cve_examples: [
        %{
          id: "CVE-2023-26033",
          description: "SQL injection in Gentoo soko through String formatting in queries",
          severity: "high",
          cvss: 8.8,
          note: "String formatting used to build SQL queries allowed injection attacks"
        },
        %{
          id: "CVE-2022-31197",
          description: "SQL injection in PostgreSQL JDBC driver through format string usage",
          severity: "high",
          cvss: 8.1,
          note: "Improper handling of formatted strings in SQL query construction"
        },
        %{
          id: "CVE-2025-24787",
          description: "Parameter injection in database connection strings via string concatenation",
          severity: "critical",
          cvss: 9.8,
          note: "String concatenation and formatting allowed injection in connection parameters"
        }
      ],
      detection_notes: """
      This pattern detects String.format() and MessageFormat.format() usage in SQL contexts.
      Key indicators include:
      - Direct use in execute methods (executeQuery, executeUpdate, execute)
      - Use in prepareStatement() defeating the purpose of prepared statements
      - Assignment to query variables later executed
      - Use in JDBC template methods
      
      False positives may occur when String.format() is used for non-SQL purposes like
      logging or building non-SQL strings. AST enhancement helps distinguish SQL contexts.
      """,
      safe_alternatives: [
        "Use PreparedStatement: pstmt.setString(1, userId) instead of String.format()",
        "Use named parameters with Spring: new MapSqlParameterSource().addValue(\"id\", userId)",
        "Use query builders: jOOQ or QueryDSL for type-safe query construction",
        "For dynamic table/column names, use allowlisting and escape with identifier quotes",
        "Use stored procedures with CallableStatement for complex queries",
        "Implement input validation before any query construction"
      ],
      additional_context: %{
        common_mistakes: [
          "Believing String.format() escapes SQL special characters (it doesn't)",
          "Thinking %d format specifier prevents all injection (still vulnerable to overflow)",
          "Using String.format() with PreparedStatement (defeats the security purpose)",
          "Mixing safe and unsafe practices in the same codebase"
        ],
        secure_patterns: [
          "Always use parameterized queries with ? placeholders",
          "Never use String.format() for SQL query construction",
          "Validate and sanitize all input before use",
          "Use ORM frameworks with proper parameterization"
        ],
        framework_specific: [
          "Spring JDBC: Use NamedParameterJdbcTemplate with :param syntax",
          "Hibernate: Use HQL with positional or named parameters",
          "MyBatis: Use #\{param} for safe parameter substitution",
          "JOOQ: Use DSL methods for type-safe query building"
        ]
      }
    }
  end
  
  @doc """
  Returns AST enhancement rules to reduce false positives.
  
  This enhancement helps distinguish between SQL-related String.format usage
  and general string formatting for logging or display purposes.
  
  ## Examples
  
      iex> enhancement = RsolvApi.Security.Patterns.Java.SqlInjectionStringFormat.ast_enhancement()
      iex> Map.keys(enhancement) |> Enum.sort()
      [:ast_rules, :confidence_rules, :context_rules, :min_confidence]
      
      iex> enhancement = RsolvApi.Security.Patterns.Java.SqlInjectionStringFormat.ast_enhancement()
      iex> enhancement.min_confidence
      0.7
      
      iex> enhancement = RsolvApi.Security.Patterns.Java.SqlInjectionStringFormat.ast_enhancement()
      iex> enhancement.ast_rules.node_type
      "MethodInvocation"
  """
  @impl true
  def ast_enhancement do
    %{
      ast_rules: %{
        node_type: "MethodInvocation",
        format_analysis: %{
          check_format_methods: true,
          format_methods: ["String.format", "MessageFormat.format", "String.formatted"],
          check_format_specifiers: true,
          dangerous_specifiers: ["%s", "%S"],
          safer_specifiers: ["%d", "%f", "%b"]
        },
        sql_context: %{
          check_parent_call: true,
          sql_methods: [
            "executeQuery", "executeUpdate", "execute", "executeBatch",
            "prepareStatement", "prepareCall", "addBatch",
            "query", "update", "batchUpdate"
          ],
          check_variable_usage: true,
          sql_variable_patterns: ["query", "sql", "statement", "cmd"]
        },
        string_analysis: %{
          check_sql_keywords: true,
          sql_keywords: ["SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "CREATE", "ALTER"],
          check_format_string: true,
          table_placeholders: ["FROM %s", "INTO %s", "UPDATE %s"]
        }
      },
      context_rules: %{
        check_format_arguments: true,
        safe_format_types: ["literal_string", "constant", "enum"],
        unsafe_format_types: ["user_input", "request_parameter", "external_data"],
        exclude_patterns: [
          ~r/logger\.\w+\s*\(\s*String\.format/i,
          ~r/log\.\w+\s*\(\s*String\.format/i,
          ~r/System\.out\.print(?:ln)?\s*\(\s*String\.format/,
          ~r/throw\s+new\s+\w*Exception\s*\(\s*String\.format/
        ],
        check_jdbc_context: true,
        jdbc_classes: ["Connection", "Statement", "PreparedStatement", "JdbcTemplate"]
      },
      confidence_rules: %{
        base: 0.4,
        adjustments: %{
          "has_sql_keyword" => 0.3,
          "in_sql_method_call" => 0.4,
          "has_user_input" => 0.3,
          "assigned_to_sql_variable" => 0.2,
          "uses_safe_specifier_only" => -0.3,
          "in_logging_context" => -0.8,
          "in_test_code" => -0.5,
          "has_prepared_statement_nearby" => -0.4
        }
      },
      min_confidence: 0.7
    }
  end
end