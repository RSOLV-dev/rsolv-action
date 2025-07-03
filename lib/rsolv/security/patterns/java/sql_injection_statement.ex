defmodule Rsolv.Security.Patterns.Java.SqlInjectionStatement do
  @moduledoc """
  SQL Injection via Statement pattern for Java code.
  
  Detects SQL injection vulnerabilities where Java Statement objects are used with
  string concatenation to build SQL queries. This is one of the most common and
  dangerous security vulnerabilities.
  
  ## Vulnerability Details
  
  Using java.sql.Statement with string concatenation allows attackers to inject
  arbitrary SQL commands. The Statement interface executes SQL directly without
  parameterization, making it vulnerable when user input is concatenated.
  
  ### Attack Example
  
  ```java
  // Vulnerable code
  String userId = request.getParameter("id");
  Statement stmt = conn.createStatement();
  ResultSet rs = stmt.executeQuery("SELECT * FROM users WHERE id = " + userId);
  
  // Attack input: userId = "1 OR 1=1 --"
  // Results in: SELECT * FROM users WHERE id = 1 OR 1=1 --
  // Returns all users instead of just one
  ```
  
  ### Real-World Impact
  
  - CVE-2022-21724: Critical SQL injection in JDBC allowing full database compromise
  - CVE-2024-1597: SQL injection in PostgreSQL JDBC driver via string concatenation
  - CVE-2022-31197: Multiple SQL injection vulnerabilities in MySQL Connector/J
  
  ## References
  
  - CWE-89: Improper Neutralization of Special Elements used in an SQL Command
  - OWASP A03:2021 - Injection
  """
  
  use Rsolv.Security.Patterns.PatternBase
  alias Rsolv.Security.Pattern
  
  @impl true
  def pattern do
    %Pattern{
      id: "java-sql-injection-statement",
      name: "SQL Injection via Statement",
      description: "SQL injection through Statement with string concatenation",
      type: :sql_injection,
      severity: :high,
      languages: ["java"],
      regex: [
        # executeQuery with string concatenation (with or without object)
        ~r/\.?executeQuery\s*\(\s*["'].*["']\s*\+/,
        ~r/\.?executeQuery\s*\([^)]*\+[^)]*\)/,
        # executeUpdate with concatenation (with or without object)
        ~r/\.?executeUpdate\s*\(\s*["'].*["']\s*\+/,
        ~r/\.?executeUpdate\s*\([^)]*\+[^)]*\)/,
        # execute with concatenation (with or without object)
        ~r/\.?execute\s*\(\s*["'].*["']\s*\+/,
        ~r/\.?execute\s*\([^)]*\+[^)]*\)/,
        # createStatement followed by concatenated query
        ~r/createStatement\s*\(\s*\)[^;{]*execute(?:Query|Update)?\s*\([^)]*\+/
      ],
      cwe_id: "CWE-89",
      owasp_category: "A03:2021",
      recommendation: "Use PreparedStatement with parameterized queries instead of Statement with string concatenation",
      test_cases: %{
        vulnerable: [
          ~S|Statement stmt = conn.createStatement();
ResultSet rs = stmt.executeQuery("SELECT * FROM users WHERE id = " + userId);|,
          ~S|stmt.executeQuery("SELECT * FROM products WHERE name = '" + productName + "'");|,
          ~S|statement.executeUpdate("DELETE FROM posts WHERE author = '" + author + "'");|,
          ~S|stmt.execute("DROP TABLE " + tableName);|
        ],
        safe: [
          ~S|PreparedStatement pstmt = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
pstmt.setInt(1, userId);
ResultSet rs = pstmt.executeQuery();|,
          ~S|PreparedStatement pstmt = conn.prepareStatement("SELECT * FROM products WHERE name = ?");
pstmt.setString(1, productName);|
        ]
      }
    }
  end
  
  @impl true
  def vulnerability_metadata do
    %{
      description: """
      SQL injection occurs when untrusted user input is concatenated directly into SQL queries
      executed through java.sql.Statement. This allows attackers to manipulate the query structure
      and execute arbitrary SQL commands. Statement.executeQuery(), executeUpdate(), and execute()
      methods are vulnerable when used with string concatenation.
      
      The vulnerability can lead to unauthorized data access, data modification, administrative
      operations execution, and in some cases, operating system command execution.
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
          id: "java_sql_injection_prevention",
          title: "Java SQL Injection Prevention Cheat Sheet",
          url: "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"
        },
        %{
          type: :documentation,
          id: "jdbc_security",
          title: "JDBC Security Best Practices",
          url: "https://docs.oracle.com/javase/tutorial/jdbc/basics/prepared.html"
        }
      ],
      attack_vectors: [
        "Basic injection: userId = '1 OR 1=1 --'",
        "Union-based: productId = '1 UNION SELECT username, password FROM users --'",
        "Time-based blind: id = '1; IF(1=1, SLEEP(5), 0) --'",
        "Error-based: name = '' OR CONVERT(int, @@version) > 0 --'",
        "Stacked queries: id = '1; DROP TABLE users; --'",
        "Second-order: Store malicious SQL that executes later"
      ],
      real_world_impact: [
        "Complete database compromise and data theft",
        "Authentication bypass allowing unauthorized access",
        "Data manipulation including deletion of critical records",
        "Privilege escalation to database administrator",
        "Remote code execution through database features (xp_cmdshell, etc.)",
        "Denial of service through resource-intensive queries"
      ],
      cve_examples: [
        %{
          id: "CVE-2022-21724",
          description: "Critical SQL injection vulnerability in JDBC implementations allowing remote code execution",
          severity: "critical",
          cvss: 9.8,
          note: "Affected multiple JDBC drivers due to improper input sanitization in Statement execution"
        },
        %{
          id: "CVE-2024-1597",
          description: "SQL injection in PostgreSQL JDBC driver through string concatenation in queries",
          severity: "high",
          cvss: 8.8,
          note: "Allows attackers to execute arbitrary SQL commands via crafted input parameters"
        },
        %{
          id: "CVE-2022-31197",
          description: "Multiple SQL injection vulnerabilities in MySQL Connector/J when using Statement",
          severity: "high",
          cvss: 8.1,
          note: "Improper neutralization of special elements in Statement.executeQuery() calls"
        },
        %{
          id: "CVE-2020-2934",
          description: "SQL injection in Oracle WebLogic Server through JDBC Statement usage",
          severity: "critical",
          cvss: 9.8,
          note: "Remote attackers could execute arbitrary SQL commands without authentication"
        }
      ],
      detection_notes: """
      This pattern detects Statement usage with string concatenation. Common patterns include:
      - Direct concatenation with + operator
      - String.format() used to build queries
      - StringBuilder/StringBuffer to construct SQL
      - Any dynamic SQL construction with Statement interface
      
      False positives may occur with logging statements or when building non-SQL strings.
      AST enhancement helps distinguish actual SQL operations from other string operations.
      """,
      safe_alternatives: [
        "Use PreparedStatement with placeholder parameters: pstmt.setString(1, userInput)",
        "Use stored procedures with CallableStatement",
        "Use query builders like JOOQ or QueryDSL for type-safe queries",
        "Implement input validation with allowlists before any database operation",
        "Use ORM frameworks like Hibernate with parameterized queries",
        "Apply the principle of least privilege to database connections"
      ],
      additional_context: %{
        common_mistakes: [
          "Believing that escaping quotes is sufficient protection",
          "Using Statement for 'trusted' internal data that might be compromised",
          "Concatenating 'safe' numeric values without validation",
          "Mixing PreparedStatement with string concatenation"
        ],
        secure_patterns: [
          "Always use PreparedStatement for queries with any variable input",
          "Validate input types and ranges before query construction",
          "Use named parameters where supported by frameworks",
          "Implement query logging for security monitoring"
        ],
        framework_specific: [
          "Spring: Use JdbcTemplate with ? placeholders",
          "Hibernate: Use HQL with named parameters like :userId",
          "MyBatis: Use parameterized mapper queries with #\{param}",
          "JPA: Use JPQL with positional or named parameters"
        ]
      }
    }
  end
  
  @doc """
  Returns AST enhancement rules to reduce false positives.
  
  This enhancement helps distinguish between actual SQL operations and false positives
  like logging statements or non-SQL string concatenation.
  
  ## Examples
  
      iex> enhancement = Rsolv.Security.Patterns.Java.SqlInjectionStatement.ast_enhancement()
      iex> Map.keys(enhancement) |> Enum.sort()
      [:ast_rules, :confidence_rules, :context_rules, :min_confidence]
      
      iex> enhancement = Rsolv.Security.Patterns.Java.SqlInjectionStatement.ast_enhancement()
      iex> enhancement.min_confidence
      0.7
      
      iex> enhancement = Rsolv.Security.Patterns.Java.SqlInjectionStatement.ast_enhancement()
      iex> enhancement.ast_rules.node_type
      "MethodInvocation"
  """
  @impl true
  def ast_enhancement do
    %{
      ast_rules: %{
        node_type: "MethodInvocation",
        sql_operations: %{
          check_execute_methods: true,
          execute_methods: ["executeQuery", "executeUpdate", "execute", "executeBatch"],
          check_parent_type: true,
          parent_types: ["Statement", "java.sql.Statement"],
          dangerous_patterns: [
            "concatenation_in_argument",
            "string_format_in_argument",
            "stringbuilder_in_argument"
          ]
        },
        concatenation_analysis: %{
          check_string_concat: true,
          concat_operators: ["+", "concat", "append"],
          check_format_methods: true,
          format_methods: ["String.format", "MessageFormat.format", "String.join"]
        },
        data_flow: %{
          track_user_input: true,
          user_input_sources: [
            "request.getParameter",
            "request.getAttribute",
            "request.getHeader",
            "ServletRequest",
            "HttpServletRequest"
          ]
        }
      },
      context_rules: %{
        check_statement_type: true,
        unsafe_statement_types: ["Statement", "java.sql.Statement"],
        safe_statement_types: ["PreparedStatement", "CallableStatement"],
        exclude_patterns: [
          ~r/logger\.(?:info|debug|warn|error)/i,
          ~r/System\.out\.print/,
          ~r/log4j/,
          ~r/slf4j/
        ],
        check_sql_keywords: true,
        sql_keywords: ["SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "CREATE", "ALTER", "EXEC"]
      },
      confidence_rules: %{
        base: 0.5,
        adjustments: %{
          "has_sql_keyword" => 0.3,
          "has_user_input" => 0.3,
          "in_dao_class" => 0.2,
          "uses_prepared_statement" => -0.8,
          "in_test_code" => -0.5,
          "is_logging" => -0.9,
          "has_validation" => -0.3
        }
      },
      min_confidence: 0.7
    }
  end
end
