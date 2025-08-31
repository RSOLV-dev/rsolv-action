defmodule Rsolv.Security.Patterns.Javascript.SqlInjectionConcat do
  @moduledoc """
  SQL Injection via String Concatenation in JavaScript
  
  Detects dangerous patterns like:
    query = "SELECT * FROM users WHERE id = " + userId;
    db.query("SELECT * FROM users WHERE name = '" + userName + "'");
    
  Safe patterns:
    query = db.prepare("SELECT * FROM users WHERE id = ?", [userId]);
    db.query("SELECT * FROM users WHERE id = $1", [userId]);
    
  Note: This pattern can detect SQL injection in mixed-language files,
  such as JavaScript files that construct SQL queries.
  
  ## Vulnerability Details
  
  SQL injection occurs when untrusted data is concatenated directly into SQL queries,
  allowing attackers to modify the query structure. This can lead to unauthorized data
  access, modification, or deletion.
  
  ### Attack Example
  ```javascript
  // Vulnerable code
  const userId = req.params.id; // User provides: "1 OR 1=1--"
  const query = "SELECT * FROM users WHERE id = " + userId;
  // Resulting query: SELECT * FROM users WHERE id = 1 OR 1=1--
  // This returns ALL users instead of just one!
  ```
  """
  
  use Rsolv.Security.Patterns.PatternBase
  alias Rsolv.Security.Pattern
  
  @doc """
  Structured vulnerability metadata for SQL injection.
  
  This metadata is used for:
  - Internal documentation and training
  - Generating detailed security reports
  - Providing context for security engineers
  - Tracking vulnerability research sources
  """
  def vulnerability_metadata do
    %{
      description: """
      SQL injection is a web security vulnerability that allows an attacker to interfere 
      with the queries that an application makes to its database. It generally allows an 
      attacker to view data that they are not normally able to retrieve, modify or delete 
      data, and in some cases execute administrative operations on the database.
      """,
      
      references: [
        %{
          type: :cwe,
          id: "CWE-89",
          url: "https://cwe.mitre.org/data/definitions/89.html",
          title: "Improper Neutralization of Special Elements used in an SQL Command"
        },
        %{
          type: :owasp,
          id: "A03:2021",
          url: "https://owasp.org/Top10/A03_2021-Injection/",
          title: "OWASP Top 10 2021 - A03 Injection"
        },
        %{
          type: :research,
          id: "portswigger-sqli",
          url: "https://portswigger.net/web-security/sql-injection",
          title: "PortSwigger - SQL Injection"
        },
        %{
          type: :nist,
          id: "si-10",
          url: "https://nvd.nist.gov/800-53/Rev4/control/SI-10",
          title: "NIST - Information Input Validation"
        }
      ],
      
      attack_vectors: [
        "Direct concatenation of user input into SQL queries",
        "String interpolation without proper escaping",
        "Dynamic query construction using template literals",
        "Insufficient input validation before query construction",
        "Mixing data and SQL code in the same string"
      ],
      
      real_world_impact: [
        "Data breach - unauthorized access to sensitive information",
        "Data loss - deletion of critical database records",
        "Authentication bypass - logging in without credentials",
        "Privilege escalation - gaining admin access",
        "Remote code execution (in some database configurations)"
      ],
      
      cve_examples: [
        %{
          id: "CVE-2023-22794",
          description: "SQL Injection in Active Record (Ruby on Rails)",
          severity: "critical",
          cvss: 9.8
        },
        %{
          id: "CVE-2022-21724",
          description: "PostgreSQL JDBC Driver SQL Injection via String Concatenation",
          severity: "high",
          cvss: 8.8
        }
      ],
      
      safe_alternatives: [
        "Use parameterized queries: db.query('SELECT * FROM users WHERE id = ?', [userId])",
        "Use prepared statements: db.prepare('SELECT * FROM users WHERE id = ?')",
        "Use ORM query builders: User.findById(userId)",
        "Use safe template literals with parameter binding",
        "Validate and sanitize input before query construction"
      ],
      
      detection_notes: """
      This pattern specifically detects string concatenation patterns in JavaScript
      that build SQL queries. It looks for:
      1. String concatenation operators (+) near SQL keywords
      2. User input sources (req.params, req.query, req.body)
      3. Database query method calls
      
      The AST enhancement reduces false positives by ensuring the concatenation
      occurs within actual database query calls.
      """
    }
  end
  
  @doc """
  Returns the pattern definition for SQL injection via concatenation.
  
  ## Examples
  
      iex> pattern = Rsolv.Security.Patterns.Javascript.SqlInjectionConcat.pattern()
      iex> pattern.id
      "js-sql-injection-concat"
      iex> pattern.severity
      :critical
  """
  def pattern do
    %Pattern{
      id: "js-sql-injection-concat",
      name: "SQL Injection via String Concatenation",
      description: "Detects SQL query construction using string concatenation with user input",
      type: :sql_injection,
      severity: :critical,
      languages: ["javascript", "typescript"],
      regex: ~r/(?:SELECT|INSERT|UPDATE|DELETE|FROM|WHERE|JOIN).*?["']\s*\+\s*\w+/i,
      cwe_id: "CWE-89",
      owasp_category: "A03:2021",
      recommendation: "Use parameterized queries or prepared statements instead of string concatenation",
      test_cases: %{
        vulnerable: [
          ~S|db.query("SELECT * FROM users WHERE id = " + req.params.id)|,
          ~S|const sql = "SELECT * FROM users WHERE name = '" + userName + "'"|,
          ~S|connection.execute("DELETE FROM posts WHERE id = " + postId)|
        ],
        safe: [
          ~S|db.query("SELECT * FROM users WHERE id = ?", [req.params.id])|,
          ~S|db.query("SELECT * FROM users WHERE id = $1", [userId])|,
          ~S|const stmt = db.prepare("SELECT * FROM users WHERE name = ?")|
        ]
      }
    }
  end
  
  @doc """
  Returns AST enhancement rules to reduce false positives.
  
  This enhancement helps distinguish between actual SQL injection vulnerabilities and:
  - Parameterized queries using placeholders (?, $1, :param)
  - ORM query builders (Knex, Sequelize, etc.)
  - SQL strings used only for logging
  - Test code that builds queries for assertions
  
  ## Examples
  
      iex> enhancement = Rsolv.Security.Patterns.Javascript.SqlInjectionConcat.ast_enhancement()
      iex> Map.keys(enhancement) |> Enum.sort()
      [:ast_rules, :confidence_rules, :context_rules, :min_confidence]
      
      iex> enhancement = Rsolv.Security.Patterns.Javascript.SqlInjectionConcat.ast_enhancement()
      iex> enhancement.ast_rules.node_type
      "BinaryExpression"
      
      iex> enhancement = Rsolv.Security.Patterns.Javascript.SqlInjectionConcat.ast_enhancement()
      iex> enhancement.ast_rules.operator
      "+"
      
      iex> enhancement = Rsolv.Security.Patterns.Javascript.SqlInjectionConcat.ast_enhancement()
      iex> enhancement.min_confidence
      0.7
      
      iex> enhancement = Rsolv.Security.Patterns.Javascript.SqlInjectionConcat.ast_enhancement()
      iex> "uses_parameterized_query" in Map.keys(enhancement.confidence_rules.adjustments)
      true
  """
  @impl true
  def ast_enhancement do
    %{
      ast_rules: %{
        node_type: "BinaryExpression",
        operator: "+",
        # Must be building a SQL query
        context_analysis: %{
          contains_sql_keywords: true,
          has_user_input_in_concatenation: true
          # Relaxed: within_db_call is now optional - gives confidence boost if found
        }
        # Removed strict ancestor requirements - pattern matcher can't effectively
        # track context across multiple statements in current implementation
      },
      context_rules: %{
        exclude_paths: [~r/test/, ~r/spec/, ~r/__tests__/, ~r/fixtures/, ~r/mocks/],
        exclude_if_parameterized: true,      # Using ? or $1 placeholders
        exclude_if_uses_orm_builder: true,   # Query builders are safer
        exclude_if_logging_only: true,       # Just logging SQL, not executing
        safe_if_input_validated: true        # Has input sanitization
      },
      confidence_rules: %{
        base: 0.4,  # Increased base since we relaxed context requirements
        adjustments: %{
          "direct_req_param_concat" => 0.4,   # req.params.id directly concatenated
          "within_db_query_call" => 0.3,      # Bonus if inside db.query() call
          "has_sql_keywords" => 0.3,          # Contains SELECT/INSERT/etc - increased for better detection
          "has_user_input" => 0.2,            # Clear user input present - increased for better detection
          "uses_parameterized_query" => -0.9, # Has ?, $1, :param placeholders
          "uses_orm_query_builder" => -0.8,   # Using Knex, Sequelize builders
          "is_console_log" => -1.0,           # Just logging, not querying
          "has_input_validation" => -0.7,     # Input is sanitized/escaped
          "in_test_file" => -0.9              # Test code
        }
      },
      min_confidence: 0.7
    }
  end
end
