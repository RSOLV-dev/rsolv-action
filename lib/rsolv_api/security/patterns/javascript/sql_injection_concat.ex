defmodule RsolvApi.Security.Patterns.Javascript.SqlInjectionConcat do
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
  
  use RsolvApi.Security.Patterns.PatternBase
  alias RsolvApi.Security.Pattern
  
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
  
      iex> pattern = RsolvApi.Security.Patterns.Javascript.SqlInjectionConcat.pattern()
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
      regex: ~r/(?:SELECT|INSERT|UPDATE|DELETE|FROM|WHERE|JOIN).*?\+[^+]*(?:req\.|request\.|params|query|body)/i,
      default_tier: :protected,
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
end