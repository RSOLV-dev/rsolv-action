defmodule RsolvApi.Security.Patterns.Javascript.SqlInjectionInterpolation do
  @moduledoc """
  SQL Injection via Template Literals (String Interpolation) in JavaScript
  
  Detects dangerous patterns like:
    const query = `SELECT * FROM users WHERE id = ${userId}`
    db.query(`DELETE FROM posts WHERE author = '${username}'`)
    
  Safe patterns:
    db.query("SELECT * FROM users WHERE id = ?", [userId])
    db.query("SELECT * FROM users WHERE id = $1", [userId])
    
  Template literals using backticks (`) with ${} interpolation are just as vulnerable
  as string concatenation when used to build SQL queries.
  
  ## Vulnerability Details
  
  ES6 template literals do NOT protect against SQL injection. They are simply another
  way to build strings and pose the same security risks as concatenation. Developers
  often mistakenly believe template literals are safer, leading to vulnerable code.
  
  ### Attack Example
  ```javascript
  // Vulnerable code
  const username = req.params.name; // User provides: "admin' OR '1'='1"
  const query = `SELECT * FROM users WHERE name = '${username}'`;
  // Resulting query: SELECT * FROM users WHERE name = 'admin' OR '1'='1'
  // This bypasses authentication!
  ```
  """
  
  use RsolvApi.Security.Patterns.PatternBase
  alias RsolvApi.Security.Pattern
  
  @doc """
  Structured vulnerability metadata for SQL injection via template literals.
  
  This metadata documents the specific risks of using ES6 template literals
  for SQL query construction, a common misconception among developers.
  """
  def vulnerability_metadata do
    %{
      description: """
      SQL injection via template literals occurs when JavaScript ES6 template strings 
      (using backticks ` and ${} interpolation) are used to construct SQL queries with 
      untrusted user input. Despite common misconceptions, template literals provide 
      NO protection against SQL injection - they are merely syntactic sugar for string 
      concatenation. The interpolated values are inserted directly into the string 
      without any escaping or parameterization.
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
          id: "template-literal-injection",
          url: "https://r1cs3c.medium.com/understanding-and-preventing-js-template-literal-injection-attacks-cf0e7c799cde",
          title: "Understanding and Preventing JS Template Literal Injection Attacks"
        },
        %{
          type: :stackoverflow,
          id: "es6-sql-injection",
          url: "https://stackoverflow.com/questions/44086785/do-es6-template-literals-protect-against-sql-injection",
          title: "Do ES6 template literals protect against SQL injection?"
        },
        %{
          type: :blog,
          id: "neon-sql-tags",
          url: "https://neon.com/blog/sql-template-tags",
          title: "Why SQL template tags are not vulnerable to SQL injection attacks"
        }
      ],
      
      attack_vectors: [
        "Template literal interpolation with ${} syntax containing user input",
        "Breaking out of SQL string context using quotes within interpolated values",
        "Injecting SQL operators and commands through template expressions",
        "Exploiting developer misconception that template literals are 'safer'",
        "Combining multiple interpolations to build complex injection payloads",
        "Using template literal line breaks to inject multi-line SQL commands"
      ],
      
      real_world_impact: [
        "Authentication bypass through always-true conditions",
        "Data exfiltration via UNION SELECT attacks",
        "Database schema discovery through error messages",
        "Privilege escalation by modifying user roles",
        "Data tampering or deletion of critical records",
        "Potential for second-order SQL injection if data is stored and reused"
      ],
      
      cve_examples: [
        %{
          id: "CVE-2023-29453",
          description: "Template literal injection in html/template affecting Go templates with JavaScript",
          severity: "high",
          cvss: 7.5,
          note: "While focused on Go templates, demonstrates template literal injection risks"
        },
        %{
          id: "CVE-2021-3129",
          description: "Laravel Ignition template injection leading to RCE",
          severity: "critical",
          cvss: 9.8,
          note: "Shows how template injection can escalate to remote code execution"
        }
      ],
      
      detection_notes: """
      This pattern detects template literals (backtick strings) containing SQL keywords
      with ${} interpolation. Key indicators:
      1. Backticks (`) delimiting the string
      2. SQL keywords (SELECT, INSERT, UPDATE, DELETE, etc.)
      3. ${} interpolation syntax within the SQL string
      4. Common user input sources (req.params, req.body, etc.)
      
      The pattern must be careful not to match legitimate uses of template literals
      for non-SQL purposes or properly parameterized query builders.
      """,
      
      additional_context: %{
        common_mistakes: [
          "Believing template literals automatically escape SQL",
          "Thinking ${} syntax provides parameterization",
          "Assuming template literals are 'modern' and therefore secure",
          "Using template literals for 'cleaner' SQL code without considering security"
        ],
        
        secure_alternatives: [
          "Use parameterized queries with placeholders (?, $1, :param)",
          "Use query builder libraries with proper escaping",
          "Use stored procedures with parameter binding",
          "Implement SQL template tag functions that properly escape values"
        ]
      }
    }
  end
  
  @doc """
  Returns the pattern definition for SQL injection via template literals.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Javascript.SqlInjectionInterpolation.pattern()
      iex> pattern.id
      "js-sql-injection-interpolation"
      iex> pattern.severity
      :critical
  """
  def pattern do
    %Pattern{
      id: "js-sql-injection-interpolation",
      name: "SQL Injection via String Interpolation",
      description: "Template literals with unescaped variables in SQL queries",
      type: :sql_injection,
      severity: :critical,
      languages: ["javascript", "typescript"],
      # Matches template literals containing SQL keywords and ${} interpolation
      regex: ~r/`[^`]*(?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|UNION|FROM|WHERE)[^`]*\$\{[^}]+\}[^`]*`/i,
      default_tier: :protected,
      cwe_id: "CWE-89",
      owasp_category: "A03:2021",
      recommendation: "Use parameterized queries instead of string interpolation for SQL queries.",
      test_cases: %{
        vulnerable: [
          ~S|const query = `SELECT * FROM users WHERE name = '${userName}'`|,
          ~S|db.query(`DELETE FROM posts WHERE id = ${postId}`)|,
          ~S|const sql = `UPDATE users SET email = '${email}' WHERE id = ${id}`|,
          ~S|`INSERT INTO logs (message, user) VALUES ('${msg}', '${user}')`|
        ],
        safe: [
          ~S|db.query("SELECT * FROM users WHERE name = ?", [userName])|,
          ~S|const query = db.prepare("DELETE FROM posts WHERE id = ?")|,
          ~S|await db.execute("UPDATE users SET email = ? WHERE id = ?", [email, id])|,
          ~S|const result = await pool.query('SELECT * FROM users WHERE id = $1', [userId])|
        ]
      }
    }
  end
end