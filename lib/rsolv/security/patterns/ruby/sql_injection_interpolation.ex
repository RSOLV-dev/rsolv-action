defmodule Rsolv.Security.Patterns.Ruby.SqlInjectionInterpolation do
  @moduledoc """
  Pattern for detecting SQL injection vulnerabilities via string interpolation in Ruby applications.
  
  This pattern identifies when user input is directly interpolated into SQL queries using Ruby's
  string interpolation syntax #{}, which bypasses SQL parameter binding and creates injection
  vulnerabilities.
  
  ## Vulnerability Details
  
  SQL injection via string interpolation occurs when developers construct SQL queries by
  directly embedding variables into SQL strings using Ruby's #{} interpolation syntax.
  This practice is extremely dangerous because:
  
  - **Direct Code Execution**: User input becomes part of the SQL command structure
  - **Bypasses Parameter Binding**: No sanitization or escaping is performed
  - **ActiveRecord Blind Spot**: Even secure ORM methods become vulnerable when passed raw SQL
  - **Difficult to Detect**: String interpolation can appear in many contexts
  
  ### Attack Example
  ```ruby
  # Vulnerable SQL interpolation
  class UserController < ApplicationController
    def search
      name = params[:name]  # User input: "'; DROP TABLE users; --"
      
      # VULNERABLE: Direct interpolation into SQL
      users = User.where("name = '\#{name}'")
      # Results in: SELECT * FROM users WHERE name = ''; DROP TABLE users; --'
      
      # VULNERABLE: Even with ActiveRecord methods
      User.find_by_sql("SELECT * FROM users WHERE status = \#{params[:status]}")
      # Attack: params[:status] = "1; INSERT INTO admin_users..."
    end
  end
  
  # Attack result: Complete database compromise
  ```
  """
  
  use Rsolv.Security.Patterns.PatternBase
  alias Rsolv.Security.Pattern
  
  @impl true
  def pattern do
    %Pattern{
      id: "ruby-sql-injection-interpolation",
      name: "SQL Injection via String Interpolation",
      description: "Detects SQL queries built with string interpolation",
      type: :sql_injection,
      severity: :critical,
      languages: ["ruby"],
      regex: [
        ~r/ActiveRecord::Base\.connection\.execute\s*\(\s*[\"'].*?#\{/,
        ~r/\.connection\.execute\s*\(\s*[\"'].*?#\{/,
        ~r/\.execute\s*\(\s*[\"'](?:SELECT|INSERT|UPDATE|DELETE).*?#\{/i,
        ~r/\.find_by_sql\s*\(\s*[\"'].*?#\{/,
        ~r/\.where\s*\(\s*[\"'].*?#\{/,
        ~r/\.joins\s*\(\s*[\"'].*?#\{/,
        ~r/\.order\s*\(\s*[\"'].*?#\{/,
        ~r/\.group\s*\(\s*[\"'].*?#\{/,
        ~r/\.having\s*\(\s*[\"'].*?#\{/,
        ~r/\.select\s*\(\s*[\"'].*?#\{/,
        ~r/\.from\s*\(\s*[\"'].*?#\{/,
        ~r/\.count\s*\(\s*[\"'].*?#\{/,
        ~r/\.sum\s*\(\s*[\"'].*?#\{/,
        ~r/\.update_all\s*\(\s*[\"'].*?#\{/,
        ~r/\.delete_all\s*\(\s*[\"'].*?#\{/
      ],
      cwe_id: "CWE-89",
      owasp_category: "A03:2021",
      recommendation: "Use parameterized queries or ActiveRecord query interface",
      test_cases: %{
        vulnerable: [
          ~S|User.where("name = '#{params[:name]}'")|,
          ~S|ActiveRecord::Base.connection.execute("SELECT * FROM users WHERE id = #{id}")|,
          ~S|User.find_by_sql("SELECT * FROM users WHERE status = #{status}")|,
          ~S|Post.joins("LEFT JOIN users ON users.id = #{user_id}")|,
          ~S|User.order("#{params[:sort_column]} #{params[:direction]}")|
        ],
        safe: [
          ~S|User.where(name: params[:name])|,
          ~S|User.where("name = ?", params[:name])|,
          ~S|User.find_by(name: params[:name])|,
          ~S|User.joins(:posts)|,
          ~S|User.order(:created_at)|
        ]
      }
    }
  end
  
  @impl true
  def vulnerability_metadata do
    %{
      description: """
      SQL injection via string interpolation is one of the most dangerous vulnerabilities
      in Ruby on Rails applications. It occurs when developers use Ruby's string interpolation
      syntax (#{}) to insert user-controlled data directly into SQL queries.
      
      **How String Interpolation Works:**
      Ruby's #{} syntax evaluates expressions and inserts their string representation
      directly into the containing string. When used with SQL, this creates a direct
      pathway for attackers to inject malicious SQL code.
      
      **Why It's Dangerous:**
      - **No Sanitization**: String interpolation performs no SQL escaping or validation
      - **ActiveRecord Bypass**: Even secure ORM methods become vulnerable when given raw SQL
      - **Silent Failures**: Vulnerable code often appears to work correctly in testing
      - **Widespread Usage**: Many developers use interpolation for dynamic column names or conditions
      
      **Common Vulnerable Patterns:**
      - Dynamic WHERE clauses: `where("column = '\#{value}'")`
      - Dynamic ORDER BY: `order("\#{column} \#{direction}")`
      - Custom joins: `joins("JOIN table ON condition = \#{value}")`
      - Raw SQL execution: `connection.execute("SQL with \#{variables}")`
      - Search queries: `find_by_sql("SELECT * WHERE field LIKE '%\#{search}%'")`
      
      **Attack Vectors:**
      Attackers can exploit string interpolation to:
      - Extract sensitive data through UNION-based attacks
      - Bypass authentication with boolean-based conditions
      - Execute administrative commands like DROP TABLE
      - Insert malicious data or create backdoor accounts
      - Cause denial of service through resource-intensive queries
      
      **Real-World Context:**
      CVE-2023-22794 demonstrated how even Rails' built-in comment functionality
      could be vulnerable to SQL injection when user input was interpolated into
      SQL queries without proper sanitization.
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
          id: "rails_sql_injection_guide",
          title: "Rails SQL Injection Guide: Examples and Prevention",
          url: "https://www.stackhawk.com/blog/sql-injection-prevention-rails/"
        },
        %{
          type: :research,
          id: "rails_security_guide",
          title: "Ruby on Rails Security Guide",
          url: "https://guides.rubyonrails.org/security.html#sql-injection"
        },
        %{
          type: :research,
          id: "owasp_rails_cheatsheet",
          title: "OWASP Ruby on Rails Cheat Sheet",
          url: "https://cheatsheetseries.owasp.org/cheatsheets/Ruby_on_Rails_Cheat_Sheet.html"
        }
      ],
      attack_vectors: [
        "Union-based injection: Inject UNION SELECT to extract data from other tables",
        "Boolean-based blind injection: Use true/false conditions to extract data bit by bit",
        "Time-based blind injection: Use SLEEP() or similar to detect successful injection",
        "Error-based injection: Trigger database errors to reveal schema information",
        "Stacked queries: Execute multiple SQL statements separated by semicolons",
        "Comment injection: Use -- or /* */ to ignore rest of query and inject new logic",
        "Quote escape injection: Break out of quoted strings with ' or \" characters",
        "Numeric injection: Inject into numeric contexts without quotes",
        "ORDER BY injection: Manipulate sorting to extract data or cause errors",
        "HAVING clause injection: Inject conditions into aggregate queries"
      ],
      real_world_impact: [
        "CVE-2023-22794: Rails ActiveRecord comment injection via string interpolation",
        "2019 Capital One breach: SQL injection led to 100+ million customer records exposed",
        "2017 Equifax breach: SQL injection in web application compromised 147 million records",
        "GitHub security incidents: Multiple Rails apps compromised via string interpolation",
        "Shopify partner app vulnerabilities: SQL injection via dynamic query building",
        "Ruby gem vulnerabilities: Popular gems with SQL injection via interpolation",
        "E-commerce platform breaches: Payment and customer data exposed via Rails SQL injection",
        "Healthcare data breaches: Patient records accessed through vulnerable Rails applications"
      ],
      cve_examples: [
        %{
          id: "CVE-2023-22794",
          description: "SQL Injection Vulnerability via ActiveRecord comments",
          severity: "critical",
          cvss: 9.8,
          note: "Improper sanitization of comments allowed SQL injection via string interpolation"
        },
        %{
          id: "CVE-2019-5420", 
          description: "File Content Disclosure in Action View",
          severity: "high",
          cvss: 7.5,
          note: "Could expose database configuration files containing credentials"
        },
        %{
          id: "CVE-2019-5418",
          description: "File Content Disclosure in Action View",
          severity: "high",
          cvss: 7.5,
          note: "Path traversal vulnerability that could expose source code with SQL injection"
        },
        %{
          id: "CVE-2013-0156",
          description: "ActiveSupport XML and YAML deserialization",
          severity: "critical",
          cvss: 10.0,
          note: "Remote code execution that often combined with SQL injection for persistence"
        }
      ],
      detection_notes: """
      This pattern detects SQL injection via string interpolation by looking for:
      
      **ActiveRecord Method Patterns:**
      - .where(), .joins(), .order(), .group(), .having() with string arguments containing #{}
      - .find_by_sql() with interpolated strings
      - .select(), .from() clauses with dynamic content
      
      **Database Connection Patterns:**
      - ActiveRecord::Base.connection.execute() with interpolated strings
      - Direct database connection methods with SQL keywords and interpolation
      
      **SQL Keyword Detection:**
      - Patterns that match SQL keywords (SELECT, INSERT, UPDATE, DELETE) followed by interpolation
      - This helps catch raw SQL execution that bypasses ActiveRecord
      
      **False Positive Considerations:**
      - Static strings without user input (acceptable but should be reviewed)
      - Interpolation of safe, developer-controlled values (still risky practice)
      - Comments and documentation containing example code
      - Test files and fixtures (excluded by AST enhancement)
      
      **Limitations:**
      - Cannot detect all forms of dynamic SQL construction
      - May miss complex string building across multiple lines
      - Template literals and heredocs require separate patterns
      """,
      safe_alternatives: [
        "Parameter binding: User.where('name = ?', params[:name])",
        "Hash conditions: User.where(name: params[:name])",
        "Named parameters: User.where('name = :name', name: params[:name])",
        "ActiveRecord methods: User.find_by(name: params[:name])",
        "Arel for complex queries: User.where(User.arel_table[:name].eq(params[:name]))",
        "Sanitization helpers: User.where('name = %s', ActiveRecord::Base.sanitize_sql(params[:name]))",
        "Strong parameters: Only permit expected attributes in controllers",
        "Input validation: Validate and whitelist all user inputs before database operations"
      ],
      additional_context: %{
        common_mistakes: [
          "Believing that validation elsewhere makes interpolation safe",
          "Using interpolation for 'trusted' values like column names (still risky)",
          "Thinking that ActiveRecord methods automatically sanitize string arguments",
          "Using interpolation in development with plans to 'fix later'",
          "Assuming internal/admin interfaces don't need SQL injection protection",
          "Interpolating arrays or objects without proper conversion",
          "Using string interpolation for LIMIT, OFFSET, or ORDER BY clauses"
        ],
        secure_patterns: [
          "User.where(email: params[:email], status: 'active')",
          "User.where('created_at > ?', 1.week.ago)",
          "User.where('name ILIKE ?', \"%\#{params[:search]}%\")",
          "User.joins(:posts).where(posts: { status: 'published' })",
          "User.order(params[:sort_column]&.to_sym || :created_at)",
          "scope :by_status, ->(status) { where(status: status) }"
        ],
        rails_specific: %{
          safe_methods: [
            "where(hash): Always safe with hash arguments",
            "find_by(attributes): Safe for simple attribute lookups", 
            "joins(symbol): Safe when using association names",
            "order(symbol): Safe when using column symbols",
            "group(symbol): Safe when using column symbols"
          ],
          dangerous_methods: [
            "where(string): Dangerous if string contains user input",
            "joins(string): Dangerous with user-controlled join conditions",
            "order(string): Dangerous for dynamic sorting with user input",
            "find_by_sql(string): Always dangerous if user input is interpolated",
            "connection.execute(string): Direct SQL execution, always dangerous"
          ],
          mitigation_strategies: [
            "Use strong parameters to whitelist allowed inputs",
            "Create scopes for complex queries instead of building SQL strings",
            "Use Arel for programmatic query building",
            "Validate column names against a whitelist for dynamic sorting",
            "Use Rails' built-in sanitization methods when raw SQL is necessary"
          ]
        }
      }
    }
  end
  
  @doc """
  Returns AST enhancement rules to reduce false positives.
  
  This enhancement helps distinguish between actual SQL injection vulnerabilities
  and safe string interpolation practices.
  
  ## Examples
  
      iex> enhancement = Rsolv.Security.Patterns.Ruby.SqlInjectionInterpolation.ast_enhancement()
      iex> Map.keys(enhancement) |> Enum.sort()
      [:ast_rules, :confidence_rules, :context_rules, :min_confidence]
      
      iex> enhancement = Rsolv.Security.Patterns.Ruby.SqlInjectionInterpolation.ast_enhancement()
      iex> enhancement.min_confidence
      0.7
  """
  @impl true
  def ast_enhancement do
    %{
      ast_rules: %{
        node_type: "CallExpression",
        method_names: [
          "where", "joins", "order", "group", "having", "select", "from",
          "find_by_sql", "execute", "count", "sum", "update_all", "delete_all"
        ],
        receiver_analysis: %{
          check_activerecord_context: true,
          database_classes: ["ActiveRecord::Base", "ApplicationRecord"],
          connection_methods: ["connection", "execute"]
        },
        argument_analysis: %{
          check_string_interpolation: true,
          sql_keyword_detection: true,
          interpolation_pattern: ~r/#\{[^}]+\}/,
          dangerous_keywords: ["SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "ALTER"]
        }
      },
      context_rules: %{
        exclude_paths: [
          ~r/test/,
          ~r/spec/,
          ~r/fixtures/,
          ~r/examples/,
          ~r/seed/,
          ~r/migration/
        ],
        check_sql_context: true,
        safe_patterns: [
          "?", ":named_param", "ActiveRecord::Base.sanitize_sql",
          "quote", "quote_string", "sanitize"
        ],
        dangerous_sources: [
          "params", "request", "cookies", "session", "ENV",
          "gets", "ARGV", "user_input", "form_data"
        ],
        framework_methods: %{
          activerecord_safe: ["where", "find_by", "joins", "order", "group"],
          activerecord_dangerous: ["find_by_sql", "execute", "connection.execute"],
          requires_special_attention: ["where", "joins", "order", "group", "having"]
        }
      },
      confidence_rules: %{
        base: 0.6,
        adjustments: %{
          "contains_sql_keywords" => 0.3,
          "uses_params_or_request" => 0.4,
          "in_activerecord_context" => 0.2,
          "has_dangerous_method" => 0.3,
          "uses_connection_execute" => 0.5,
          "contains_safe_patterns" => -0.8,
          "uses_parameterized_query" => -1.0,
          "in_test_code" => -0.9,
          "static_interpolation_only" => -0.5,
          "uses_sanitization" => -0.7
        }
      },
      min_confidence: 0.7
    }
  end
end
