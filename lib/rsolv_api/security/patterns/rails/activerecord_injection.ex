defmodule RsolvApi.Security.Patterns.Rails.ActiverecordInjection do
  @moduledoc """
  ActiveRecord SQL Injection pattern for Rails applications.
  
  This pattern detects SQL injection vulnerabilities through ActiveRecord methods
  that use string interpolation. This is one of the most critical vulnerabilities
  in Rails applications as it can lead to complete database compromise.
  
  ## Background
  
  ActiveRecord provides safe query interfaces, but developers can still introduce
  SQL injection vulnerabilities by:
  - Using string interpolation in query methods
  - Building SQL strings dynamically with user input
  - Using raw SQL methods without proper parameterization
  
  ## Vulnerability Details
  
  The vulnerability occurs when:
  1. User input is directly interpolated into SQL queries
  2. String concatenation is used to build queries
  3. Raw SQL methods are used without parameterization
  4. Dynamic column/table names are interpolated from user input
  
  ## Known CVEs
  
  - CVE-2023-22794: SQL Injection via ActiveRecord comments
  - CVE-2012-2695: ActiveRecord SQL injection via nested query parameters
  - CVE-2012-6496: SQL injection via dynamic finders
  - CVE-2008-4094: SQL injection via limit and offset parameters
  - CVE-2012-2661: SQL injection on Rails affecting GitHub
  
  ## Examples
  
      # Vulnerable - string interpolation
      User.where("name = '\#{params[:name]}'")
      
      # Vulnerable - direct interpolation without quotes
      Post.where("id = \#{params[:id]}")
      
      # Vulnerable - raw SQL methods
      User.find_by_sql("SELECT * FROM users WHERE email = '\#{email}'")
      
      # Safe - parameterized queries
      User.where("name = ?", params[:name])
      User.where(name: params[:name])
  """
  
  use RsolvApi.Security.Patterns.PatternBase
  
  def pattern do
    %RsolvApi.Security.Pattern{
      id: "rails-activerecord-injection",
      name: "ActiveRecord SQL Injection",
      description: "SQL injection through ActiveRecord methods using string interpolation",
      type: :sql_injection,
      severity: :critical,
      languages: ["ruby"],
      frameworks: ["rails"],
      regex: [
        # where with string interpolation
        ~r/\.where\s*\(\s*["'`].*?#\{[^}]+\}/,
        # joins with string interpolation
        ~r/\.joins\s*\(\s*["'`].*?#\{[^}]+\}/,
        # group with string interpolation
        ~r/\.group\s*\(\s*["'`].*?#\{[^}]+\}/,
        # having with string interpolation
        ~r/\.having\s*\(\s*["'`].*?#\{[^}]+\}/,
        # order with string interpolation
        ~r/\.order\s*\(\s*["'`].*?#\{[^}]+\}/,
        # select with string interpolation
        ~r/\.select\s*\(\s*["'`].*?#\{[^}]+\}/,
        # find_by_sql with string interpolation
        ~r/\.find_by_sql\s*\(\s*["'`].*?#\{[^}]+\}/,
        # count_by_sql with string interpolation
        ~r/\.count_by_sql\s*\(\s*["'`].*?#\{[^}]+\}/,
        # exists? with array and string interpolation
        ~r/\.exists\?\s*\(\s*\[["'`].*?#\{[^}]+\}/,
        # update_all with string interpolation
        ~r/\.update_all\s*\(\s*["'`].*?#\{[^}]+\}/,
        # delete_all with string interpolation
        ~r/\.delete_all\s*\(\s*["'`].*?#\{[^}]+\}/
      ],
      cwe_id: "CWE-89",
      owasp_category: "A03:2021",
      recommendation: "Use Rails parameterized queries: where(\"name = ?\", params[:name]) or ActiveRecord hash conditions: where(name: params[:name])",
      test_cases: %{
        vulnerable: [
          "User.where(\"name = '\#{params[:name]}'\")"
        ],
        safe: [
          "User.where(\"name = ?\", params[:name])",
          "User.where(name: params[:name])"
        ]
      }
    }
  end
  
  def vulnerability_metadata do
    %{
      description: """
      SQL injection vulnerabilities in ActiveRecord occur when user-controlled input
      is directly interpolated into SQL queries. This is particularly dangerous because
      ActiveRecord is the primary ORM in Rails applications, handling all database
      interactions. Attackers can exploit these vulnerabilities to read, modify, or
      delete any data in the database, bypass authentication, escalate privileges,
      or even execute commands on the database server in some configurations.
      
      The vulnerability is especially severe because Rails applications often have
      full database access, and successful exploitation can compromise the entire
      application's data integrity and confidentiality.
      """,
      
      attack_vectors: """
      1. **Data Extraction**: ' OR 1=1 UNION SELECT username, password FROM users--
      2. **Authentication Bypass**: admin'-- \\(bypasses password check\\)
      3. **Data Modification**: '; UPDATE users SET admin = true WHERE id = 123--
      4. **Data Deletion**: '; DELETE FROM orders WHERE 1=1--
      5. **Database Schema Discovery**: ' UNION SELECT table_name FROM information_schema.tables--
      6. **Time-based Blind SQLi**: ' OR IF\\(1=1, SLEEP\\(5\\), 0\\)--
      7. **Error-based SQLi**: ' AND 1=CONVERT\\(int, @@version\\)--
      8. **Stacked Queries**: '; EXEC xp_cmdshell\\('net user hacker password /add'\\)--
      """,
      
      business_impact: """
      - Complete data breach exposing all customer and business data
      - Financial losses from fraudulent transactions or data theft
      - Regulatory fines for data protection violations (GDPR, CCPA)
      - Reputation damage and loss of customer trust
      - Business disruption from data corruption or deletion
      - Legal liability from compromised user data
      - Competitive disadvantage from stolen intellectual property
      """,
      
      technical_impact: """
      - Full database read/write access
      - Authentication and authorization bypass
      - Ability to execute arbitrary SQL commands
      - Database server compromise in some configurations
      - Data integrity corruption
      - Audit trail manipulation
      - Potential for lateral movement to other systems
      """,
      
      likelihood: "Very High - String interpolation is a common mistake in Rails applications",
      
      cve_examples: [
        "CVE-2023-22794 - SQL Injection in ActiveRecord via comments parameter",
        "CVE-2012-2695 - ActiveRecord SQL injection via nested query parameters", 
        "CVE-2012-6496 - SQL injection in ActiveRecord dynamic finders",
        "CVE-2012-2661 - GitHub compromised via Rails SQL injection",
        "CVE-2008-4094 - SQL injection via limit and offset parameters in Rails"
      ],
      
      compliance_standards: [
        "OWASP Top 10 2021 - A03: Injection",
        "CWE-89: SQL Injection",
        "PCI DSS 6.5.1 - Injection flaws",
        "NIST SP 800-53 - SI-10 Information Input Validation",
        "ISO 27001 - A.14.2.5 Secure system engineering principles"
      ],
      
      remediation_steps: """
      1. **Use Parameterized Queries (Preferred)**:
         ```ruby
         # Instead of string interpolation
         User.where("name = '\#{params[:name]}'")  # VULNERABLE
         
         # Use placeholder with separate parameter
         User.where("name = ?", params[:name])    # SAFE
         
         # For multiple parameters
         User.where("name = ? AND age > ?", params[:name], params[:age])
         ```
      
      2. **Use Hash Conditions (Recommended)**:
         ```ruby
         # Hash syntax - Rails automatically parameterizes
         User.where(name: params[:name])
         User.where(name: params[:name], active: true)
         
         # For IN clauses
         User.where(status: ['active', 'pending'])
         ```
      
      3. **Use Named Placeholders**:
         ```ruby
         User.where("name = :name AND email = :email", 
                   name: params[:name], 
                   email: params[:email])
         ```
      
      4. **For Dynamic Column Names (Use Allowlist)**:
         ```ruby
         # NEVER do this
         User.order("\#{params[:sort]} DESC")  # VULNERABLE
         
         # Use an allowlist instead
         ALLOWED_SORT_COLUMNS = %w[name created_at updated_at]
         sort_column = ALLOWED_SORT_COLUMNS.include?(params[:sort]) ? 
                      params[:sort] : 'created_at'
         User.order("\#{sort_column} DESC")   # SAFE
         ```
      
      5. **Sanitize When Raw SQL is Necessary**:
         ```ruby
         # Use sanitize_sql_array
         query = ActiveRecord::Base.sanitize_sql_array([
           "SELECT * FROM users WHERE name = ?", params[:name]
         ])
         User.find_by_sql(query)
         
         # Or use connection.quote
         name = ActiveRecord::Base.connection.quote(params[:name])
         User.find_by_sql("SELECT * FROM users WHERE name = \#{name}")
         ```
      """,
      
      prevention_tips: """
      - Never use string interpolation (#\\{\\}) in SQL queries
      - Always use parameterized queries or hash conditions
      - Enable strict parameter filtering in Rails
      - Use static analysis tools like Brakeman
      - Code review all database queries
      - Implement least privilege database access
      - Use stored procedures for complex queries
      - Enable SQL query logging in development
      - Train developers on secure coding practices
      - Regular security audits of database queries
      """,
      
      detection_methods: """
      - Static analysis with Brakeman scanner
      - Manual code review of all ActiveRecord queries
      - Grep for patterns like .where.*#\\{
      - Dynamic testing with SQLMap or similar tools
      - Database query logs analysis
      - Web Application Firewall \\(WAF\\) alerts
      - Penetration testing
      - Automated security scanning in CI/CD
      """,
      
      safe_alternatives: """
      # Safe query building patterns
      
      # 1. Simple where conditions
      User.where(name: params[:name])
      User.where(active: true, role: 'admin')
      
      # 2. Complex conditions with Arel
      users = User.arel_table
      User.where(users[:name].eq(params[:name])
                .and(users[:age].gt(18)))
      
      # 3. Scopes with parameterized queries
      scope :by_name, ->(name) { where(name: name) }
      scope :recent, -> { where('created_at > ?', 1.week.ago) }
      
      # 4. Dynamic queries with sanitization
      def self.search(fields)
        conditions = fields.map do |field, value|
          sanitize_sql_array(["\#{field} = ?", value])
        end.join(" AND ")
        where(conditions)
      end
      
      # 5. Using ActiveRecord query interface
      User.joins(:posts)
          .where(posts: { published: true })
          .where('users.created_at > ?', 1.year.ago)
          .order(created_at: :desc)
      
      # 6. Raw SQL with proper quoting
      connection.select_all(
        sanitize_sql_array([
          "SELECT * FROM users WHERE email = ?", 
          params[:email]
        ])
      )
      """
    }
  end
  
  def ast_enhancement do
    %{
      min_confidence: 0.9,
      
      context_rules: %{
        # Common sources of user input
        input_sources: [
          "params", "request", "cookies", "session",
          "query_params", "form_params", "user_input"
        ],
        
        # ActiveRecord methods vulnerable to SQL injection
        activerecord_methods: [
          "where", "joins", "group", "having", "order",
          "select", "find_by_sql", "count_by_sql",
          "exists?", "update_all", "delete_all", "pluck"
        ],
        
        # Safe patterns to reduce false positives
        safe_patterns: [
          ~r/where\s*\(\s*["']\w+\s*=\s*\?["']\s*,/,
          ~r/where\s*\(\s*:\w+\s*=>/,
          ~r/where\s*\(\s*\w+:\s*/,
          ~r/sanitize_sql/
        ]
      },
      
      confidence_rules: %{
        adjustments: %{
          # Very high confidence for direct user input
          direct_user_input: +0.4,
          # High confidence for params usage
          uses_params: +0.3,
          # Medium confidence for any interpolation
          has_interpolation: +0.2,
          # Lower confidence if parameterized elsewhere
          has_safe_usage_nearby: -0.3,
          # Much lower if in test file
          in_test_file: -0.5,
          # Lower if sanitization present
          uses_sanitization: -0.4,
          # Higher for raw SQL methods
          raw_sql_method: +0.3
        }
      },
      
      ast_rules: %{
        # Detection of string interpolation patterns
        interpolation_detection: %{
          patterns: [
            "StringInterpolation",
            "StringConcat",
            "DynamicString"
          ],
          check_for_user_input: true
        },
        
        # Method call analysis
        method_analysis: %{
          check_receiver: true,
          check_arguments: true,
          trace_variable_flow: true
        },
        
        # SQL query construction patterns
        query_patterns: %{
          dangerous_operators: ["+", "<<", "concat"],
          safe_methods: ["sanitize_sql", "quote", "escape"],
          parameterized_indicators: ["?", ":placeholder"]
        }
      }
    }
  end
  
end

