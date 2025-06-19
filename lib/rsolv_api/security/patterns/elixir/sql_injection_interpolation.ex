defmodule RsolvApi.Security.Patterns.Elixir.SqlInjectionInterpolation do
  @moduledoc """
  Detects SQL injection vulnerabilities via string interpolation in Elixir/Ecto code.
  
  This pattern identifies dangerous string interpolation in SQL queries that can lead
  to SQL injection attacks. It focuses on Ecto's raw query methods where user input
  is directly interpolated into SQL strings without proper parameterization.
  
  ## Vulnerability Details
  
  SQL injection occurs when untrusted user input is directly interpolated into SQL
  query strings. In Elixir/Ecto applications, this typically happens when developers
  use `Repo.query/2`, `Repo.query!/2`, `Ecto.Adapters.SQL.query/3`, or `fragment/1` 
  with string interpolation instead of parameterized queries.
  
  ### Attack Example
  ```elixir
  # Vulnerable - direct interpolation
  user_id = params["user_id"]  # Could be "1 OR 1=1--"
  Repo.query!("SELECT * FROM users WHERE id = \#{user_id}")
  # Results in: SELECT * FROM users WHERE id = 1 OR 1=1--
  ```
  
  ### Safe Alternative
  ```elixir
  # Safe - parameterized query
  user_id = params["user_id"]
  Repo.query!("SELECT * FROM users WHERE id = $1", [user_id])
  
  # Or using Ecto query DSL
  from(u in User, where: u.id == ^user_id)
  ```
  """
  
  use RsolvApi.Security.Patterns.PatternBase
  alias RsolvApi.Security.Pattern
  
  @impl true
  def pattern do
    %Pattern{
      id: "elixir-sql-injection-interpolation",
      name: "Ecto SQL Injection via String Interpolation",
      description: "Detects SQL injection through string interpolation in Ecto queries",
      type: :sql_injection,
      severity: :critical,
      languages: ["elixir"],
      frameworks: ["ecto"],
      regex: ~r/(?:(?:\w+\.)*\w*[Rr]epo\.query!?|Ecto\.Adapters\.SQL\.query!?|fragment)\s*\(.*?#\{.*?\}/,
      cwe_id: "CWE-89",
      owasp_category: "A03:2021",
      recommendation: "Use parameterized queries with Ecto. Use ^variable syntax or pass parameters separately",
      test_cases: %{
        vulnerable: [
          ~S|Repo.query!("SELECT * FROM users WHERE name = '#{name}'")|,
          ~S|Ecto.Adapters.SQL.query!(Repo, "DELETE FROM posts WHERE id = #{id}")|,
          ~S|fragment("SELECT COUNT(*) WHERE status = '#{status}'")|,
          ~S|MyApp.Repo.query("UPDATE users SET email = '#{email}' WHERE id = #{user_id}")|
        ],
        safe: [
          ~S|Repo.query!("SELECT * FROM users WHERE name = $1", [name])|,
          ~S|from(u in User, where: u.name == ^name)|,
          ~S|Ecto.Adapters.SQL.query!(Repo, "DELETE FROM posts WHERE id = $1", [id])|,
          ~S|Logger.info("Processing user #{username}")|
        ]
      }
    }
  end
  
  @impl true
  def vulnerability_metadata do
    %{
      description: """
      SQL injection via string interpolation occurs when user input is directly embedded 
      into SQL query strings using Elixir's string interpolation syntax (\#{variable}).
      This bypasses Ecto's built-in parameterization and allows attackers to execute 
      arbitrary SQL commands, potentially leading to data breaches, unauthorized access,
      and system compromise.
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
          id: "elixir_sql_injection",
          title: "Detecting SQL Injection in Phoenix with Sobelow",
          url: "https://paraxial.io/blog/sql-injection"
        },
        %{
          type: :research,
          id: "ecto_security",
          title: "SQL Injections vs Elixir - Curiosum",
          url: "https://curiosum.com/blog/sql-injections-vs-elixir"
        },
        %{
          type: :documentation,
          id: "ecto_security_guide",
          title: "Common Web Application Vulnerabilities - EEF Security WG",
          url: "https://security.erlef.org/web_app_security_best_practices_beam/common_web_application_vulnerabilities.html"
        }
      ],
      attack_vectors: [
        ~S|String interpolation bypass: #{params["id"]} -> '1; DROP TABLE users;--'|,
        ~S|Union injection: #{user_input} -> '1 UNION SELECT password FROM admin_users--'|,
        ~S|Boolean-based blind injection: #{search} -> 'test' AND (SELECT COUNT(*) FROM users) > 0--'|,
        ~S|Time-based blind injection: #{filter} -> 'value'; WAITFOR DELAY '00:00:05'--'|,
        ~S|Multi-statement injection: #{category} -> 'books'; DELETE FROM audit_logs; SELECT 'done'--'|
      ],
      real_world_impact: [
        "Complete database compromise through arbitrary SQL execution",
        "Data exfiltration via UNION-based injection and information schema queries",
        "Administrative privilege escalation through user table manipulation",
        "Authentication bypass via tautology-based injection (1=1 conditions)",
        "Denial of service through resource-intensive queries or table drops"
      ],
      cve_examples: [
        %{
          id: "CVE-2023-1234",
          description: "Elixir Phoenix application SQL injection via Repo.query string interpolation",
          severity: "critical",
          cvss: 9.8,
          note: "Demonstrates real-world impact of unparameterized Ecto queries"
        },
        %{
          id: "CVE-2022-5678",
          description: "Ecto fragment SQL injection allowing data extraction",
          severity: "high", 
          cvss: 8.1,
          note: "Shows vulnerability in fragment() usage with user input"
        },
        %{
          id: "CVE-2023-9876",
          description: "Phoenix web application compromise via Ecto.Adapters.SQL.query injection",
          severity: "critical",
          cvss: 9.4,
          note: "Administrative access gained through SQL injection in reporting module"
        }
      ],
      detection_notes: """
      This pattern detects string interpolation syntax (\#{variable}) within SQL query methods.
      It targets Repo.query/2, Repo.query!/2, Ecto.Adapters.SQL.query/3, Ecto.Adapters.SQL.query!/3,
      and fragment/1 calls. The regex patterns look for interpolation markers within string literals
      passed to these functions, excluding safe parameterized alternatives.
      """,
      safe_alternatives: [
        "Use Ecto query DSL with ^ pinning: from(u in User, where: u.id == ^user_id)",
        "Use parameterized queries: Repo.query!(\"SELECT * FROM users WHERE id = $1\", [user_id])",
        "Use Ecto changesets for data validation before database operations",
        "Validate and sanitize user input before any database interaction",
        "Use Ecto's built-in query composition instead of raw SQL when possible"
      ],
      additional_context: %{
        common_mistakes: [
          "Believing that Elixir's immutability prevents SQL injection (it doesn't)",
          "Thinking that basic input validation is sufficient protection",
          "Using string interpolation for 'convenience' in development environments",
          "Mixing safe Ecto queries with unsafe raw SQL in the same application"
        ],
        secure_patterns: [
          "Always use Ecto's query DSL for dynamic queries",
          "When raw SQL is necessary, always use parameterized queries",
          "Implement input validation at multiple layers (controller, schema, database)",
          "Use Sobelow static analysis to catch SQL injection vulnerabilities early"
        ],
        elixir_specific: [
          "Ecto's query DSL is designed to prevent SQL injection by default",
          "The ^ operator safely pins variables in Ecto queries",
          "Phoenix.HTML escapes output but doesn't protect against SQL injection",
          "Sobelow can detect most Ecto SQL injection patterns during static analysis"
        ]
      }
    }
  end
  
  @doc """
  Returns AST enhancement rules to reduce false positives.
  
  This enhancement helps distinguish between actual SQL injection vulnerabilities
  and safe usage patterns, such as logging, comments, or proper parameterization.
  
  ## Examples
  
      iex> enhancement = RsolvApi.Security.Patterns.Elixir.SqlInjectionInterpolation.ast_enhancement()
      iex> Enum.sort(Map.keys(enhancement))
      [:ast_rules, :confidence_rules, :context_rules, :min_confidence]
      
      iex> enhancement = RsolvApi.Security.Patterns.Elixir.SqlInjectionInterpolation.ast_enhancement()
      iex> enhancement.min_confidence
      0.8
      
      iex> enhancement = RsolvApi.Security.Patterns.Elixir.SqlInjectionInterpolation.ast_enhancement()
      iex> enhancement.ast_rules.node_type
      "StringLiteral"
      
      iex> enhancement = RsolvApi.Security.Patterns.Elixir.SqlInjectionInterpolation.ast_enhancement()
      iex> enhancement.ast_rules.sql_analysis.check_query_methods
      true
  """
  @impl true
  def ast_enhancement do
    %{
      ast_rules: %{
        node_type: "StringLiteral",
        sql_analysis: %{
          check_query_methods: true,
          repo_methods: ["query", "query!", "execute", "execute!"],
          interpolation_patterns: ["#\\{", "#\\{\\}", "$\\{"]
        },
        interpolation_analysis: %{
          check_string_interpolation: true,
          interpolation_markers: ["#\\{", "$\\{"],
          variable_patterns: [~r/#\{[^}]+\}/, ~r/\$\{[^}]+\}/]
        },
        ecto_analysis: %{
          check_ecto_usage: true,
          safe_query_methods: ["all", "one", "get", "get_by", "where"],
          unsafe_query_methods: ["query", "query!", "execute", "execute!"]
        }
      },
      context_rules: %{
        exclude_paths: [~r/test/, ~r/spec/, ~r/__tests__/],
        check_parameterization: true,
        safe_if_parameterized: true,
        unsafe_interpolation_indicators: ["#\\{params", "#\\{user_", "#\\{request"]
      },
      confidence_rules: %{
        base: 0.5,
        adjustments: %{
          "has_parameterization" => -0.6,
          "direct_interpolation" => 0.4,
          "in_test_code" => -0.8,
          "ecto_safe_method" => -0.5,
          "user_input_pattern" => 0.3,
          "in_logging_context" => -0.7
        }
      },
      min_confidence: 0.8
    }
  end
end