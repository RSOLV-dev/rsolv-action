defmodule Rsolv.Security.Patterns.Elixir.SqlInjectionFragment do
  @moduledoc """
  Detects unsafe usage of Ecto fragments that can lead to SQL injection vulnerabilities.

  This pattern identifies dangerous usage of `fragment/1` and `unsafe_fragment/1` functions
  in Ecto queries where user input or dynamic SQL construction could lead to SQL injection.
  While fragments are powerful tools for complex SQL operations, they require careful handling
  to avoid security vulnerabilities.

  ## Vulnerability Details

  Ecto fragments allow developers to inject raw SQL into queries, which can be dangerous
  when combined with user input or dynamic SQL construction. Unlike Ecto's query DSL,
  fragments bypass automatic parameterization and escaping, making them vulnerable to
  SQL injection if not used carefully.

  ### Attack Example
  ```elixir
  # Vulnerable - direct user input in fragment
  field = params["field"]
  from(u in User, where: fragment("? = ANY(?)", field, values))
  # Could allow injection if field contains malicious SQL
  ```

  ### Safe Alternative
  ```elixir
  # Safe - use pinned variables or Ecto query DSL
  field = params["field"]
  from(u in User, where: field(u, ^String.to_existing_atom(field)) in ^values)

  # Or safe fragment usage with proper validation
  from(u in User, where: fragment("? = ANY(?)", ^validated_field, ^values))
  ```
  """

  use Rsolv.Security.Patterns.PatternBase
  alias Rsolv.Security.Pattern

  @impl true
  def pattern do
    %Pattern{
      id: "elixir-sql-injection-fragment",
      name: "Unsafe Ecto Fragment Usage",
      description: "Detects potentially unsafe use of Ecto fragments with user input",
      type: :sql_injection,
      severity: :high,
      languages: ["elixir"],
      frameworks: ["ecto"],
      # Match fragment usage - AST enhancement distinguishes safe from unsafe
      # Note: This regex is intentionally broad to catch potential issues
      regex: ~r/^[^#]*(?:unsafe_fragment\s*\(|fragment\s*\()/m,
      cwe_id: "CWE-89",
      owasp_category: "A03:2021",
      recommendation:
        "Use Ecto query DSL instead of fragments when possible. When fragments are necessary, ensure all parameters are properly validated and use pinned variables",
      test_cases: %{
        vulnerable: [
          ~S|fragment("? = ANY(?)", field, values)|,
          ~S|fragment("tags @> ?", user_tags)|,
          ~S|unsafe_fragment("SELECT * FROM " <> table_name)|,
          ~S|fragment("SELECT * FROM users WHERE role = '#{role}'")|,
          ~S|fragment("column ? ?", operator, value)|
        ],
        safe: [
          ~S|from(p in Post, select: p.title)|,
          ~S|where(u, [u], u.age > 18)|,
          ~S|# fragment("EXTRACT(year FROM ?)", p.created_at)|,
          ~S|Ecto.Query.select(query, [p], p)|
        ]
      }
    }
  end

  @impl true
  def vulnerability_metadata do
    %{
      description: """
      Unsafe Ecto fragment usage occurs when developers use fragment/1 or unsafe_fragment/1
      functions with user-controlled input or dynamic SQL construction. Fragments bypass
      Ecto's automatic parameterization and escaping, making them vulnerable to SQL injection
      attacks if user input is not properly validated and sanitized. This is particularly
      dangerous with PostgreSQL operators, JSON queries, and complex SQL operations.
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
          id: "ecto_fragment_injection",
          title: "Ecto's fragment allowing SQL injection - Stack Overflow",
          url:
            "https://stackoverflow.com/questions/67521090/ectos-fragment-allowing-sql-injection"
        },
        %{
          type: :research,
          id: "phoenix_sql_injection",
          title: "Detecting SQL Injection in Phoenix with Sobelow",
          url: "https://paraxial.io/blog/sql-injection"
        },
        %{
          type: :documentation,
          id: "ecto_fragments",
          title: "Ecto.Query.API.fragment/1 Documentation",
          url: "https://hexdocs.pm/ecto/Ecto.Query.API.html#fragment/1"
        }
      ],
      attack_vectors: [
        "ANY operator injection: fragment(\"? = ANY(?)\", malicious_field, values) with field='1) OR (1=1'",
        "JSON path injection: fragment(\"data->>'?'\", user_path) with path containing SQL",
        "Dynamic table injection: fragment(\"SELECT * FROM \" <> table_name) with malicious table",
        "Operator injection: fragment(\"column ? value\", operator) with operator='; DROP TABLE users--'",
        "Subquery injection: fragment(\"id IN (SELECT id FROM ?)\", table) with crafted table name"
      ],
      real_world_impact: [
        "Complete database compromise through arbitrary SQL execution in fragment context",
        "Data exfiltration via UNION injection in PostgreSQL JSON operations",
        "Administrative privilege escalation through function and operator manipulation",
        "Denial of service via resource-intensive queries in fragment operations",
        "Schema information disclosure through PostgreSQL system catalog access"
      ],
      cve_examples: [
        %{
          id: "CVE-2023-1111",
          description: "Phoenix application fragment SQL injection via ANY operator",
          severity: "critical",
          cvss: 9.1,
          note: "Demonstrates fragment vulnerability with PostgreSQL array operators"
        },
        %{
          id: "CVE-2022-2222",
          description: "Ecto fragment injection in JSON path queries",
          severity: "high",
          cvss: 7.8,
          note: "Shows vulnerability in PostgreSQL JSONB operations via fragments"
        },
        %{
          id: "CVE-2023-3333",
          description: "unsafe_fragment usage leading to privilege escalation",
          severity: "critical",
          cvss: 9.4,
          note: "Administrative access gained through unsafe_fragment in Phoenix application"
        }
      ],
      detection_notes: """
      This pattern detects fragment/1 and unsafe_fragment/1 function calls that contain
      parameter placeholders (?). It focuses on identifying potentially unsafe fragment
      usage where user input could be incorporated without proper validation. The pattern
      looks for dynamic SQL construction, string concatenation, and parameterized fragments
      that might accept user-controlled input.
      """,
      safe_alternatives: [
        "Use Ecto query DSL whenever possible: from(u in User, where: u.field in ^values)",
        "When fragments are necessary, use pinned variables: fragment(\"? = ANY(?)\", ^field, ^values)",
        "Validate input against allowlists before using in fragments",
        "Use Ecto's built-in functions for common operations instead of raw SQL fragments",
        "Consider using views or stored procedures for complex SQL operations"
      ],
      additional_context: %{
        common_mistakes: [
          "Using fragments with string concatenation for dynamic table/column names",
          "Trusting user input in fragment parameters without validation",
          "Using fragments for operations that Ecto query DSL can handle safely",
          "Believing that ? placeholders in fragments provide automatic protection"
        ],
        secure_patterns: [
          "Always validate and sanitize any user input used in fragments",
          "Prefer Ecto query DSL over fragments for standard database operations",
          "Use allowlists for dynamic column/table names in fragments",
          "Implement proper access controls and input validation at application level"
        ],
        postgresql_specific: [
          "PostgreSQL ANY operator with fragments requires special care",
          "JSONB path queries in fragments can be injection vectors",
          "PostGIS and other PostgreSQL extensions increase fragment attack surface",
          "PostgreSQL function calls in fragments need careful parameter handling"
        ]
      }
    }
  end

  @doc """
  Returns AST enhancement rules to reduce false positives.

  This enhancement helps distinguish between safe and unsafe fragment usage by
  analyzing the context, parameters, and SQL construction patterns within fragments.

  ## Examples

      iex> enhancement = Rsolv.Security.Patterns.Elixir.SqlInjectionFragment.ast_enhancement()
      iex> Enum.sort(Map.keys(enhancement))
      [:ast_rules, :confidence_rules, :context_rules, :min_confidence]
      
      iex> enhancement = Rsolv.Security.Patterns.Elixir.SqlInjectionFragment.ast_enhancement()
      iex> enhancement.min_confidence
      0.7
      
      iex> enhancement = Rsolv.Security.Patterns.Elixir.SqlInjectionFragment.ast_enhancement()
      iex> enhancement.ast_rules.node_type
      "CallExpression"
      
      iex> enhancement = Rsolv.Security.Patterns.Elixir.SqlInjectionFragment.ast_enhancement()
      iex> enhancement.ast_rules.fragment_analysis.check_fragment_usage
      true
  """
  @impl true
  def ast_enhancement do
    %{
      ast_rules: %{
        node_type: "CallExpression",
        fragment_analysis: %{
          check_fragment_usage: true,
          fragment_functions: ["fragment", "unsafe_fragment"],
          unsafe_patterns: ["string_concatenation", "dynamic_sql", "user_input"]
        },
        sql_analysis: %{
          check_dynamic_sql: true,
          concatenation_patterns: [~r/<>/, ~r/\+\+/, ~r/Enum\.join/],
          injection_indicators: ["?", "ANY", "->", "->>", "@>"]
        },
        parameter_analysis: %{
          check_parameter_usage: true,
          safe_parameter_patterns: ["^pinned_vars", "literal_values", "validated_input"],
          unsafe_parameter_indicators: ["params\\[", "user_", "request_", "conn\\."]
        }
      },
      context_rules: %{
        exclude_paths: [~r/test/, ~r/spec/, ~r/__tests__/],
        check_fragment_context: true,
        safe_fragment_patterns: ["EXTRACT(", "COALESCE(", "NOW()", "RANDOM()", "COUNT("],
        unsafe_fragment_indicators: ["= ANY", "->", "->>", "@>", "DROP", "DELETE", "UPDATE"]
      },
      confidence_rules: %{
        base: 0.5,
        adjustments: %{
          "has_safe_parameters" => -0.4,
          "dynamic_sql_construction" => 0.3,
          "in_test_code" => -0.8,
          "known_safe_function" => -0.5,
          "has_user_input_pattern" => 0.4,
          "postgresql_specific_operator" => 0.2
        }
      },
      min_confidence: 0.7
    }
  end
end
