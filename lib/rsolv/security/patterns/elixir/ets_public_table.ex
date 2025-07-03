defmodule Rsolv.Security.Patterns.Elixir.EtsPublicTable do
  @moduledoc """
  Public ETS Table Security Risk vulnerability pattern for Elixir applications.

  This pattern detects potentially dangerous ETS table creation with public access
  that can allow unauthorized processes to read and modify sensitive data.

  ## Vulnerability Details

  Public ETS table risks occur when:
  - Creating ETS tables with `:public` access for sensitive data
  - Allowing any process to read/write table contents without authorization
  - Storing authentication tokens, session data, or passwords in public tables
  - Using `:named_table` with `:public` for globally accessible sensitive data
  - Lack of proper access control for shared application state

  ## Technical Impact

  Unauthorized data access and manipulation through:
  - Any process can read sensitive data from public ETS tables
  - Malicious code can modify or delete critical application state
  - Session hijacking through access to authentication tokens
  - Data corruption from uncontrolled concurrent modifications
  - Information disclosure of user credentials or business data

  ## Examples

  Vulnerable patterns:
  ```elixir
  # VULNERABLE - public access to sensitive session data
  :ets.new(:user_sessions, [:public, :named_table])
  
  # VULNERABLE - authentication tokens accessible by any process
  :ets.new(:auth_tokens, [:public, :set])
  
  # VULNERABLE - user data with unrestricted access
  :ets.new(:user_profiles, [:public, :bag, :named_table])
  
  # VULNERABLE - API keys in public table
  :ets.new(:api_keys, [:public])
  ```

  Safe alternatives:
  ```elixir
  # SAFE - protected access (default, owner can write, others can read)
  :ets.new(:cache, [:protected, :named_table])
  
  # SAFE - private access (only owner can read/write)
  :ets.new(:sensitive_data, [:private])
  
  # SAFE - protected with explicit access control
  :ets.new(:user_sessions, [:protected, :set, :named_table])
  
  # SAFE - public only for truly public read-only data
  :ets.new(:public_config, [:public, :read_concurrency])  # With careful consideration
  ```

  ## Attack Scenarios

  1. **Data Theft**: Malicious process reads sensitive user data from public tables
     containing session tokens, passwords, or personal information

  2. **Session Hijacking**: Attacker accesses authentication tokens stored in
     public ETS tables to impersonate legitimate users

  3. **Data Manipulation**: Unauthorized modification of application state,
     user profiles, or configuration data in public tables

  4. **Denial of Service**: Malicious deletion of critical data from public
     tables causing application failures

  ## References

  - Erlang ETS Documentation: https://www.erlang.org/docs/23/man/ets
  - Erlang Thursday - ETS Access Protections: https://www.proctor-it.com/erlang-thursday-ets-introduction-part-4-ets-access-protections/
  - Elixir School - ETS: https://elixirschool.com/en/lessons/storage/ets
  - CWE-732: Incorrect Permission Assignment for Critical Resource
  - OWASP Top 10 2021 - A01: Broken Access Control
  """

  use Rsolv.Security.Patterns.PatternBase

  @impl true
  def pattern do
    %Rsolv.Security.Pattern{
      id: "elixir-ets-public-table",
      name: "Public ETS Table Security Risk",
      description: "ETS tables with public access can be read and modified by any process, exposing sensitive data",
      type: :authentication,
      severity: :medium,
      languages: ["elixir"],
      frameworks: [],
      regex: [
        # Basic public ETS table patterns
        ~r/:ets\.new\s*\([^,]+,\s*\[[^\]]*:public[^\]]*\]/,
        
        # Public with specific table types
        ~r/:ets\.new\s*\([^,]+,\s*\[:public,\s*:set[^\]]*\]/,
        ~r/:ets\.new\s*\([^,]+,\s*\[:public,\s*:bag[^\]]*\]/,
        ~r/:ets\.new\s*\([^,]+,\s*\[:public,\s*:ordered_set[^\]]*\]/,
        ~r/:ets\.new\s*\([^,]+,\s*\[:public,\s*:duplicate_bag[^\]]*\]/,
        
        # Public with named_table (globally accessible)
        ~r/:ets\.new\s*\([^,]+,\s*\[[^\]]*:public[^\]]*:named_table[^\]]*\]/,
        ~r/:ets\.new\s*\([^,]+,\s*\[[^\]]*:named_table[^\]]*:public[^\]]*\]/,
        
        # Various option arrangements with public
        ~r/:ets\.new\s*\([^,]+,\s*\[:named_table,\s*:public[^\]]*\]/,
        ~r/:ets\.new\s*\([^,]+,\s*\[:public\s*\|\s*\w+\]/,
        
        # Sensitive table names with public access
        ~r/:ets\.new\s*\(:[a-z_]*(?:session|auth|token|password|key|user|credential)[a-z_]*,\s*\[[^\]]*:public[^\]]*\]/i
      ],
      cwe_id: "CWE-732",
      owasp_category: "A01:2021",
      recommendation: "Use :protected (default) or :private access for sensitive data. Reserve :public only for truly public read-only data.",
      test_cases: %{
        vulnerable: [
          ~S|:ets.new(:sessions, [:public, :named_table])|,
          ~S|:ets.new(:auth_tokens, [:public, :set])|,
          ~S|:ets.new(:user_data, [:public])|,
          ~S|:ets.new(:api_keys, [:public, :bag])|
        ],
        safe: [
          ~S|:ets.new(:sessions, [:protected, :named_table])|,
          ~S|:ets.new(:cache, [:private])|,
          ~S|:ets.new(:data, [:protected])|,
          ~S|:ets.new(:config, [])|
        ]
      }
    }
  end

  @impl true
  def vulnerability_metadata do
    %{
      attack_vectors: """
      1. Data Theft: Unauthorized access to sensitive data in public ETS tables
      2. Session Hijacking: Access to authentication tokens for user impersonation  
      3. Data Manipulation: Unauthorized modification of application state and user data
      4. Information Disclosure: Reading confidential business data or user credentials
      """,
      business_impact: """
      Medium: Public ETS tables can lead to:
      - Data breaches exposing user personal information
      - Unauthorized access to business-critical data
      - Compliance violations (GDPR, HIPAA, SOX)
      - Loss of customer trust and reputation damage
      - Financial losses from security incidents
      """,
      technical_impact: """
      Medium: Unrestricted ETS access can cause:
      - Any process can read sensitive data without authorization
      - Malicious modification or deletion of critical application state
      - Session token theft enabling account takeovers
      - Data corruption from uncontrolled concurrent access
      - Potential escalation to more serious vulnerabilities
      """,
      likelihood: "Medium: Common when developers don't understand ETS access control implications",
      cve_examples: [
        "CWE-732: Incorrect Permission Assignment for Critical Resource",
        "OWASP Top 10 A01:2021 - Broken Access Control",
        "General pattern in distributed Erlang/Elixir applications with shared state"
      ],
      compliance_standards: [
        "OWASP Top 10 2021 - A01: Broken Access Control",
        "NIST Cybersecurity Framework - PR.AC: Access Control",
        "ISO 27001 - A.9.1: Access Control Management"
      ],
      remediation_steps: """
      1. Change public ETS tables to :protected or :private access
      2. Review all ETS table creation for appropriate access levels
      3. Implement proper authorization checks before table access
      4. Use :private for sensitive data that only the owner should access
      5. Reserve :public only for truly public, non-sensitive data
      6. Add access control validation in table operations
      """,
      prevention_tips: """
      1. Use :protected access by default (allows owner write, others read)
      2. Use :private for highly sensitive data (owner-only access)
      3. Never store credentials, tokens, or PII in public tables
      4. Review table access patterns during code reviews
      5. Implement principle of least privilege for ETS access
      6. Document and validate access control requirements
      """,
      detection_methods: """
      1. Static code analysis for ETS table creation patterns
      2. Code review focusing on data sensitivity and access patterns
      3. Dynamic analysis of table access permissions at runtime
      4. Security testing with unauthorized access attempts
      5. Audit logs of ETS table operations and access patterns
      """,
      safe_alternatives: """
      1. Use :protected access for shared readable data (default)
      2. Use :private access for sensitive owner-only data
      3. Implement application-level access control on top of ETS
      4. Use process-based authorization before table operations
      5. Consider alternative data storage with built-in access control
      6. Use message passing for controlled data access patterns
      """
    }
  end

  @impl true  
  def ast_enhancement do
    %{
      min_confidence: 0.7,
      context_rules: %{
        exclude_test_files: true,
        test_file_patterns: [
          ~r/_test\.exs$/,
          ~r/\/test\//,
          ~r/test_helper\.exs$/
        ],
        sensitive_table_names: [
          "session",
          "auth",
          "token",
          "password",
          "key",
          "user", 
          "credential",
          "api_key",
          "secret"
        ],
        check_table_name_sensitivity: true,
        public_indicators: [
          ":public"
        ],
        safe_access_levels: [
          ":protected",
          ":private"
        ]
      },
      confidence_rules: %{
        base: 0.7,
        adjustments: %{
          test_context_penalty: -0.5,
          sensitive_data_bonus: 0.2,
          named_table_bonus: 0.1,
          cache_context_penalty: -0.2,
          read_only_penalty: -0.3
        }
      },
      ast_rules: %{
        node_type: "ets_analysis",
        ets_analysis: %{
          check_table_creation: true,
          check_access_level: true,
          table_functions: [":ets.new"],
          public_access_pattern: ":public",
          safe_access_patterns: [":protected", ":private"]
        },
        access_control_analysis: %{
          check_sensitivity: true,
          check_named_tables: true,
          sensitive_keywords: ["session", "auth", "token", "password", "user"],
          named_table_indicator: ":named_table"
        },
        context_analysis: %{
          check_data_type: true,
          check_usage_pattern: true,
          acceptable_public_uses: ["cache", "config", "stats", "metrics"],
          dangerous_public_uses: ["session", "auth", "user", "password", "token"]
        },
        table_analysis: %{
          check_table_type: true,
          check_concurrency_options: true,
          table_types: [":set", ":bag", ":ordered_set", ":duplicate_bag"],
          concurrency_options: [":read_concurrency", ":write_concurrency"]
        }
      }
    }
  end
end
