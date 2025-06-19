defmodule RsolvApi.Security.Patterns.Elixir.HardcodedSecrets do
  @moduledoc """
  Hardcoded Secrets vulnerability pattern for Elixir applications.

  This pattern detects hardcoded secrets, credentials, API keys, and other sensitive
  values embedded directly in source code, which poses significant security risks.

  ## Vulnerability Details

  Hardcoded secrets occur when sensitive information is stored directly in source code:
  - API keys and tokens embedded in module attributes or variables
  - Database passwords in connection strings
  - Encryption keys and cryptographic secrets
  - Authentication tokens and credentials
  - Private keys and certificates stored as strings

  ## Technical Impact

  Security risks through:
  - Unauthorized access to external services and APIs
  - Data breaches through compromised database credentials
  - Financial losses from API abuse and unauthorized service usage
  - Privilege escalation through exposed authentication tokens
  - Cryptographic compromise via exposed encryption keys

  ## Examples

  Vulnerable patterns:
  ```elixir
  # VULNERABLE - hardcoded API key
  @api_key "sk_live_abcd1234efgh5678"
  
  # VULNERABLE - hardcoded database password
  database_url = "postgres://user:secret123@localhost/myapp"
  
  # VULNERABLE - hardcoded JWT secret
  def get_jwt_secret, do: "my-super-secret-jwt-key-12345"
  
  # VULNERABLE - hardcoded encryption key
  @encryption_key "32charencryptionkey123456789012"
  
  # VULNERABLE - hardcoded AWS credentials
  @aws_access_key "AKIAIOSFODNN7EXAMPLE"
  ```

  Safe alternatives:
  ```elixir
  # SAFE - environment variable usage
  @api_key System.get_env("API_KEY")
  
  # SAFE - application configuration
  secret_key = Application.get_env(:myapp, :secret_key)
  
  # SAFE - runtime configuration
  database_url = System.fetch_env!("DATABASE_URL")
  
  # SAFE - config files with runtime secrets
  config :myapp, :encryption_key, System.get_env("ENCRYPTION_KEY")
  
  # SAFE - using Phoenix secret key base
  config :myapp, MyAppWeb.Endpoint,
    secret_key_base: System.get_env("SECRET_KEY_BASE")
  ```

  ## Attack Scenarios

  1. **Source Code Exposure**: Attackers gain access to hardcoded credentials through
     version control systems, public repositories, or leaked source code

  2. **API Abuse**: Exposed API keys allow attackers to make unauthorized requests
     and potentially exhaust service quotas or access sensitive data

  3. **Database Compromise**: Hardcoded database credentials enable direct database
     access, bypassing application security controls

  4. **Service Impersonation**: Authentication tokens allow attackers to impersonate
     the application and access protected resources

  ## References

  - CWE-798: Use of Hard-coded Credentials
  - OWASP Top 10 2021 - A02: Cryptographic Failures
  - OWASP Mobile Top 10 - M10: Extraneous Functionality
  - NIST SP 800-53 - IA-5: Authenticator Management
  """

  use RsolvApi.Security.Patterns.PatternBase

  @impl true
  def pattern do
    %RsolvApi.Security.Pattern{
      id: "elixir-hardcoded-secrets",
      name: "Hardcoded Secrets",
      description: "Sensitive credentials and secrets should not be hardcoded in source code",
      type: :hardcoded_secret,
      severity: :critical,
      languages: ["elixir"],
      frameworks: ["phoenix"],
      regex: [
        # Module attributes with secrets (exclude lines starting with #)
        ~r/^[^#]*@(?:api_key|secret|password|token|key|credential|auth|db_password|encryption_key)\s+["'][^"']{8,}["']/,
        # Variable assignments with secrets (exclude lines starting with #)
        ~r/^[^#]*(?:secret_key|password|token|api_key|private_key|auth_token|access_key|encryption_key|jwt_secret)\s*=\s*["'][^"']{8,}["']/,
        # Database URLs with embedded credentials (exclude lines starting with #)
        ~r/^[^#]*database_url\s*=\s*["'][^"']*:\/\/[^"']*:[^"']*@[^"']*["']/,
        # Common API key patterns (exclude lines starting with #)
        ~r/^[^#]*["'][a-zA-Z0-9_-]*(?:sk_live|pk_test|ghp_|xoxb-|AIza|AKIA)[a-zA-Z0-9_-]{16,}["']/,
        # Function definitions returning secrets (handle def/defp, get_api_key, handle do:, handle data structures)
        ~r/^[^#]*defp?\s+(?:get_api_key|.*(?:secret|password|token|auth|api_key|key)).*do\s*:?\s*.*["'][^"']{8,}["']/,
        # GCP and GitHub patterns specifically (exclude lines starting with #)
        ~r/^[^#]*["'](?:AIza|ghp_)[a-zA-Z0-9_-]{20,}["']/,
        # Elixir keyword list with password (exclude lines starting with #)
        ~r/^[^#]*password:\s*["'][^"']{8,}["']/
      ],
      cwe_id: "CWE-798",
      owasp_category: "A02:2021",
      recommendation: "Use environment variables or runtime configuration to manage secrets securely",
      test_cases: %{
        vulnerable: [
          ~S|@api_key "sk_live_abcd1234efgh5678"|,
          ~S|secret_key = "very_secret_password_12345"|,
          ~S|def get_api_key, do: "sk_test_abcdef1234567890"|,
          ~S|database_url = "postgres://user:secret123@localhost/myapp"|
        ],
        safe: [
          ~S|@api_key System.get_env("API_KEY")|,
          ~S|secret_key = Application.get_env(:myapp, :secret_key)|,
          ~S|password = System.fetch_env!("DATABASE_PASSWORD")|,
          ~S|config :myapp, secret_key_base: System.get_env("SECRET_KEY_BASE")|
        ]
      }
    }
  end

  @impl true
  def vulnerability_metadata do
    %{
      attack_vectors: """
      1. source code exposure through version control systems and public repositories
      2. Financial losses through API abuse using exposed service keys
      3. Database compromise via hardcoded connection credentials
      4. Service impersonation using embedded authentication tokens
      """,
      business_impact: """
      Critical: Hardcoded secrets can lead to:
      - financial losses from unauthorized API usage and service abuse
      - Data breaches through compromised database and service access
      - Regulatory compliance violations and potential fines
      - Reputation damage from security incidents and customer data exposure
      - Legal liability from inadequate protection of sensitive information
      """,
      technical_impact: """
      Critical: Hardcoded credentials enable:
      - unauthorized access to databases, APIs, and external services
      - Privilege escalation through exposed authentication mechanisms
      - Cryptographic compromise via exposed encryption keys and secrets
      - Service disruption through credential abuse and quota exhaustion
      - Data exfiltration through direct access to protected resources
      """,
      likelihood: "High: Common mistake in development without proper secret management",
      cve_examples: [
        "CWE-798: Use of Hard-coded Credentials",
        "CVE-2023-5456: Hardcoded MariaDB credentials allowing database access",
        "CVE-2022-22722: SSH cryptographic key hardcoded enabling privilege escalation",
        "OWASP Top 10 A02:2021 - Cryptographic Failures"
      ],
      compliance_standards: [
        "OWASP Top 10 2021 - A02: Cryptographic Failures",
        "NIST Cybersecurity Framework - PR.AC: Access Control",
        "ISO 27001 - A.9.4: System and application access control",
        "PCI DSS - Requirement 8: Identify and authenticate access"
      ],
      remediation_steps: """
      1. Replace hardcoded secrets with environment variable references
      2. Use application configuration for runtime secret management
      3. Implement proper secret rotation and lifecycle management
      4. Audit codebase for existing hardcoded credentials and remove them
      5. Set up secret management tools like HashiCorp Vault or AWS Secrets Manager
      6. Ensure secrets are excluded from version control systems
      """,
      prevention_tips: """
      1. Use System.get_env/1 and Application.get_env/2 for runtime configuration
      2. Never commit secrets to version control repositories
      3. Implement pre-commit hooks to scan for potential secrets
      4. Use dedicated secret management tools for production environments
      5. Rotate credentials regularly and monitor for unauthorized usage
      6. Separate configuration from code using external config files
      """,
      detection_methods: """
      1. Static code analysis for hardcoded string patterns and credentials
      2. Secret scanning tools and pre-commit hooks
      3. Regular code reviews focusing on configuration and authentication
      4. Automated security scanning in CI/CD pipelines
      5. Runtime monitoring for suspicious API usage patterns
      """,
      safe_alternatives: """
      1. Use environment variables: System.get_env("SECRET_KEY")
      2. Application configuration: Application.get_env(:app, :secret)
      3. Runtime configuration files with external secret injection
      4. Secret management services integrated with deployment systems
      5. Encrypted configuration files with runtime decryption
      6. Container orchestration secret management (Kubernetes secrets)
      """
    }
  end

  @impl true  
  def ast_enhancement do
    %{
      min_confidence: 0.8,
      context_rules: %{
        exclude_test_files: true,
        test_file_patterns: [
          ~r/_test\.exs$/,
          ~r/\/test\//,
          ~r/test_helper\.exs$/
        ],
        secret_indicators: [
          "api_key",
          "secret",
          "password", 
          "token",
          "credential",
          "private_key",
          "auth",
          "bearer"
        ],
        safe_functions: [
          "System.get_env",
          "Application.get_env",
          "System.fetch_env!",
          "Config.get",
          "runtime_config"
        ],
        minimum_length: 8,
        exclude_patterns: [
          "test",
          "example",
          "placeholder",
          "TODO",
          "FIXME"
        ]
      },
      confidence_rules: %{
        base: 0.8,
        adjustments: %{
          test_context_penalty: -0.6,
          environment_usage_penalty: -0.8,
          short_value_penalty: -0.5,
          api_key_pattern_bonus: 0.2,
          database_url_bonus: 0.15,
          private_key_bonus: 0.3
        }
      },
      ast_rules: %{
        node_type: "secrets_analysis",
        string_analysis: %{
          check_string_literals: true,
          check_string_length: true,
          minimum_secret_length: 8,
          api_key_patterns: ["sk_", "pk_", "ghp_", "xoxb-", "AIza", "AKIA"],
          credential_patterns: ["bearer", "basic", "-----begin"]
        },
        variable_analysis: %{
          check_variable_names: true,
          check_assignment_patterns: true,
          secret_variable_names: ["secret", "password", "token", "key", "credential"],
          safe_assignment_patterns: ["System.get_env", "Application.get_env"]
        },
        function_analysis: %{
          check_function_returns: true,
          check_function_names: true,
          secret_function_patterns: ["get_secret", "get_password", "get_token", "get_key"],
          safe_function_patterns: ["fetch_env", "get_env", "runtime_config"]
        }
      }
    }
  end
end