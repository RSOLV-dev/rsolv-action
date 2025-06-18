defmodule RsolvApi.Security.Patterns.Ruby.HardcodedSecrets do
  @moduledoc """
  Pattern for detecting hardcoded secrets, passwords, API keys, and credentials in Ruby applications.
  
  This pattern identifies when sensitive credentials are hardcoded directly in source code
  instead of being stored securely in environment variables, key management systems,
  or encrypted configuration files.
  
  ## Vulnerability Details
  
  Hardcoded credentials represent one of the most dangerous security vulnerabilities because
  they expose sensitive information directly in source code. This practice puts applications
  at extreme risk since source code is often:
  - Stored in version control systems (Git repositories)
  - Shared among development teams
  - Deployed to multiple environments
  - Potentially exposed through code leaks or breaches
  
  ### Attack Example
  ```ruby
  # Vulnerable credential storage
  class DatabaseConfig
    PASSWORD = "super_secret_pass123"
    API_KEY = "sk_live_abcdef1234567890"
    
    def connect
      ActiveRecord::Base.establish_connection(
        adapter: "postgresql",
        host: "localhost",
        username: "admin",
        password: PASSWORD  # Hardcoded password exposed!
      )
    end
  end
  
  # Attack: Source code access reveals credentials
  # Result: Complete system compromise
  ```
  """
  
  use RsolvApi.Security.Patterns.PatternBase
  alias RsolvApi.Security.Pattern
  
  @impl true
  def pattern do
    %Pattern{
      id: "ruby-hardcoded-secrets",
      name: "Hardcoded Secrets",
      description: "Detects hardcoded API keys, passwords, and secrets",
      type: :sensitive_data_exposure,
      severity: :critical,
      languages: ["ruby"],
      regex: [
        ~r/(?:password|pwd|pass)\s*=\s*['\"][\w\-!@#$%^&*()+={}[\]:;<>,.?~]{4,}['\"]/i,
        ~r/(?:api_key|apikey|key)\s*=\s*['\"][\w\-]{8,}['\"]/i,
        ~r/(?:secret(?:_key)?|secret)\s*=\s*['\"][\w\-!@#$%^&*()+={}[\]:;<>,.?~]{8,}['\"]/i,
        ~r/AWS_ACCESS_KEY_ID\s*=\s*['\"]AKIA[0-9A-Z]{16}['\"]/,
        ~r/AWS_SECRET_ACCESS_KEY\s*=\s*['\"][A-Za-z0-9\/+=]{40}['\"]/,
        ~r/(?:private_key|privatekey)\s*=\s*['\"][\w\-\s+=]+['\"]/i,
        ~r/(?:auth_token|access_token|bearer_token|session_token)\s*=\s*['\"][\w\-\.\s]+['\"]/i,
        ~r/(?:database_url|db_url)\s*=\s*['\"](?:postgres|mysql|mongodb):\/\/[\w\-.:@\/]+['\"]/i,
        ~r/(?:redis_url|redis_password)\s*=\s*['\"]redis:\/\/[\w\-.:@\/]+['\"]/i,
        ~r/-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----/,
        ~r/(?:github_token|gh_token)\s*=\s*['\"](?:ghp_|gho_|ghu_|ghs_|ghr_)[\w]{20,}['\"]/i,
        ~r/(?:stripe_key|sk_|pk_)\s*=\s*['\"](?:sk_|pk_)(?:test_|live_)[\w]{24,}['\"]/i
      ],
      default_tier: :ai,
      cwe_id: "CWE-798",
      owasp_category: "A07:2021",
      recommendation: "Use environment variables or secure key management systems",
      test_cases: %{
        vulnerable: [
          ~S|password = "super_secret123"|,
          ~S|API_KEY = "sk_test_123456"|,
          ~S|config.secret_key = "hardcoded_secret"|,
          ~S|AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"|,
          ~S|private_key = "-----BEGIN PRIVATE KEY-----"|,
          ~S|auth_token = "Bearer abcdef123456"|,
          ~S|database_url = "postgres://user:pass@host:5432/db"|
        ],
        safe: [
          ~S|password = ENV['DATABASE_PASSWORD']|,
          ~S|api_key = Rails.application.credentials.api_key|,
          ~S|secret = KeyVault.fetch('app_secret')|,
          ~S|config.password = SecureRandom.hex(16)|,
          ~S|password = gets.chomp|,
          ~S|# password = "commented_out"|,
          ~S|ENV['API_KEY'] = user_input|
        ]
      }
    }
  end
  
  @impl true
  def vulnerability_metadata do
    %{
      description: """
      Hardcoded credentials are sensitive information such as passwords, API keys, 
      encryption keys, or access tokens that are embedded directly in source code
      rather than stored securely. This practice creates significant security risks
      because:
      
      **Primary Security Risks:**
      - **Source Code Exposure**: Credentials become visible to anyone with code access
      - **Version Control History**: Secrets persist in Git history even after removal
      - **Environment Propagation**: Same credentials used across dev/staging/production
      - **No Rotation Capability**: Hardcoded secrets cannot be easily rotated
      - **Privilege Escalation**: Exposed credentials often have elevated permissions
      
      **Common Hardcoded Credential Types:**
      - Database passwords and connection strings
      - API keys and authentication tokens
      - Cryptographic keys and certificates
      - Cloud service credentials (AWS, Azure, GCP)
      - Third-party service credentials (Stripe, GitHub, etc.)
      - JWT signing secrets and session keys
      
      **Attack Vectors:**
      Attackers can discover hardcoded credentials through:
      - Public code repositories (GitHub, GitLab leaks)
      - Source code analysis and reverse engineering
      - Memory dumps and configuration file access
      - CI/CD pipeline artifacts and logs
      - Docker images and container layers
      - Error messages and debug output
      
      **Real-World Impact:**
      The CVE-2013-0156 Rails vulnerability demonstrated how hardcoded secret tokens
      combined with other vulnerabilities can lead to complete system compromise.
      When Rails applications used predictable or hardcoded secret_token values,
      attackers could forge session cookies and achieve remote code execution.
      """,
      references: [
        %{
          type: :cwe,
          id: "CWE-798",
          title: "Use of Hard-coded Credentials",
          url: "https://cwe.mitre.org/data/definitions/798.html"
        },
        %{
          type: :cwe,
          id: "CWE-321",
          title: "Use of Hard-coded Cryptographic Key",
          url: "https://cwe.mitre.org/data/definitions/321.html"
        },
        %{
          type: :owasp,
          id: "A07:2021",
          title: "OWASP Top 10 2021 - A07 Identification and Authentication Failures",
          url: "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/"
        },
        %{
          type: :research,
          id: "rails_secret_token",
          title: "Rails Secret Token Security Best Practices",
          url: "https://guides.rubyonrails.org/security.html#session-storage"
        },
        %{
          type: :research,
          id: "github_secrets_scanning",
          title: "GitHub Secret Scanning",
          url: "https://docs.github.com/en/code-security/secret-scanning"
        }
      ],
      attack_vectors: [
        "Public repository scanning: Automated tools scan GitHub/GitLab for exposed credentials",
        "Source code analysis: Manual or automated review of application source code",
        "Configuration file harvesting: Extraction from config files, .env files, or YAML",
        "Memory dump analysis: Extraction from application memory or core dumps",
        "Container image inspection: Scanning Docker layers for embedded credentials",
        "CI/CD pipeline exploitation: Accessing build logs and deployment artifacts",
        "Error message exploitation: Credentials leaked through stack traces or debug output",
        "Reverse engineering: Extracting hardcoded values from compiled applications",
        "Social engineering: Developers sharing code containing credentials",
        "Supply chain attacks: Compromised dependencies exposing embedded secrets"
      ],
      real_world_impact: [
        "CVE-2013-0156: Rails secret_token hardcoding enabled remote code execution attacks",
        "2019 Capital One breach: Hardcoded AWS credentials in application code led to 100M+ records exposed",
        "2018 Uber breach: Hardcoded AWS keys in GitHub repository allowed unauthorized access",
        "Docker Hub incidents: Thousands of images found with embedded AWS credentials",
        "Tesla cloud infrastructure compromise via hardcoded AWS credentials in public repository",
        "Slack API token leaks: Hardcoded tokens in mobile apps led to unauthorized workspace access",
        "Cryptocurrency theft: Hardcoded wallet private keys in mobile apps led to fund theft",
        "Jenkins security advisory: Default hardcoded encryption key compromised stored secrets",
        "Zoom client vulnerability: Hardcoded AES key allowed encryption bypass",
        "Microsoft Azure breach: Hardcoded storage account keys exposed customer data"
      ],
      cve_examples: [
        %{
          id: "CVE-2013-0156",
          description: "Rails XML/YAML deserialization with hardcoded secret tokens",
          severity: "critical",
          cvss: 10.0,
          note: "Hardcoded secret_token enabled session forgery and remote code execution"
        },
        %{
          id: "CVE-2019-5418",
          description: "Rails file content disclosure with path traversal",
          severity: "high", 
          cvss: 7.5,
          note: "Could expose configuration files containing hardcoded credentials"
        },
        %{
          id: "CVE-2020-8163",
          description: "Rails remote code execution via deserialization",
          severity: "critical",
          cvss: 9.8,
          note: "Exploitable when combined with hardcoded session secrets"
        },
        %{
          id: "CVE-2012-3503",
          description: "Installation script hard-coded secret token value",
          severity: "high",
          cvss: 7.5,
          note: "Hardcoded authentication bypass in enterprise software"
        },
        %{
          id: "GitHub-2019",
          description: "Millions of hardcoded secrets found in public repositories",
          severity: "critical",
          cvss: 9.0,
          note: "GitGuardian study found 4M+ secrets in 1B+ GitHub commits"
        }
      ],
      detection_notes: """
      This pattern detects hardcoded credentials through multiple regex patterns targeting:
      
      **Variable Assignment Patterns:**
      - password, pwd, pass assignments with string literals
      - api_key, apikey, key assignments with alphanumeric strings
      - secret, secret_key assignments with complex string values
      
      **Cloud Provider Credentials:**
      - AWS_ACCESS_KEY_ID with AKIA prefix pattern
      - AWS_SECRET_ACCESS_KEY with base64-like 40-character strings
      - Other cloud service credential patterns
      
      **Authentication Tokens:**
      - Bearer tokens, auth tokens, access tokens
      - GitHub personal access tokens (ghp_, gho_, etc.)
      - Stripe API keys (sk_, pk_ prefixes)
      
      **Database and Service URLs:**
      - Connection strings with embedded credentials
      - Redis URLs with authentication
      
      **Cryptographic Material:**
      - Private key headers (-----BEGIN PRIVATE KEY-----)
      - Certificate and key file content
      
      **False Positive Considerations:**
      - Environment variable references (ENV['KEY'])
      - Method calls that generate dynamic values
      - Commented-out code examples
      - Test fixtures and mock data
      - User input prompts and interactive code
      """,
      safe_alternatives: [
        "Environment variables: ENV['DATABASE_PASSWORD'], ENV['API_KEY']",
        "Rails credentials: Rails.application.credentials.secret_key_base",
        "Key management services: AWS Secrets Manager, Azure Key Vault, HashiCorp Vault",
        "Configuration management: Ansible Vault, Chef encrypted data bags",
        "Container secrets: Docker secrets, Kubernetes secrets",
        "CI/CD secret management: GitHub Secrets, GitLab variables",
        "Dynamic credential generation: SecureRandom.hex(32)",
        "Secret rotation systems: Automatic credential rotation services",
        "Encrypted configuration files: SOPS, git-crypt, BlackBox"
      ],
      additional_context: %{
        common_mistakes: [
          "Believing private repositories are safe for hardcoded secrets",
          "Using weak obfuscation like Base64 encoding for secrets",
          "Hardcoding development credentials that work in production",
          "Committing .env files or configuration with secrets to version control",
          "Using the same secret across multiple environments",
          "Hardcoding backup or emergency access credentials",
          "Embedding API keys in mobile applications",
          "Using predictable or default secret values"
        ],
        secure_patterns: [
          "config.password = ENV.fetch('DATABASE_PASSWORD')",
          "api_key = Rails.application.credentials.dig(:aws, :access_key_id)",
          "secret = Vault.logical.read('secret/myapp/database')['data']['password']",
          "token = SecureRandom.urlsafe_base64(32)",
          "credentials = AWS::STS::AssumeRoleCredentialsProvider.new(...)",
          "config.secret_key_base = Rails.application.secret_key_base"
        ],
        migration_guide: [
          "Audit codebase for all hardcoded credentials using automated tools",
          "Move secrets to environment variables or secure storage",
          "Implement proper secret management infrastructure",
          "Rotate all exposed credentials immediately",
          "Add pre-commit hooks to prevent future hardcoded secrets",
          "Remove secrets from Git history using tools like BFG Repo-Cleaner",
          "Document secure credential management practices for team",
          "Regular security audits and secret scanning in CI/CD"
        ],
        framework_specific: %{
          rails: [
            "Use Rails.application.credentials for encrypted secrets",
            "Configure config/master.key securely for production",
            "Use Rails.application.secret_key_base for session security",
            "Leverage encrypted_password in models with has_secure_password"
          ],
          sinatra: [
            "Use environment variables with ENV['SECRET_KEY']",
            "Configure session secret via set :session_secret, ENV['SESSION_SECRET']",
            "Use external configuration gems like Figaro or Dotenv"
          ]
        }
      }
    }
  end
  
  @doc """
  Returns AST enhancement rules to reduce false positives.
  
  This enhancement helps distinguish between actual hardcoded credentials
  and safe credential management practices.
  
  ## Examples
  
      iex> enhancement = RsolvApi.Security.Patterns.Ruby.HardcodedSecrets.ast_enhancement()
      iex> Map.keys(enhancement) |> Enum.sort()
      [:ast_rules, :confidence_rules, :context_rules, :min_confidence]
      
      iex> enhancement = RsolvApi.Security.Patterns.Ruby.HardcodedSecrets.ast_enhancement()
      iex> enhancement.min_confidence
      0.8
  """
  @impl true
  def ast_enhancement do
    %{
      ast_rules: %{
        node_type: "Assignment",
        variable_patterns: [
          "password", "pwd", "pass", "secret", "key", "token", "credential",
          "api_key", "apikey", "auth_token", "access_token", "private_key",
          "aws_access_key", "aws_secret", "database_url", "redis_url"
        ],
        assignment_analysis: %{
          check_right_hand_side: true,
          value_types: ["string_literal", "concatenation"],
          exclude_method_calls: true,
          exclude_variable_references: true
        }
      },
      context_rules: %{
        exclude_paths: [
          ~r/test/,
          ~r/spec/,
          ~r/fixtures/,
          ~r/examples/,
          ~r/sample/,
          ~r/demo/,
          ~r/\.example\./
        ],
        check_assignment_context: true,
        safe_sources: [
          "ENV", "ARGV", "gets", "readline", "SecureRandom", "Random",
          "Rails.application.credentials", "Rails.application.secrets",
          "Vault", "KeyVault", "AWS::SecretsManager", "Azure::KeyVault"
        ],
        safe_methods: [
          "fetch", "dig", "read", "get", "generate", "create", "new",
          "chomp", "strip", "gsub", "upcase", "downcase"
        ],
        danger_indicators: [
          "sk_live_", "pk_live_", "AKIA", "-----BEGIN", "ghp_", "gho_",
          "postgres://", "mysql://", "mongodb://", "redis://",
          "Bearer ", "Basic ", "AWS_ACCESS_KEY", "AWS_SECRET"
        ]
      },
      confidence_rules: %{
        base: 0.5,
        adjustments: %{
          "has_credential_pattern" => 0.4,
          "matches_known_format" => 0.3,
          "contains_danger_indicator" => 0.5,
          "long_random_string" => 0.2,
          "uses_safe_source" => -0.8,
          "is_method_call" => -0.6,
          "is_environment_var" => -1.0,
          "in_test_code" => -0.9,
          "is_commented" => -1.0,
          "is_example_code" => -0.7,
          "has_placeholder_pattern" => -0.8
        }
      },
      min_confidence: 0.8
    }
  end
end