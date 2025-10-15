defmodule Rsolv.Security.Patterns.Java.HardcodedPassword do
  @moduledoc """
  Hardcoded Credentials pattern for Java code.

  Detects hardcoded passwords, API keys, tokens, and other sensitive credentials in Java
  applications. Hardcoded credentials represent a critical security vulnerability as they
  cannot be changed without code modification and are visible to anyone with access to
  the source code or decompiled bytecode.

  ## Vulnerability Details

  Hardcoded credentials occur when developers embed sensitive authentication information
  directly in source code. This practice creates numerous security risks including:

  - Credentials exposed in version control systems
  - No ability to rotate credentials without code changes
  - Same credentials used across all environments
  - Credentials visible through code decompilation
  - Potential for accidental credential disclosure

  Common vulnerable patterns:
  - Password variables assigned literal string values
  - Database connection strings with embedded credentials
  - API keys and tokens hardcoded in configuration
  - Authentication logic with hardcoded comparisons
  - Service account credentials in source code

  ### Attack Examples

  ```java
  // Vulnerable code - hardcoded database password
  String password = "admin123";
  Connection conn = DriverManager.getConnection(url, "admin", password);

  // Vulnerable code - hardcoded API key
  String apiKey = "sk-1234567890abcdef";

  // Vulnerable code - hardcoded authentication
  if (password.equals("master_password")) {
      // Authentication logic
  }
  ```

  ## References

  - CWE-798: Use of Hard-coded Credentials
  - OWASP A07:2021 - Identification and Authentication Failures
  - CVE-2024-28987: SolarWinds Web Help Desk hardcoded credential vulnerability
  - CVE-2022-34462: Dell EMC SCG Policy Manager hardcoded password vulnerability
  """

  use Rsolv.Security.Patterns.PatternBase
  alias Rsolv.Security.Pattern

  @doc """
  Pattern detects hardcoded credentials in Java code.

  Identifies hardcoded passwords, API keys, tokens, and other sensitive credentials
  that pose significant security risks through exposure and inability to rotate.

  ## Examples

      iex> pattern = Rsolv.Security.Patterns.Java.HardcodedPassword.pattern()
      iex> pattern.id
      "java-hardcoded-password"
      
      iex> pattern = Rsolv.Security.Patterns.Java.HardcodedPassword.pattern()
      iex> pattern.severity
      :high
      
      iex> pattern = Rsolv.Security.Patterns.Java.HardcodedPassword.pattern()
      iex> vulnerable = "String password = \\\"admin123\\\";"
      iex> Enum.any?(pattern.regex, fn r -> Regex.match?(r, vulnerable) end)
      true
      
      iex> pattern = Rsolv.Security.Patterns.Java.HardcodedPassword.pattern()
      iex> safe = "String password = System.getenv(\\\"DB_PASSWORD\\\");"
      iex> Enum.any?(pattern.regex, fn r -> Regex.match?(r, safe) end)
      false
  """
  @impl true
  def pattern do
    %Pattern{
      id: "java-hardcoded-password",
      name: "Hardcoded Credentials",
      description: "Hardcoded passwords, API keys, or other credentials in source code",
      type: :hardcoded_secret,
      severity: :high,
      languages: ["java"],
      regex: [
        # Variable assignments with credential-like names and string literals (6+ chars) - exclude commented lines
        ~r/^(?!.*\/\/).*(?:password|pwd|passwd|secret|key|token|credential|auth|salt)\s*=\s*[\"'][^\"']{6,}[\"']/im,
        # Database connection methods with hardcoded credentials - exclude commented lines
        ~r/^(?!.*\/\/).*getConnection\s*\([^)]*[\"'][^\"']{6,}[\"']/im,
        # Property setters with credential-like methods and hardcoded values - exclude commented lines
        ~r/^(?!.*\/\/).*\.set(?:Password|Secret|Key|Token|Credential|Auth)\s*\(\s*[\"'][^\"']{6,}[\"']\s*\)/im,
        # Properties.setProperty with credential keys and hardcoded values - exclude commented lines
        ~r/^(?!.*\/\/).*\.setProperty\s*\(\s*[\"'](?:password|secret|key|token|credential)[\"']\s*,\s*[\"'][^\"']{6,}[\"']\s*\)/im,
        # Authentication method calls with hardcoded values - exclude commented lines
        ~r/^(?!.*\/\/).*(?:authenticate|login|setCredentials|authorize|connect)\s*\([^)]*[\"'][^\"']{6,}[\"'][^)]*\)/im,
        # API key and token patterns with typical formats - exclude commented lines
        ~r/^(?!.*\/\/).*(?:api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret)\s*=\s*[\"'][a-zA-Z0-9_-]{10,}[\"']/im,
        # Map.put and similar with credential keys - exclude commented lines
        ~r/^(?!.*\/\/).*\.put\s*\(\s*[\"'](?:password|secret|key|token|credential|auth|api|database\.password|api\.key)[\"']\s*,\s*[\"'][^\"']{6,}[\"']\s*\)/im,
        # Hardcoded password comparisons in conditional statements - exclude commented lines
        ~r/^(?!.*\/\/).*\.equals\s*\(\s*[\"'][^\"']{6,}[\"']\s*\)/im,
        # Encryption and cryptographic key assignments - exclude commented lines
        ~r/^(?!.*\/\/).*(?:encryptionKey|secretKey|cryptoKey|jwtSecret|hashSalt)\s*=\s*[\"'][^\"']{6,}[\"']/im,
        # Method calls with credential parameters (addParameter, etc) - exclude commented lines
        ~r/^(?!.*\/\/).*\.(?:addParameter|setParameter)\s*\(\s*[\"'](?:password|secret|key|token|credential)[\"']\s*,\s*[\"'][^\"']{6,}[\"']\s*\)/im
      ],
      cwe_id: "CWE-798",
      owasp_category: "A07:2021",
      recommendation:
        "Use environment variables, configuration files, or secure credential management services to store sensitive credentials",
      test_cases: %{
        vulnerable: [
          ~S|String password = "admin123";|,
          ~S|private static final String PASSWORD = "secretpass";|,
          ~S|conn = DriverManager.getConnection(url, "user", "passwd123");|,
          ~S|String apiKey = "sk-1234567890abcdef";|,
          ~S|dataSource.setPassword("hardcoded_password");|
        ],
        safe: [
          ~S|String password = System.getenv("DB_PASSWORD");|,
          ~S|String password = config.getString("database.password");|,
          ~S|// String password = "admin123";|,
          ~S|String password = null;|,
          ~S|String passwordField = "password_field_name";|
        ]
      }
    }
  end

  @impl true
  def vulnerability_metadata do
    %{
      description: """
      Hardcoded credentials vulnerabilities occur when sensitive authentication information such as
      passwords, API keys, tokens, or other secrets are embedded directly in source code. This practice
      creates significant security risks as credentials become immutable, visible to all developers,
      and potentially exposed through version control systems, decompiled bytecode, or accidental disclosure.

      Hardcoded credentials can lead to:
      - Unauthorized access to systems, databases, or APIs
      - Inability to rotate credentials without code changes
      - Same credentials used across all environments (dev, staging, production)
      - Credential exposure through source code repositories
      - Compromise of multiple systems using shared hardcoded credentials

      The vulnerability is particularly dangerous because:
      - Java bytecode can be easily decompiled to reveal hardcoded strings
      - Credentials cannot be changed without recompiling and redeploying code
      - Version control systems preserve historical credential values
      - Developers often use the same credentials across multiple projects
      - Automated scanners can easily detect hardcoded credential patterns

      Historical context:
      - Hardcoded credentials have been a persistent issue since early software development
      - Featured prominently in OWASP Top 10 2021 under A07 (Identification and Authentication Failures)
      - Critical vulnerabilities in enterprise software (SolarWinds, Dell, numerous Java applications)
      - Common attack vector in supply chain attacks and insider threats
      - Regulatory compliance violations (SOX, HIPAA, PCI DSS) for exposed credentials
      """,
      references: [
        %{
          type: :cwe,
          id: "CWE-798",
          title: "Use of Hard-coded Credentials",
          url: "https://cwe.mitre.org/data/definitions/798.html"
        },
        %{
          type: :owasp,
          id: "A07:2021",
          title: "OWASP Top 10 2021 - A07 Identification and Authentication Failures",
          url: "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/"
        },
        %{
          type: :research,
          id: "owasp_hardcoded_password",
          title: "OWASP Use of Hard-coded Password",
          url: "https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password"
        },
        %{
          type: :research,
          id: "owasp_secrets_management",
          title: "OWASP Secrets Management Cheat Sheet",
          url:
            "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html"
        },
        %{
          type: :research,
          id: "sonarqube_hardcoded_passwords",
          title: "SonarQube Hard-coded passwords are security-sensitive",
          url: "https://next.sonarqube.com/sonarqube/coding_rules?rule_key=java%3AS2068"
        }
      ],
      attack_vectors: [
        "Source code analysis: Attackers analyze decompiled Java bytecode to extract hardcoded credentials",
        "Version control mining: Attackers search Git repositories and commit history for exposed credentials",
        "Configuration file analysis: Scanning deployment packages and configuration files for embedded secrets",
        "Memory dump analysis: Extracting hardcoded strings from application memory during runtime",
        "Supply chain attacks: Compromising dependencies that contain hardcoded credentials",
        "Insider threats: Developers with code access can easily extract and misuse hardcoded credentials",
        "Automated scanning: Using tools to systematically scan codebases for credential patterns"
      ],
      real_world_impact: [
        "SolarWinds Web Help Desk: CVE-2024-28987 hardcoded credential allowing admin access with CVSS 9.1",
        "Dell EMC SCG Policy Manager: CVE-2022-34462 hardcoded password enabling privilege escalation",
        "Western Digital SSD Utility: CVE-2019-13466 hardcoded password for customer report encryption",
        "MongoDB data breaches: Hardcoded credentials in applications leading to database compromises",
        "Cloud service breaches: Hardcoded API keys enabling unauthorized access to cloud resources",
        "Financial services attacks: Banking applications with hardcoded database credentials",
        "IoT device compromises: Hardcoded SSH and service credentials in embedded Java applications"
      ],
      cve_examples: [
        %{
          id: "CVE-2024-28987",
          description:
            "SolarWinds Web Help Desk hardcoded credential vulnerability allowing admin access",
          severity: "critical",
          cvss: 9.1,
          note:
            "Remote unauthenticated attackers can login with hardcoded credentials to gain admin privileges"
        },
        %{
          id: "CVE-2022-34462",
          description:
            "Dell EMC SCG Policy Manager hardcoded password vulnerability enabling privilege escalation",
          severity: "high",
          cvss: 8.4,
          note:
            "Knowledge of hardcoded credentials allows attackers to login and gain admin privileges"
        },
        %{
          id: "CVE-2019-13466",
          description:
            "Western Digital SSD Utility hardcoded password protecting customer reports archive",
          severity: "medium",
          cvss: 6.2,
          note:
            "Hardcoded password used to encrypt customer support report archives can be extracted"
        }
      ],
      detection_notes: """
      This pattern detects insecure credential handling by identifying:

      1. Variable assignments with credential-like names (password, secret, key, token) and string literal values
      2. Database connection methods with hardcoded username/password parameters
      3. Property setters and configuration methods with hardcoded credential values
      4. Authentication method calls containing hardcoded password parameters
      5. API key and token assignments with typical credential formats
      6. Map and Properties operations with credential keys and hardcoded values

      The pattern uses multiple regex approaches to catch various Java credential patterns:
      - Direct variable assignments (String password = "value")
      - Method calls with credential parameters (authenticate("user", "password"))
      - Property configuration (setPassword("hardcoded"), setProperty("password", "value"))
      - API key patterns (apiKey = "sk-...", authToken = "bearer_...")

      Key detection criteria:
      - Looks for credential-related variable names and method calls
      - Requires string literals with sufficient length (6+ characters) to avoid false positives
      - Covers both direct assignments and method parameter scenarios
      - Includes common API key and token format patterns
      """,
      safe_alternatives: [
        "Use System.getenv() to read credentials from environment variables",
        "Store credentials in external configuration files with restricted access",
        "Use secure credential management systems (HashiCorp Vault, AWS Secrets Manager)",
        "Implement Java KeyStore for cryptographic key management",
        "Use Spring Boot's @ConfigurationProperties with external configuration",
        "Employ JNDI datasource configuration for database credentials",
        "Use OAuth 2.0 or similar token-based authentication instead of passwords",
        "Implement proper secret rotation and versioning mechanisms"
      ],
      additional_context: %{
        common_mistakes: [
          "Believing that obfuscation or encoding provides adequate security for hardcoded credentials",
          "Using hardcoded credentials for 'development only' that accidentally reach production",
          "Storing credentials in properties files within the application JAR",
          "Using the same hardcoded credentials across multiple environments",
          "Assuming that private repositories provide sufficient protection for hardcoded secrets",
          "Hardcoding database URLs with embedded credentials in connection strings",
          "Using weak or default passwords thinking they won't be discovered"
        ],
        secure_patterns: [
          "Always externalize credentials using environment variables or configuration management",
          "Use dependency injection with configuration beans for credential management",
          "Implement credential validation and expiration policies",
          "Use different credentials for each environment (dev, staging, production)",
          "Employ least privilege principles for service account credentials",
          "Implement secure credential storage with encryption at rest",
          "Use managed identity services in cloud environments when available",
          "Regular credential rotation and automated expiration policies"
        ],
        credential_types: [
          "Database passwords and connection strings",
          "API keys and access tokens for external services",
          "Encryption keys and cryptographic secrets",
          "Service account credentials and certificates",
          "OAuth client secrets and refresh tokens",
          "LDAP and directory service passwords",
          "Message queue and broker authentication credentials"
        ],
        java_specific_considerations: [
          "Java bytecode decompilation easily reveals hardcoded string literals",
          "Class files can be extracted from JAR archives for analysis",
          "Spring Boot configuration should use externalized properties",
          "JNDI datasources provide secure database credential management",
          "Java KeyStore provides secure key and certificate storage",
          "System properties and environment variables are preferred for configuration"
        ],
        compliance_impact: [
          "SOX: Hardcoded credentials violate financial reporting security controls",
          "PCI DSS: Credit card processing systems must secure all authentication credentials",
          "HIPAA: Healthcare applications must protect authentication mechanisms for PHI access",
          "GDPR: Personal data processing systems require secure authentication controls",
          "ISO 27001: Information security management requires proper credential handling",
          "NIST Cybersecurity Framework: Hardcoded credentials violate access control standards"
        ]
      }
    }
  end

  @doc """
  Returns AST enhancement rules to reduce false positives.

  This enhancement helps distinguish between actual hardcoded credential vulnerabilities
  and legitimate string assignments that happen to match credential patterns.

  ## Examples

      iex> enhancement = Rsolv.Security.Patterns.Java.HardcodedPassword.ast_enhancement()
      iex> Map.keys(enhancement) |> Enum.sort()
      [:ast_rules, :confidence_rules, :context_rules, :min_confidence]
      
      iex> enhancement = Rsolv.Security.Patterns.Java.HardcodedPassword.ast_enhancement()
      iex> enhancement.min_confidence
      0.8
      
      iex> enhancement = Rsolv.Security.Patterns.Java.HardcodedPassword.ast_enhancement()
      iex> enhancement.ast_rules.node_type
      "VariableDeclaration"
  """
  @impl true
  def ast_enhancement do
    %{
      ast_rules: %{
        node_type: "VariableDeclaration",
        credential_analysis: %{
          check_hardcoded_values: true,
          credential_patterns: [
            "password",
            "pwd",
            "passwd",
            "secret",
            "key",
            "token",
            "credential",
            "auth",
            "apiKey",
            "accessToken",
            "authToken",
            "clientSecret",
            "privateKey"
          ],
          check_string_literals: true,
          minimum_length: 6,
          exclude_common_placeholders: [
            "password",
            "secret",
            "key",
            "token",
            "changeme",
            "admin",
            "test"
          ]
        },
        auth_analysis: %{
          check_authentication_context: true,
          method_patterns: ["authenticate", "login", "setCredentials", "authorize", "connect"],
          dangerous_assignments: true,
          check_connection_strings: true,
          database_methods: ["getConnection", "connect", "createConnection"]
        },
        config_analysis: %{
          check_configuration_files: true,
          property_patterns: ["setProperty", "put", "setPassword", "setSecret", "setKey"],
          dangerous_configurations: true,
          check_spring_properties: true,
          configuration_annotations: ["@Value", "@ConfigurationProperties"]
        },
        api_analysis: %{
          check_api_credentials: true,
          api_key_patterns: ["api.?key", "access.?token", "auth.?token", "client.?secret"],
          token_patterns: ["bearer", "jwt", "oauth", "api"],
          check_external_service_calls: true,
          service_patterns: ["HttpClient", "RestTemplate", "WebClient"]
        }
      },
      context_rules: %{
        check_environment_usage: true,
        safe_credential_sources: [
          "System.getenv",
          "System.getProperty",
          "config.getString",
          "properties.getProperty",
          "@Value",
          "Environment.getProperty",
          "keyStore.getKey",
          "vault.read",
          "secretsManager.getSecret"
        ],
        hardcoded_credential_indicators: [
          "string_literal_with_credential_name",
          "no_external_configuration_usage",
          "credential_in_method_parameter",
          "database_connection_with_hardcoded_values"
        ],
        exclude_paths: [~r/test/, ~r/spec/, ~r/__tests__/, ~r/example/, ~r/demo/, ~r/sample/],
        check_test_code: true,
        high_risk_contexts: [
          "authentication",
          "database_connection",
          "api_authorization",
          "encryption_keys"
        ],
        safe_if_uses_configuration: true
      },
      confidence_rules: %{
        base: 0.9,
        adjustments: %{
          "uses_environment_variables" => -0.8,
          "uses_configuration_management" => -0.7,
          "uses_secure_storage" => -0.6,
          "in_authentication_context" => 0.1,
          "has_credential_pattern_name" => 0.1,
          "in_database_context" => 0.1,
          "in_api_context" => 0.1,
          "in_test_code" => -0.5,
          "is_commented_out" => -0.9,
          "is_placeholder_value" => -0.4,
          "uses_spring_configuration" => -0.5,
          "short_string_length" => -0.3
        }
      },
      min_confidence: 0.8
    }
  end
end
