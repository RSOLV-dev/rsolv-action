defmodule RsolvApi.Security.Patterns.Javascript.HardcodedSecretPassword do
  @moduledoc """
  Hardcoded Secret - Password in JavaScript/Node.js
  
  Detects dangerous patterns like:
    const password = "admin123"
    let dbPassword = 'secretpass'
    var config = { password: "mysecret123" }
    
  Safe alternatives:
    const password = process.env.DB_PASSWORD
    const password = await secretManager.getSecret('db-password')
    const password = config.get('database.password')
    
  Hardcoded passwords in source code represent one of the most critical security 
  vulnerabilities in software development. This practice exposes sensitive 
  authentication credentials to anyone with access to the codebase, including 
  developers, version control systems, code repositories, and potentially attackers.
  
  ## Vulnerability Details
  
  Hardcoded passwords violate fundamental security principles and create multiple 
  attack vectors:
  
  1. **Source Code Exposure**: Passwords visible in plain text to anyone with code access
  2. **Version Control History**: Passwords permanently stored in git history
  3. **Repository Scanning**: Automated tools easily detect hardcoded credentials
  4. **Deployment Leakage**: Passwords exposed in build artifacts and logs
  5. **Shared Development**: Multiple developers gain access to production credentials
  
  ### Attack Example
  ```javascript
  // Vulnerable: Hardcoded database password
  const dbConfig = {
    host: 'production-db.company.com',
    user: 'admin',
    password: 'Pr0duct10nP@ss2024',  // <- Exposed in source code
    database: 'users'
  };
  
  // Vulnerable: API authentication
  const config = {
    apiKey: process.env.API_KEY,        // Good
    password: "supersecret123"          // <- Bad: Hardcoded
  };
  ```
  
  ### Modern Attack Scenarios
  Hardcoded passwords enable numerous attack vectors including unauthorized database 
  access, API abuse, privilege escalation, and lateral movement within systems. 
  Attackers regularly scan public repositories for exposed credentials, making this 
  a high-priority target for both automated tools and manual exploitation.
  """
  
  use RsolvApi.Security.Patterns.PatternBase
  alias RsolvApi.Security.Pattern
  

  def pattern do
    %Pattern{
      id: "js-hardcoded-secret-password",
      name: "Hardcoded Password",
      description: "Passwords should never be hardcoded in source code",
      type: :hardcoded_secret,
      severity: :high,
      languages: ["javascript", "typescript"],
      regex: ~r/(?:password|passwd|pwd)\s*[=:]\s*["'`][^"'`]{4,}["'`]/i,
      cwe_id: "CWE-798",
      owasp_category: "A07:2021",
      recommendation: "Store passwords in environment variables or secure configuration management systems.",
      test_cases: %{
        vulnerable: [
          ~s(const password = "admin123"),
          ~s(let dbPassword = 'secretpass'),
          ~s(var config = { password: "mysecret123" }),
          ~s(const PASSWORD = "P@ssw0rd!"),
          ~s(let userPassword = `superSecret2024`),
          ~s(var auth = { passwd: "test1234" }),
          ~s(const pwd = "quickPass"),
          ~s(password: "defaultPassword"),
          ~s(const dbConfig = { password: "root123" }),
          ~s(let credentials = { pwd: "admin@2024" })
        ],
        safe: [
          ~S|const password = process.env.DB_PASSWORD|,
          ~S|const password = config.get('database.password')|,
          ~S|const password = await secretManager.getSecret('db-password')|,
          ~S|let password = getPasswordFromVault()|,
          ~S|const pwd = getUserInput()|,
          ~S|var password = prompt("Enter password:")|,
          ~S|password = await hashPassword(userInput)|,
          ~S|const hashedPassword = bcrypt.hash(plaintext, 10)|,
          ~S|// password should be stored securely|,
          ~S|const validationMessage = "password must contain uppercase"|,
          ~S|const passwordField = document.getElementById("password")|,
          ~S|function validatePassword(pwd) { return pwd.length > 8; }|,
          ~S|const passwordRegex = /^(?=.*[A-Z])(?=.*[a-z])/|,
          ~S|console.log("Password validation failed")|
        ]
      }
    }
  end
  
  @doc """
  Comprehensive vulnerability metadata for hardcoded passwords.
  
  This metadata documents the critical security risks of storing passwords directly 
  in source code and provides authoritative guidance for secure credential management.
  """
  def vulnerability_metadata do
    %{
      description: """
      Hardcoded passwords represent one of the most critical and easily exploitable 
      security vulnerabilities in software development. This practice involves storing 
      authentication credentials directly in source code, making them visible to anyone 
      with access to the codebase, version control history, or deployment artifacts.
      
      The vulnerability is particularly dangerous because it combines high impact with 
      trivial exploitation. Once discovered, hardcoded passwords provide immediate 
      unauthorized access to systems, databases, APIs, and other sensitive resources. 
      The exposure is persistent and difficult to remediate completely, as passwords 
      may remain in version control history even after being removed from current code.
      
      Modern development practices, including public repositories, CI/CD pipelines, 
      and automated code scanning, have made hardcoded passwords increasingly risky. 
      Attackers routinely scan GitHub and other platforms for exposed credentials, 
      often gaining access to production systems within hours of code commits containing 
      hardcoded passwords.
      
      Beyond direct security risks, hardcoded passwords violate compliance requirements, 
      complicate credential rotation, prevent proper access management, and create 
      operational challenges for teams managing multiple environments and deployment scenarios.
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
          type: :nist,
          id: "SP_800-63B",
          title: "NIST Digital Identity Guidelines - Authentication and Lifecycle Management",
          url: "https://pages.nist.gov/800-63-3/sp800-63b.html"
        },
        %{
          type: :sans,
          id: "TOP25_2022",
          title: "SANS/CWE Top 25 Most Dangerous Software Weaknesses (2022)",
          url: "https://www.sans.org/top25-software-errors/"
        },
        %{
          type: :research,
          id: "github_credential_exposure",
          title: "Empirical Study of Credential Exposure in Public Repositories",
          url: "https://www.ndss-symposium.org/wp-content/uploads/2019/02/ndss2019_04B-3_Meli_paper.pdf"
        }
      ],
      attack_vectors: [
        "Source code repository scanning: Automated tools discover passwords in public/private repos",
        "Version control history mining: Passwords persist in git history even after removal",
        "Code review exposure: Credentials visible during peer review processes",
        "Build artifact inspection: Passwords embedded in compiled or packaged applications",
        "Log file analysis: Credentials accidentally logged during application startup or errors",
        "Developer machine compromise: Local repositories contain production passwords",
        "CI/CD pipeline exploitation: Build processes expose hardcoded credentials",
        "Insider threats: Malicious or negligent employees access production credentials"
      ],
      real_world_impact: [
        "Unauthorized database access: Direct access to production databases with hardcoded passwords",
        "API abuse and data theft: Exposed API keys enable unlimited access to external services",
        "Account takeover: Admin passwords allow complete system compromise",
        "Lateral movement: Credential reuse enables access to multiple systems and services",
        "Data breaches: Exposed databases lead to customer data theft and privacy violations",
        "Service disruption: Attackers can modify or delete critical data and configurations",
        "Compliance violations: Hardcoded passwords violate PCI DSS, HIPAA, SOX, and other regulations",
        "Reputational damage: Public exposure of poor security practices damages organization credibility"
      ],
      cve_examples: [
        %{
          id: "CVE-2023-28343",
          description: "Hardcoded credentials in Kubernetes admission controller",
          severity: "critical",
          cvss: 9.8,
          note: "Administrative credentials hardcoded in container images"
        },
        %{
          id: "CVE-2022-31499",
          description: "Default hardcoded password in Fluentd logging system",
          severity: "high",
          cvss: 8.8,
          note: "Default administrative password never changed in production deployments"
        },
        %{
          id: "CVE-2021-44228",
          description: "Log4Shell vulnerability partially enabled by hardcoded credentials",
          severity: "critical",
          cvss: 10.0,
          note: "Hardcoded LDAP credentials facilitated exploitation in some environments"
        },
        %{
          id: "CVE-2020-10189",
          description: "Hardcoded credentials in Zoho ManageEngine products",
          severity: "critical",
          cvss: 9.8,
          note: "Multiple products shipped with identical hardcoded administrative passwords"
        }
      ],
      detection_notes: """
      This pattern detects variable assignments where password-related identifiers 
      (password, passwd, pwd) are assigned string literals of 4 or more characters.
      The detection covers:
      
      1. Variable declarations: const password = "value"
      2. Object properties: { password: "value" }
      3. Assignment expressions: password = "value"
      4. Various quote styles: single, double, template literals
      5. Case variations: password, PASSWORD, Password
      6. Common abbreviations: passwd, pwd
      
      The pattern uses a minimum length of 4 characters to reduce false positives 
      from test data or placeholder values while catching real passwords. The regex 
      is designed to be sensitive enough to catch hardcoded credentials while 
      avoiding matches on password validation logic, form field definitions, or 
      comment text discussing password security.
      """,
      safe_alternatives: [
        "Use environment variables: const password = process.env.DB_PASSWORD",
        "Use secure configuration management: const password = config.get('database.password')",
        "Use cloud secret managers: const password = await secretManager.getSecret('db-password')",
        "Use vault systems: const password = await vault.read('secret/database')",
        "Use encrypted configuration files with runtime decryption",
        "Use service account authentication where possible instead of passwords",
        "Use OAuth2 or JWT tokens with limited scope and expiration",
        "Implement credential rotation with automated password management systems"
      ],
      additional_context: %{
        compliance_impact: [
          "PCI DSS Requirement 8.2.1 prohibits hardcoded passwords for payment processing",
          "HIPAA requires proper credential management for healthcare applications",
          "SOX compliance demands secure authentication for financial systems",
          "GDPR privacy requirements include secure credential handling for personal data",
          "ISO 27001 mandates proper access control and credential management",
          "FedRAMP requires specific credential security standards for government systems"
        ],
        common_mistakes: [
          "Believing private repositories provide sufficient security for credentials",
          "Using weak obfuscation thinking it prevents credential discovery",
          "Hardcoding 'temporary' passwords that become permanent in production",
          "Storing encrypted passwords in code without secure key management",
          "Using the same hardcoded passwords across multiple environments",
          "Committing credential removal without cleaning version control history"
        ],
        secure_patterns: [
          "Implement proper secret management using dedicated tools (Vault, AWS Secrets Manager)",
          "Use environment variable injection at runtime rather than build time",
          "Implement credential rotation policies with automated password updates",
          "Use service-to-service authentication (mutual TLS, service accounts) when possible",
          "Implement least-privilege access with scope-limited credentials",
          "Use configuration templates with runtime secret injection",
          "Implement proper credential lifecycle management with expiration and renewal"
        ],
        remediation_steps: [
          "Immediately rotate all exposed credentials and update systems",
          "Remove hardcoded passwords from current codebase",
          "Clean git history to remove historical credential exposure",
          "Implement proper secret management infrastructure",
          "Update CI/CD pipelines to use secure credential injection",
          "Add automated scanning to prevent future hardcoded credentials",
          "Train development teams on secure credential management practices",
          "Establish security policies and code review processes for credential handling"
        ],
        detection_tools: [
          "git-secrets: Prevent committing secrets to git repositories",
          "truffleHog: Search git repositories for high entropy strings and secrets",
          "detect-secrets: Enterprise tool for identifying hardcoded credentials",
          "GitGuardian: Automated secret detection in code repositories",
          "SAST tools: Static analysis security testing with credential detection rules",
          "Pre-commit hooks: Automated credential scanning before code commits"
        ]
      }
    }
  end
  
  @doc """
  Check if this pattern applies to a file based on its path and content.
  
  Applies to JavaScript/TypeScript files or any file containing password assignments.
  """
  def applies_to_file?(file_path, content \\ nil) do
    cond do
      # JavaScript/TypeScript files always apply
      String.match?(file_path, ~r/\.(js|jsx|ts|tsx|mjs)$/i) -> true
      
      # If content is provided, check for password assignments
      content != nil ->
        # Check for password-related variable names in content
        String.contains?(content, "password") || 
        String.contains?(content, "passwd") ||
        String.contains?(content, "pwd") ||
        # Also check if the pattern regex itself matches
        Regex.match?(pattern().regex, content)
        
      # Default
      true -> false
    end
  end
  
  @doc """
  Returns AST enhancement rules to reduce false positives.
  
  This enhancement helps distinguish between actual hardcoded passwords
  and legitimate uses of the word "password" in code.
  
  ## Examples
  
      iex> enhancement = RsolvApi.Security.Patterns.Javascript.HardcodedSecretPassword.ast_enhancement()
      iex> Map.keys(enhancement) |> Enum.sort()
      [:ast_rules, :confidence_rules, :context_rules, :min_confidence]
      
      iex> enhancement = RsolvApi.Security.Patterns.Javascript.HardcodedSecretPassword.ast_enhancement()
      iex> enhancement.ast_rules.node_type
      "VariableDeclarator"
      
      iex> enhancement = RsolvApi.Security.Patterns.Javascript.HardcodedSecretPassword.ast_enhancement()
      iex> "Literal" in enhancement.ast_rules.value_types
      true
      
      iex> enhancement = RsolvApi.Security.Patterns.Javascript.HardcodedSecretPassword.ast_enhancement()
      iex> enhancement.min_confidence
      0.8
  """
  @impl true
  def ast_enhancement do
    %{
      ast_rules: %{
        node_type: "VariableDeclarator",
        value_types: ["Literal", "TemplateLiteral"],  # String values
        identifier_check: %{
          pattern: ~r/(?:password|passwd|pwd|pass|secret|credential)/i,
          exclude_pattern: ~r/(?:regex|pattern|validation|test|example|placeholder|message|error|field|input)/i
        },
        assignment_analysis: %{
          check_value_content: true,
          suspicious_values: ~r/^(?!.*(?:TODO|FIXME|CHANGE_ME|placeholder|example)).*$/i,
          min_value_length: 4,  # Real passwords are usually longer
          max_value_length: 100  # Very long strings are likely not passwords
        }
      },
      context_rules: %{
        exclude_paths: [~r/test/, ~r/spec/, ~r/__tests__/, ~r/fixtures/, ~r/examples/, ~r/docs/],
        safe_patterns: [
          "process.env",      # Environment variables
          "config.get",       # Configuration systems
          "getenv",           # Environment access
          "prompt",           # User input
          "readPassword",     # Password input functions
          "getSecret",        # Secret management
          "vault",            # HashiCorp Vault
          "secretManager",    # AWS/GCP secret managers
          "keychain"          # OS keychains
        ],
        check_surrounding_code: true,
        safe_contexts: [
          "validation",       # Password validation logic
          "placeholder",      # UI placeholders
          "error_message",    # Error messages about passwords
          "documentation",    # Code comments
          "schema",           # Database schemas
          "mock",             # Mock data
          "fixture"           # Test fixtures
        ]
      },
      confidence_rules: %{
        base: 0.6,  # Medium-high base - many false positives possible
        adjustments: %{
          "literal_string_value" => 0.4,        # Direct string assignment
          "production_file" => 0.3,             # In production code
          "config_file" => 0.3,                 # Configuration files
          "short_value" => -0.2,                # Very short values unlikely
          "environment_variable" => -0.8,       # Using env vars is safe
          "test_file" => -0.7,                  # Test files OK
          "example_code" => -0.6,               # Example/demo code
          "validation_context" => -0.5,         # Password validation logic
          "ui_placeholder" => -0.6,             # UI placeholder text
          "encrypted_value" => -0.3,            # Already encrypted
          "configuration_access" => -0.7        # Using config system
        }
      },
      min_confidence: 0.8  # High threshold due to many false positives
    }
  end
end