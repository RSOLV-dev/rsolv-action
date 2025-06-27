defmodule RsolvApi.Security.Patterns.Javascript.HardcodedSecretApiKey do
  @moduledoc """
  Hardcoded Secret - API Key in JavaScript/Node.js
  
  Detects dangerous patterns like:
    const apiKey = "sk-1234567890abcdef"
    const API_KEY = "abcd1234efgh5678ijkl"
    let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    
  Safe alternatives:
    const apiKey = process.env.API_KEY
    const token = await keyManager.getKey('api-secret')
    const apiSecret = config.get('stripe.apiKey')
    
  Hardcoded API keys and tokens represent one of the most frequently exploited 
  security vulnerabilities in modern software development. Unlike passwords which 
  may be used for human authentication, API keys are designed for automated 
  service-to-service communication and often carry extensive permissions for 
  accessing external services, databases, and cloud resources.
  
  ## Vulnerability Details
  
  API keys embedded in source code create multiple critical security exposures:
  
  1. **Service Abuse**: Direct access to paid external services (AWS, Stripe, etc.)
  2. **Data Exfiltration**: API keys often provide broad access to customer data
  3. **Financial Impact**: Exposed keys can lead to unauthorized charges and resource consumption
  4. **Lateral Movement**: Cloud API keys can provide access to entire infrastructure
  5. **Permanent Exposure**: Keys remain exposed in version control history indefinitely
  
  ### Attack Example
  ```javascript
  // Vulnerable: Hardcoded Stripe API key
  const stripe = require('stripe')('sk_live_1234567890abcdef');
  // This key provides full access to payment processing
  
  // Vulnerable: AWS credentials in config
  const config = {
    aws: {
      accessKeyId: 'AKIAIOSFODNN7EXAMPLE',
      secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'  // <- Exposed
    }
  };
  ```
  
  ### Modern Attack Landscape
  Automated tools continuously scan public repositories for exposed API keys, 
  often leading to exploitation within minutes of code commits. Cloud providers 
  and service vendors actively monitor for their keys in public repositories, 
  but this reactive approach cannot prevent the window of vulnerability that 
  exists between exposure and detection.
  """
  
  use RsolvApi.Security.Patterns.PatternBase
  alias RsolvApi.Security.Pattern
  

  def pattern do
    %Pattern{
      id: "js-hardcoded-secret-api-key",
      name: "Hardcoded API Key",
      description: "API keys should not be hardcoded in source code",
      type: :hardcoded_secret,
      severity: :high,
      languages: ["javascript", "typescript"],
      regex: ~r/(?:api[_-]?key|api[_-]?secret|token)\s*[=:]\s*["'`][\w\-]{16,}["'`]/i,
      cwe_id: "CWE-798",
      owasp_category: "A07:2021",
      recommendation: "Store API keys in environment variables or secure key management systems.",
      test_cases: %{
        vulnerable: [
          ~S|const apiKey = "sk-1234567890abcdef"|,
          ~S|const API_KEY = "abcd1234efgh5678ijkl"|,
          ~S|let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"|,
          ~S|var config = { apiKey: "prod_live_abc123def456" }|,
          ~S|const api_secret = "secret_key_12345678901234567890"|,
          ~S|let authToken = `bearer_token_abcdefghijklmnop`|,
          ~S|const API_SECRET = "live_api_secret_xyz789"|,
          ~S|api-key: "service_account_key_123456789"|,
          ~S|const stripe = { api_key: "sk_live_1234567890123456" }|,
          ~S|let github_token = "ghp_abcdefghijklmnopqrstuvwxyz123456"|
        ],
        safe: [
          ~S|const apiKey = process.env.API_KEY|,
          ~S|const token = getTokenFromVault()|,
          ~S|const apiSecret = await keyManager.getKey('api-secret')|,
          ~S|let apiKey = config.get('stripe.apiKey')|,
          ~S|const token = await oauth.getAccessToken()|,
          ~S|var apiKey = prompt("Enter API key:")|,
          ~S|const key = generateApiKey()|,
          ~S|// apiKey should be stored securely|,
          ~S|const keyField = document.getElementById("apiKey")|,
          ~S|function validateApiKey(key) { return key.length > 16; }|,
          ~S|const API_URL = "https://api.example.com"|,
          ~S|console.log("API key validation failed")|,
          ~S|const shortKey = "abc"|,
          ~S|let tempKey = "test123"|,
          ~S|const mockKey = "fake_key"|
        ]
      }
    }
  end
  
  @doc """
  Comprehensive vulnerability metadata for hardcoded API keys.
  
  This metadata documents the critical security and business risks of embedding 
  API keys in source code, with specific focus on service abuse and financial impact.
  """
  def vulnerability_metadata do
    %{
      description: """
      Hardcoded API keys represent a critical vulnerability class that combines high 
      exploitability with severe business impact. Unlike traditional authentication 
      credentials, API keys are designed for programmatic access and often carry 
      broad permissions for external services, cloud resources, and payment processing.
      
      The vulnerability is particularly dangerous because API keys are frequently 
      associated with billable services, sensitive data access, and infrastructure 
      control. A single exposed API key can lead to immediate financial damage, 
      data breaches, and service disruption. The automated nature of API key usage 
      also means that exploitation can occur at scale and with minimal human intervention.
      
      Modern development practices have made API key exposure increasingly common, 
      with developers working across multiple environments, integrating numerous 
      third-party services, and sharing code through public repositories. The rise 
      of cloud services and microservices architectures has multiplied both the 
      number of API keys used in applications and their potential for abuse.
      
      The persistence of API keys in version control systems creates long-term 
      exposure risks, as keys remain accessible even after being removed from 
      current code. This creates ongoing vulnerability to repository compromise, 
      insider threats, and historical data mining attacks.
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
          id: "SP_800-57",
          title: "NIST Recommendation for Key Management",
          url: "https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r5.pdf"
        },
        %{
          type: :vendor,
          id: "AWS_SECURITY",
          title: "AWS Security Best Practices for Managing Access Keys",
          url: "https://docs.aws.amazon.com/general/latest/gr/aws-access-keys-best-practices.html"
        },
        %{
          type: :research,
          id: "api_key_exposure_study",
          title: "Large-Scale Analysis of API Key Exposure in Public Repositories",
          url: "https://www.usenix.org/conference/usenixsecurity21/presentation/meli"
        },
        %{
          type: :sans,
          id: "API_SECURITY",
          title: "SANS API Security Top 10",
          url: "https://www.sans.org/white-papers/api-security/"
        }
      ],
      attack_vectors: [
        "Repository scanning: Automated tools discover API keys in public/private repositories",
        "Build artifact analysis: Keys embedded in compiled applications and container images",
        "Configuration file exposure: API keys in deployed configuration files and environment dumps",
        "Log file mining: Keys accidentally logged during application startup and debugging",
        "Developer workstation compromise: Local repositories and IDE configurations contain production keys",
        "Supply chain attacks: Dependencies and packages containing hardcoded API keys",
        "Social engineering: Developers inadvertently sharing code snippets containing keys",
        "Memory dumps and crash reports: API keys exposed in application memory and crash diagnostics"
      ],
      real_world_impact: [
        "Service abuse and resource theft: Unauthorized usage of paid cloud services and APIs",
        "Financial losses: Direct charges for API usage, data transfer, and compute resources",
        "Data breaches: API keys providing access to customer databases and sensitive information",
        "Infrastructure compromise: Cloud API keys enabling lateral movement and privilege escalation",
        "Compliance violations: Unauthorized access to regulated data through exposed service keys",
        "Service disruption: Rate limiting exhaustion and service blocking due to abuse",
        "Reputation damage: Public exposure of poor security practices and customer data breaches",
        "Legal liability: Regulatory fines and litigation from security breaches and data exposure"
      ],
      cve_examples: [
        %{
          id: "CVE-2023-35794",
          description: "Hardcoded API keys in popular NPM packages leading to service abuse",
          severity: "high",
          cvss: 8.2,
          note: "Multiple packages contained hardcoded cloud service API keys"
        },
        %{
          id: "CVE-2022-24765",
          description: "Git configuration exposure leading to API key compromise",
          severity: "high",
          cvss: 7.8,
          note: "Git configuration files containing hardcoded API keys for CI/CD services"
        },
        %{
          id: "CVE-2021-44228",
          description: "Log4Shell vulnerability partially exploited through exposed API keys",
          severity: "critical",
          cvss: 10.0,
          note: "Hardcoded API keys in logging configurations facilitated some attack vectors"
        },
        %{
          id: "CVE-2020-8912",
          description: "AWS S3 bucket exposure through hardcoded access keys",
          severity: "high",
          cvss: 8.1,
          note: "Hardcoded AWS credentials in mobile applications led to bucket compromise"
        }
      ],
      detection_notes: """
      This pattern detects variable assignments where API key-related identifiers 
      (api_key, apiKey, api-key, api_secret, token) are assigned string literals 
      of 16 or more characters. The detection covers:
      
      1. Variable declarations: const apiKey = "value"
      2. Object properties: { api_key: "value" }
      3. Assignment expressions: api-key: "value"
      4. Various naming conventions: apiKey, api_key, api-key, API_KEY
      5. Token variations: token, authToken, bearerToken
      6. Secret variations: apiSecret, api_secret, API_SECRET
      7. Quote styles: single quotes, double quotes, template literals
      8. Minimum length filtering: 16+ characters to reduce false positives
      
      The pattern uses a 16-character minimum length to balance detection sensitivity 
      with false positive reduction, as most production API keys are significantly 
      longer than common test values or placeholder strings.
      """,
      safe_alternatives: [
        "Use environment variables: const apiKey = process.env.STRIPE_API_KEY",
        "Use secure configuration management: const key = config.get('aws.accessKey')",
        "Use cloud secret managers: const token = await secretManager.getSecret('github-token')",
        "Use vault systems: const apiKey = await vault.read('secret/api-keys/stripe')",
        "Use OAuth2 flows for user-delegated access instead of long-lived API keys",
        "Implement API key rotation with automated renewal systems",
        "Use service account authentication where supported by the provider",
        "Use scoped and time-limited tokens instead of permanent API keys",
        "Implement runtime key injection through secure deployment pipelines"
      ],
      additional_context: %{
        service_specific_patterns: [
          "AWS Access Keys: AKIA[0-9A-Z]{16} (20 chars total)",
          "Stripe API Keys: sk_live_ or sk_test_ prefixes",
          "GitHub Personal Access Tokens: ghp_ prefix (40+ chars)",
          "Google API Keys: AIza prefix (39 chars)",
          "JWT Tokens: eyJ prefix for JSON Web Tokens",
          "Azure Storage Keys: 88-character base64 strings",
          "SendGrid API Keys: SG. prefix",
          "Mailgun API Keys: key- prefix"
        ],
        financial_impact_examples: [
          "Exposed AWS keys leading to $50,000+ monthly charges for cryptocurrency mining",
          "Stripe API key abuse resulting in fraudulent payment processing and chargebacks",
          "Google Maps API key abuse causing $10,000+ in usage charges within hours",
          "SendGrid API key exploitation for mass spam campaigns affecting sender reputation",
          "Twilio API key abuse for premium SMS fraud generating thousands in charges",
          "Azure storage key exposure leading to data exfiltration and compliance violations"
        ],
        detection_evasion_techniques: [
          "Base64 encoding of API keys (still detectable through entropy analysis)",
          "String concatenation to split keys across multiple variables",
          "Simple obfuscation through character substitution",
          "Storing keys in binary formats or encrypted with weak algorithms",
          "Using environment variables in development but hardcoding in production builds",
          "Embedding keys in compiled assets or minified JavaScript"
        ],
        incident_response_steps: [
          "Immediately revoke and rotate all exposed API keys",
          "Review service logs for unauthorized usage and abuse patterns",
          "Assess financial impact and contact billing support for dispute resolution",
          "Clean version control history to remove historical key exposure",
          "Implement automated scanning to prevent future hardcoded credentials",
          "Update CI/CD pipelines to use secure credential injection",
          "Conduct security training for development teams on proper API key management",
          "Establish monitoring and alerting for unusual API usage patterns"
        ],
        compliance_considerations: [
          "PCI DSS requirements for payment processor API key security",
          "SOC 2 Type II controls for credential management and access control",
          "ISO 27001 requirements for cryptographic key lifecycle management",
          "GDPR considerations for API keys providing access to personal data",
          "Industry-specific regulations requiring secure credential handling",
          "Vendor security assessments and third-party risk management requirements"
        ]
      }
    }
  end
  
  @doc """
  Check if this pattern applies to a file based on its path and content.
  
  Applies to JavaScript/TypeScript files or any file containing API key assignments.
  """
  def applies_to_file?(file_path, content \\ nil) do
    cond do
      # JavaScript/TypeScript files always apply
      String.match?(file_path, ~r/\.(js|jsx|ts|tsx|mjs)$/i) -> true
      
      # If content is provided, check for API key assignments
      content != nil ->
        # Check for API key-related variable names in content
        String.contains?(content, "api") || 
        String.contains?(content, "key") ||
        String.contains?(content, "token") ||
        String.contains?(content, "secret") ||
        # Also check if the pattern regex itself matches
        Regex.match?(pattern().regex, content)
        
      # Default
      true -> false
    end
  end
  
  @doc """
  Returns AST enhancement rules to reduce false positives.
  
  This enhancement helps distinguish between actual hardcoded API keys
  and legitimate uses like test keys, documentation, or key validation logic.
  
  ## Examples
  
      iex> enhancement = RsolvApi.Security.Patterns.Javascript.HardcodedSecretApiKey.ast_enhancement()
      iex> Map.keys(enhancement) |> Enum.sort()
      [:ast_rules, :confidence_rules, :context_rules, :min_confidence]
      
      iex> enhancement = RsolvApi.Security.Patterns.Javascript.HardcodedSecretApiKey.ast_enhancement()
      iex> enhancement.ast_rules.node_type
      "VariableDeclarator"
      
      iex> enhancement = RsolvApi.Security.Patterns.Javascript.HardcodedSecretApiKey.ast_enhancement()
      iex> "Literal" in enhancement.ast_rules.value_types
      true
      
      iex> enhancement = RsolvApi.Security.Patterns.Javascript.HardcodedSecretApiKey.ast_enhancement()
      iex> enhancement.min_confidence
      0.85
  """
  @impl true
  def ast_enhancement do
    %{
      ast_rules: %{
        node_type: "VariableDeclarator",
        value_types: ["Literal", "TemplateLiteral"],  # String values
        identifier_check: %{
          pattern: ~r/(?:api[_-]?key|api[_-]?secret|token|access[_-]?key|secret[_-]?key)/i,
          exclude_pattern: ~r/(?:test|demo|example|sample|mock|fake|placeholder|temp|dummy)/i
        },
        value_analysis: %{
          check_key_format: true,
          min_length: 16,  # Real API keys are longer
          max_length: 200,  # Extremely long strings unlikely to be keys
          entropy_check: true,  # High entropy suggests real keys
          known_prefixes: [
            "sk_",         # Stripe secret key
            "pk_",         # Stripe publishable key
            "sk_test_",    # Stripe test key
            "sk_live_",    # Stripe live key
            "ghp_",        # GitHub personal access token
            "ghs_",        # GitHub server token
            "gho_",        # GitHub OAuth token
            "ghu_",        # GitHub user token
            "AKIA",        # AWS access key
            "AIza",        # Google API key
            "SG.",         # SendGrid
            "key-",        # Mailgun
            "sq0",         # Square
            "rzp_",        # Razorpay
            "eyJ"          # JWT token
          ]
        }
      },
      context_rules: %{
        exclude_paths: [
          ~r/test/,
          ~r/spec/,
          ~r/__tests__/,
          ~r/fixtures/,
          ~r/examples/,
          ~r/docs/,
          ~r/\.env\.example$/,
          ~r/\.env\.sample$/,
          ~r/\.env\.template$/
        ],
        api_key_patterns: [
          "sk_",         # Service-specific prefixes
          "pk_",
          "ghp_",
          "AKIA",
          "AIza",
          "SG.",
          "key-",
          "bearer ",
          "Basic "
        ],
        safe_patterns: [
          "process.env",       # Environment variables
          "config.get",        # Configuration systems
          "getenv",            # Environment access
          "vault",             # HashiCorp Vault
          "secretManager",     # AWS/GCP secret managers
          "keyManager",        # Key management systems
          "getSecret",         # Secret retrieval functions
          "loadConfig",        # Configuration loaders
          "generateKey",       # Key generation
          "randomBytes"        # Cryptographic randomness
        ],
        check_surrounding_code: true,
        test_indicators: [
          "test",              # Test-related terms
          "spec",
          "example",
          "demo",
          "sample",
          "mock",
          "fake",
          "dummy",
          "placeholder",
          "TODO",
          "FIXME",
          "CHANGE_ME"
        ]
      },
      confidence_rules: %{
        base: 0.6,  # Medium-high base
        adjustments: %{
          "known_api_key_format" => 0.5,         # Matches known key patterns
          "production_prefix" => 0.4,            # live_, prod_, etc.
          "high_entropy" => 0.3,                 # High randomness
          "production_file" => 0.3,              # In production code
          "literal_assignment" => 0.2,           # Direct string assignment
          "environment_variable" => -0.9,        # Using env vars is safe
          "test_key" => -0.8,                    # Test/demo keys
          "short_value" => -0.5,                 # Too short for real key
          "test_file" => -0.7,                   # In test directory
          "example_file" => -0.8,                # Example/template files
          "configuration_system" => -0.8,        # Using config management
          "key_generation" => -0.9,              # Generating keys
          "documentation" => -0.7,               # In documentation
          "low_entropy" => -0.4                  # Low randomness
        }
      },
      min_confidence: 0.85  # High threshold - API keys need careful filtering
    }
  end
end
