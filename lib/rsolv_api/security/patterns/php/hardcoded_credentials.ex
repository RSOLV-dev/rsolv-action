defmodule RsolvApi.Security.Patterns.Php.HardcodedCredentials do
  @moduledoc """
  Pattern for detecting hardcoded credentials in PHP code.
  
  This pattern identifies when sensitive credentials like passwords, API keys,
  tokens, and secrets are hardcoded directly in the source code. This is a
  critical security vulnerability as it exposes credentials to anyone with
  access to the codebase.
  
  ## Vulnerability Details
  
  Hardcoded credentials are one of the most common and dangerous security
  vulnerabilities. They expose sensitive authentication data in source code,
  version control systems, and compiled applications. This can lead to
  unauthorized access, data breaches, and complete system compromise.
  
  ### Attack Example
  ```php
  // Vulnerable code
  $password = "admin123";
  $api_key = "sk-1234567890abcdef";
  
  // Anyone with code access can see these credentials
  // They're also visible in version control history
  ```
  """
  
  use RsolvApi.Security.Patterns.PatternBase
  alias RsolvApi.Security.Pattern
  
  @impl true
  def pattern do
    %Pattern{
      id: "php-hardcoded-credentials",
      name: "Hardcoded Credentials",
      description: "Credentials embedded directly in source code",
      type: :hardcoded_secret,
      severity: :critical,
      languages: ["php"],
      regex: ~r/(?:\$(?:password|passwd|pwd|mysql_pwd|db_password|api_key|apikey|secret|token|auth_token|secret_key)|password|api_key|secret|token)\s*[=:]\s*['"][^'"]{3,}['"]|define\s*\(\s*['"](?:DB_)?(?:PASSWORD|API_KEY|SECRET|TOKEN|AUTH_TOKEN|SECRET_KEY|SECRET_TOKEN)['"]\s*,\s*['"][^'"]{3,}['"]\)|['"](?:password|api_key|secret|token)['"]\s*=>\s*['"][^'"]{3,}['"]/i,
      cwe_id: "CWE-798",
      owasp_category: "A07:2021",
      recommendation: "Use environment variables or secure configuration management",
      test_cases: %{
        vulnerable: [
          ~S|$password = "admin123";|,
          ~S|$api_key = "sk-1234567890abcdef";|,
          ~S|define('DB_PASSWORD', 'mysecret');|,
          ~S|$config = ['password' => 'admin123'];|
        ],
        safe: [
          ~S|$password = $_ENV['DB_PASSWORD'];|,
          ~S|$api_key = getenv('API_KEY');|
        ]
      }
    }
  end
  
  @impl true
  def vulnerability_metadata do
    %{
      description: """
      Hardcoded credentials are a critical security vulnerability where sensitive
      authentication data is embedded directly in source code. This practice exposes
      passwords, API keys, tokens, and other secrets to anyone who can access the
      codebase, including developers, contractors, and potential attackers.
      
      Why hardcoded credentials are dangerous:
      - Visible in source code repositories
      - Cannot be rotated without code changes
      - Exposed in version control history forever
      - Accessible to all developers and systems
      - Often forgotten and left in production code
      - Easily discovered by automated scanners
      
      The risk is amplified when code is:
      - Stored in public repositories
      - Shared with third parties
      - Deployed to multiple environments
      - Subject to compliance requirements
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
          type: :cwe,
          id: "CWE-259",
          title: "Use of Hard-coded Password",
          url: "https://cwe.mitre.org/data/definitions/259.html"
        },
        %{
          type: :cwe,
          id: "CWE-321",
          title: "Use of Hard-coded Cryptographic Key",
          url: "https://cwe.mitre.org/data/definitions/321.html"
        }
      ],
      attack_vectors: [
        "Source code access: Reading credentials directly from code",
        "Version control: Finding credentials in git history",
        "Compiled code: Extracting strings from binaries",
        "Configuration files: Accessing unprotected config files",
        "Memory dumps: Reading credentials from process memory",
        "Log files: Credentials accidentally logged",
        "Error messages: Credentials exposed in stack traces",
        "Public repositories: Automated scanning for secrets"
      ],
      real_world_impact: [
        "Complete system compromise through admin credentials",
        "Data breaches via database passwords",
        "Financial loss through API key abuse",
        "Service disruption by revoking exposed keys",
        "Compliance violations (PCI-DSS, GDPR, HIPAA)",
        "Reputation damage from security incidents",
        "Legal liability for negligent security practices"
      ],
      cve_examples: [
        %{
          id: "CVE-2024-4007",
          description: "ABB Cylon Aspect hardcoded default credentials",
          severity: "critical",
          cvss: 9.8,
          note: "Default credentials allow remote access to building control systems"
        },
        %{
          id: "CVE-2021-34812",
          description: "Synology Calendar hardcoded credentials",
          severity: "high",
          cvss: 8.8,
          note: "Hardcoded credentials in PHP component allow information disclosure"
        },
        %{
          id: "CVE-2020-24115",
          description: "Hardcoded admin credentials in source code",
          severity: "critical",
          cvss: 9.8,
          note: "Admin panel access through hardcoded credentials in PHP application"
        },
        %{
          id: "CVE-2019-9193",
          description: "PostgreSQL JDBC hardcoded credentials",
          severity: "critical",
          cvss: 9.8,
          note: "Database credentials hardcoded in connection strings"
        }
      ],
      detection_notes: """
      This pattern detects hardcoded credentials by looking for:
      - Variable assignments with credential-related names
      - PHP define() statements with credential constants
      - Array assignments with credential keys
      - Common patterns like $password = "value"
      
      The regex requires credential values to be at least 3 characters
      to reduce false positives from empty strings or placeholders.
      """,
      safe_alternatives: [
        "Use environment variables via $_ENV or getenv()",
        "Store credentials in external configuration files (outside web root)",
        "Use secure key management services (AWS KMS, HashiCorp Vault)",
        "Implement proper secrets management with rotation",
        "Use PHP dotenv library for .env file management",
        "Leverage cloud provider secret managers",
        "Use configuration management tools (Ansible, Chef)",
        "Implement least privilege access controls"
      ],
      additional_context: %{
        common_mistakes: [
          "Committing .env files to version control",
          "Using weak or default passwords",
          "Sharing credentials across environments",
          "Not rotating credentials regularly",
          "Logging credentials accidentally",
          "Using the same credentials everywhere"
        ],
        secure_patterns: [
          "$password = $_ENV['DB_PASSWORD']",
          "$apiKey = getenv('API_KEY')",
          "$secret = file_get_contents('/etc/secrets/app.key')",
          "$config = parse_ini_file('/secure/config.ini')",
          "$token = $secretManager->getSecret('auth-token')"
        ],
        php_specific_notes: [
          "putenv() can set environment variables at runtime",
          "php.ini can disable certain functions for security",
          ".env files should never be in document root",
          "Use .gitignore to exclude sensitive files",
          "opcache can cache credentials in memory"
        ]
      }
    }
  end
  
  @doc """
  Returns test cases for the pattern.
  
  ## Examples
  
      iex> test_cases = RsolvApi.Security.Patterns.Php.HardcodedCredentials.test_cases()
      iex> length(test_cases.positive) > 0
      true
      
      iex> test_cases = RsolvApi.Security.Patterns.Php.HardcodedCredentials.test_cases()
      iex> length(test_cases.negative) > 0
      true
      
      iex> pattern = RsolvApi.Security.Patterns.Php.HardcodedCredentials.pattern()
      iex> pattern.id
      "php-hardcoded-credentials"
  """
  def test_cases do
    %{
      positive: [
        %{
          code: ~S|$password = "admin123";|,
          description: "Direct password assignment"
        },
        %{
          code: ~S|$db_password = 'secretpassword';|,
          description: "Database password"
        },
        %{
          code: ~S|$api_key = "sk-1234567890abcdef";|,
          description: "API key assignment"
        },
        %{
          code: ~S|define('DB_PASSWORD', 'mysecret');|,
          description: "Password in constant"
        },
        %{
          code: ~S|$config = ['password' => 'admin123'];|,
          description: "Password in array"
        },
        %{
          code: ~S|$secret_key = "AKIAIOSFODNN7EXAMPLE";|,
          description: "AWS-like secret key"
        },
        %{
          code: ~S|$token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";|,
          description: "JWT token"
        }
      ],
      negative: [
        %{
          code: ~S|$password = $_ENV['DB_PASSWORD'];|,
          description: "Environment variable"
        },
        %{
          code: ~S|$api_key = getenv('API_KEY');|,
          description: "getenv() function"
        },
        %{
          code: ~S|$secret = config('app.secret');|,
          description: "Configuration function"
        },
        %{
          code: ~S|$token = env('AUTH_TOKEN');|,
          description: "Laravel env helper"
        },
        %{
          code: ~S|$key = '';|,
          description: "Empty string"
        },
        %{
          code: ~S|$password = null;|,
          description: "Null assignment"
        },
        %{
          code: ~S|// $password = "commented_out";|,
          description: "Commented code"
        }
      ]
    }
  end
  
  @doc """
  Returns examples of vulnerable and fixed code.
  """
  def examples do
    %{
      vulnerable: %{
        "Database connection" => ~S"""
        // Database configuration - VULNERABLE
        $db_host = 'localhost';
        $db_user = 'admin';
        $db_password = 'admin123';  // Hardcoded password!
        $db_name = 'production_db';
        
        $connection = mysqli_connect($db_host, $db_user, $db_password, $db_name);
        
        // Anyone with code access can connect to your database
        """,
        "API integration" => ~S"""
        // Third-party API - VULNERABLE
        class PaymentGateway {
            private $api_key = 'sk-live-4eC39HqLyjWDarjtT1zdp7dc';
            private $secret = 'whsec_VfKbDlhWQWq0p5qDVHqFd7L7';
            
            public function processPayment($amount) {
                $headers = [
                    'Authorization: Bearer ' . $this->api_key,
                    'Webhook-Secret: ' . $this->secret
                ];
                // Process payment...
            }
        }
        
        // API keys exposed in source code
        """,
        "Configuration file" => ~S"""
        // config.php - VULNERABLE
        <?php
        define('DB_HOST', 'prod.database.com');
        define('DB_USER', 'root');
        define('DB_PASSWORD', 'MyStr0ngP@ssw0rd!');
        define('DB_NAME', 'company_data');
        
        define('SMTP_PASSWORD', 'smtp_secret_123');
        define('API_KEY', 'AKIAIOSFODNN7EXAMPLE');
        define('SECRET_KEY', 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY');
        
        // All credentials visible to anyone
        """,
        "Multiple services" => ~S"""
        // Service credentials - VULNERABLE
        $services = [
            'database' => [
                'host' => 'db.internal',
                'username' => 'app_user',
                'password' => 'db_password_2023'  // Hardcoded!
            ],
            'redis' => [
                'host' => 'redis.internal',
                'password' => 'redis_secret_key'   // Hardcoded!
            ],
            'elasticsearch' => [
                'api_key' => 'es_api_key_xyz789'  // Hardcoded!
            ]
        ];
        """
      },
      fixed: %{
        "Using environment variables" => ~S"""
        // Database configuration - SECURE
        $db_host = $_ENV['DB_HOST'] ?? 'localhost';
        $db_user = $_ENV['DB_USER'] ?? 'app';
        $db_password = $_ENV['DB_PASSWORD'];  // Required, no default
        $db_name = $_ENV['DB_NAME'] ?? 'app_db';
        
        if (empty($db_password)) {
            throw new Exception('Database password not configured');
        }
        
        $connection = mysqli_connect($db_host, $db_user, $db_password, $db_name);
        
        // Credentials stored securely outside code
        """,
        "Configuration file approach" => ~S"""
        // Secure configuration management
        class Config {
            private $secrets;
            
            public function __construct() {
                // Load from secure location outside web root
                $config_file = '/etc/myapp/secrets.json';
                
                if (!file_exists($config_file)) {
                    throw new Exception('Configuration file not found');
                }
                
                $contents = file_get_contents($config_file);
                $this->secrets = json_decode($contents, true);
                
                // Clear from memory after parsing
                unset($contents);
            }
            
            public function get($key) {
                return $this->secrets[$key] ?? null;
            }
        }
        
        // Usage
        $config = new Config();
        $api_key = $config->get('payment_api_key');
        """,
        "Using dotenv library" => ~S"""
        // Using vlucas/phpdotenv - SECURE
        require_once 'vendor/autoload.php';
        
        // Load .env file from outside web root
        $dotenv = Dotenv\Dotenv::createImmutable('/var/www/config');
        $dotenv->load();
        
        // Required variables
        $dotenv->required(['DB_HOST', 'DB_NAME', 'DB_USER', 'DB_PASS']);
        $dotenv->required('API_KEY')->notEmpty();
        
        // Access via $_ENV
        $db_config = [
            'host' => $_ENV['DB_HOST'],
            'database' => $_ENV['DB_NAME'],
            'username' => $_ENV['DB_USER'],
            'password' => $_ENV['DB_PASS']
        ];
        
        // .env file (never commit this!)
        // DB_HOST=localhost
        // DB_NAME=myapp
        // DB_USER=myapp_user
        // DB_PASS=secure_random_password
        // API_KEY=your_actual_api_key
        """,
        "Key management service" => ~S"""
        // Using AWS Secrets Manager - SECURE
        use Aws\SecretsManager\SecretsManagerClient;
        
        class SecretManager {
            private $client;
            private $cache = [];
            
            public function __construct() {
                $this->client = new SecretsManagerClient([
                    'version' => 'latest',
                    'region' => $_ENV['AWS_REGION']
                ]);
            }
            
            public function getSecret($secretName) {
                // Check cache first
                if (isset($this->cache[$secretName])) {
                    return $this->cache[$secretName];
                }
                
                try {
                    $result = $this->client->getSecretValue([
                        'SecretId' => $secretName
                    ]);
                    
                    $secret = json_decode($result['SecretString'], true);
                    
                    // Cache for this request only
                    $this->cache[$secretName] = $secret;
                    
                    return $secret;
                } catch (Exception $e) {
                    error_log('Failed to retrieve secret: ' . $secretName);
                    throw $e;
                }
            }
        }
        
        // Usage
        $secrets = new SecretManager();
        $dbCreds = $secrets->getSecret('prod/database/credentials');
        $apiKey = $secrets->getSecret('prod/payment/api-key');
        """
      }
    }
  end
  
  @doc """
  Returns detailed vulnerability description.
  """
  def vulnerability_description do
    """
    Hardcoded credentials represent one of the most critical security vulnerabilities
    in software development. When passwords, API keys, tokens, or other authentication
    secrets are embedded directly in source code, they become permanently exposed to
    anyone who gains access to that code.
    
    ## The Danger of Hardcoded Credentials
    
    ### Immediate Risks
    
    1. **Source Code Exposure**
       - Visible to all developers
       - Stored in version control forever
       - Accessible in code reviews
       - Exposed in build artifacts
    
    2. **Credential Lifecycle Issues**
       - Cannot rotate without code changes
       - No audit trail of access
       - No expiration management
       - Shared across all environments
    
    3. **Compliance Violations**
       - PCI-DSS: Requires credential protection
       - GDPR: Demands data security
       - HIPAA: Mandates access controls
       - SOC 2: Requires secure practices
    
    ## Common Scenarios
    
    ### Database Passwords
    ```php
    $conn = new PDO('mysql:host=localhost;dbname=prod', 
                    'root', 'admin123');  // NEVER DO THIS!
    ```
    
    ### API Keys
    ```php
    $stripe = new StripeClient('sk_live_4eC39HqLyjWDarjtT1zdp7dc');
    ```
    
    ### Service Credentials
    ```php
    define('SMTP_USER', 'admin@company.com');
    define('SMTP_PASS', 'EmailPassword123!');
    ```
    
    ## Attack Scenarios
    
    ### 1. Public Repository Exposure
    - Code pushed to GitHub/GitLab
    - Forks retain credential history
    - Automated scanners find secrets
    - Credentials exploited within minutes
    
    ### 2. Supply Chain Attacks
    - Third-party developer access
    - Contractor code reviews
    - Open source contributions
    - Vendor security breaches
    
    ### 3. Internal Threats
    - Disgruntled employees
    - Accidental exposure
    - Insufficient access controls
    - Shared development environments
    
    ## Detection Methods
    
    Attackers use various techniques to find hardcoded credentials:
    
    1. **Automated Scanning**
       - GitHub secret scanning
       - TruffleHog
       - GitGuardian
       - AWS git-secrets
    
    2. **Manual Search**
       - grep for password patterns
       - Search for API key formats
       - Review configuration files
       - Analyze commit history
    
    3. **Binary Analysis**
       - Extract strings from compiled code
       - Decompile applications
       - Memory dump analysis
       - Network traffic inspection
    
    ## Secure Credential Management
    
    ### Environment Variables
    ```php
    $password = $_ENV['DB_PASSWORD'];
    if (empty($password)) {
        throw new Exception('Database password not configured');
    }
    ```
    
    ### Configuration Files
    - Store outside web root
    - Set restrictive permissions
    - Encrypt sensitive values
    - Never commit to version control
    
    ### Secret Management Systems
    - AWS Secrets Manager
    - HashiCorp Vault
    - Azure Key Vault
    - Kubernetes Secrets
    
    ### Best Practices
    
    1. **Never hardcode credentials**
    2. **Use strong, unique passwords**
    3. **Rotate credentials regularly**
    4. **Implement least privilege**
    5. **Audit credential access**
    6. **Use encryption at rest**
    7. **Monitor for exposed secrets**
    
    ## Remediation Steps
    
    If credentials are already hardcoded:
    
    1. **Immediate Actions**
       - Rotate all exposed credentials
       - Remove from current code
       - Clean git history
       - Audit access logs
    
    2. **Long-term Solutions**
       - Implement secret management
       - Add pre-commit hooks
       - Configure CI/CD scanning
       - Train development team
    
    Remember: Once a credential is committed to version control,
    it should be considered compromised forever. The only safe
    action is to rotate it immediately.
    """
  end
  
  @doc """
  Returns AST enhancement rules to reduce false positives.
  
  ## Examples
  
      iex> enhancement = RsolvApi.Security.Patterns.Php.HardcodedCredentials.ast_enhancement()
      iex> Map.keys(enhancement) |> Enum.sort()
      [:ast_rules, :min_confidence]
      
      iex> enhancement = RsolvApi.Security.Patterns.Php.HardcodedCredentials.ast_enhancement()
      iex> enhancement.min_confidence
      0.85
      
      iex> enhancement = RsolvApi.Security.Patterns.Php.HardcodedCredentials.ast_enhancement()
      iex> length(enhancement.ast_rules)
      5
  """
  @impl true
  def ast_enhancement do
    %{
      ast_rules: [
        %{
          type: "credential_indicators",
          description: "Common credential variable names",
          keywords: [
            "password",
            "passwd",
            "pwd",
            "pass",
            "secret",
            "api_key",
            "apikey", 
            "token",
            "auth",
            "credential",
            "private_key",
            "secret_key"
          ],
          exclude: [
            "password_hash",
            "password_verify",
            "password_strength",
            "token_generate"
          ]
        },
        %{
          type: "safe_patterns",
          description: "Patterns indicating secure credential handling",
          functions: [
            "getenv",
            "env",
            "$_ENV",
            "$_SERVER",
            "parse_ini_file",
            "file_get_contents",
            "config",
            "settings"
          ]
        },
        %{
          type: "value_analysis",
          description: "Analyze assigned values",
          patterns: [
            "Length > 3 characters",
            "Not empty string",
            "Not null/false",
            "Not placeholder text",
            "Contains mixed characters"
          ],
          placeholders: [
            "xxx",
            "...",
            "changeme",
            "your_password_here",
            "placeholder"
          ]
        },
        %{
          type: "context_analysis",
          description: "Analyze surrounding code context",
          safe_contexts: [
            "Example code",
            "Documentation",
            "Test files",
            "Mock data",
            "Default configs"
          ]
        },
        %{
          type: "string_entropy",
          description: "Check string randomness",
          thresholds: [
            "High entropy suggests real secret",
            "Low entropy might be example",
            "Repeated patterns indicate fake"
          ]
        }
      ],
      min_confidence: 0.85
    }
  end
end
