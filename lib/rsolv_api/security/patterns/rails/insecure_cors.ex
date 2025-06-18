defmodule RsolvApi.Security.Patterns.Rails.InsecureCors do
  @moduledoc """
  Rails Insecure CORS Configuration pattern for Rails applications.
  
  This pattern detects insecure Cross-Origin Resource Sharing (CORS) configurations
  in Rails applications that could lead to security vulnerabilities. CORS 
  misconfigurations are a common source of vulnerabilities that allow unauthorized
  cross-origin requests and can expose sensitive data to malicious websites.
  
  ## Background
  
  CORS is a mechanism that allows servers to specify which origins are permitted
  to access resources from a web page. Misconfigured CORS policies can lead to
  serious security vulnerabilities including unauthorized data access, credential
  theft, and cross-site scripting attacks.
  
  ## Vulnerability Details
  
  The vulnerability occurs when:
  1. Origins are set to wildcard "*" with credentials enabled
  2. Headers are set to :any or "*" allowing any headers
  3. Methods are set to :any or "*" allowing any HTTP methods
  4. Dynamic origins with overly permissive regex patterns
  5. Direct header manipulation with wildcard values
  6. Insecure rack-cors configurations
  
  ## Known CVEs
  
  - CVE-2024-25124: CORS middleware insecure configurations leading to vulnerabilities
  - CVE-2021-27786: CORS bypass vulnerabilities in web applications
  - Multiple rack-cors configuration vulnerabilities
  - Fiber CORS middleware vulnerabilities (GHSA-fmg4-x8pw-hjhg)
  
  ## Examples
  
      # Critical - Wildcard origin with credentials
      allow do
        origins '*'
        credentials true
      end
      
      # Critical - Wildcard headers/methods
      allow do
        origins '*'
        headers :any
        methods :any
      end
      
      # Critical - Overly permissive regex
      origins /.*\\.domain\\.com/
      
      # Safe - Specific origins with credentials
      allow do
        origins 'https://example.com'
        credentials true
      end
  """
  
  use RsolvApi.Security.Patterns.PatternBase
  
  def pattern do
    %RsolvApi.Security.Pattern{
      id: "rails-insecure-cors",
      name: "Insecure CORS Configuration", 
      description: "Overly permissive Cross-Origin Resource Sharing configuration",
      type: :security_misconfiguration,
      severity: :medium,
      languages: ["ruby"],
      frameworks: ["rails"],
      regex: [
        # Wildcard origins with any configuration (exclude comments)
        ~r/^(?!.*#).*origins\s+["']?\*["']?/,
        
        # Wildcard headers configuration  
        ~r/headers\s+:any/,
        ~r/headers\s+["']?\*["']?/,
        ~r/headers:\s*:any/,
        ~r/headers:\s*["']?\*["']?/,
        
        # Wildcard methods configuration
        ~r/methods\s+:any/,
        ~r/methods\s+["']?\*["']?/,
        ~r/methods:\s*:any/,
        ~r/methods:\s*["']?\*["']?/,
        
        # Dangerous wildcard origins with credentials (multiline)
        ~r/origins\s+["']?\*["']?.*?credentials\s+true/s,
        
        # Direct header manipulation with wildcards
        ~r/response\.headers\[["']Access-Control-Allow-Origin["']\]\s*=\s*["']\*["']/,
        ~r/headers\[["']Access-Control-Allow-Origin["']\]\s*=\s*["']\*["']/,
        
        # Resource configurations with wildcards
        ~r/resource\s+["']?\*["']?,?\s*.*?origins:\s*["']?\*["']?/,
        ~r/resource\s+["'][^"']+["'],\s*.*?origins:\s*["']?\*["']?/,
        ~r/resource\s+["']?\*["']?,?\s*.*?headers:\s*:any/,
        ~r/resource\s+["']?\*["']?,?\s*.*?methods:\s*:any/,
        
        # Insecure rack-cors configurations
        ~r/Rack::Cors\s+do.*?origins\s+["']?\*["']?/s,
        ~r/use\s+Rack::Cors.*?origins\s+["']?\*["']?/s,
        
        # Overly permissive regex patterns
        ~r/origins\s+\/\.\*\\?\./,  # Any domain patterns like /.*/
        ~r/origins\s+\/https?\?\:\\?\/\\?\//,  # Any protocol patterns
        
        # Dynamic origins that return true for everything
        ~r/origins\s+->\s*\(.*?\)\s*\{\s*true\s*\}/,
        ~r/origins\s+lambda.*?\{\s*.*?true.*?\}/,
        ~r/origins\s+proc.*?\{\s*.*?true.*?\}/
      ],
      default_tier: :ai,
      cwe_id: "CWE-346",
      owasp_category: "A05:2021",
      recommendation: "Specify explicit origins, headers, and methods in Rails CORS. Never use credentials: true with origins: \"*\" in Rails",
      test_cases: %{
        vulnerable: [
          "origins \"*\"\\ncredentials true",
          "headers :any",
          "methods :any",
          "resource '*', origins: '*', credentials: true"
        ],
        safe: [
          "origins \"https://example.com\"\\ncredentials true",
          "headers ['Content-Type', 'Authorization']",
          "methods ['GET', 'POST', 'PUT', 'DELETE']",
          "origins ['https://example.com', 'https://api.example.com']"
        ]
      }
    }
  end
  
  def vulnerability_metadata do
    %{
      description: """
      Insecure CORS Configuration in Rails applications represents a critical 
      security misconfiguration where Cross-Origin Resource Sharing policies 
      are configured too permissively, allowing unauthorized cross-origin 
      requests. This vulnerability most commonly occurs when using wildcard 
      origins ("*") combined with credentials, or when allowing any headers 
      or methods without proper restrictions. Such misconfigurations can lead 
      to unauthorized data access, credential theft, and bypass of same-origin 
      policy protections.
      
      The vulnerability is particularly dangerous because:
      1. It bypasses fundamental browser security mechanisms
      2. CORS misconfigurations can expose sensitive API endpoints
      3. Wildcard origins with credentials violate CORS specifications
      4. It can enable sophisticated cross-site scripting attacks
      5. Many developers misunderstand CORS security implications
      """,
      
      attack_vectors: """
      1. **Credential Theft via Wildcard Origins**: Malicious sites access authenticated APIs
      2. **Cross-Origin Data Exfiltration**: Unauthorized reading of sensitive API responses
      3. **CSRF Bypass**: Circumventing CSRF protections through permissive CORS
      4. **Cookie and Session Hijacking**: Accessing authentication cookies cross-origin
      5. **API Enumeration**: Discovering and exploiting internal API endpoints
      6. **Cross-Site Scripting (XSS) Amplification**: Using CORS to amplify XSS impact
      7. **Subdomain Takeover Exploitation**: Leveraging wildcard subdomain CORS policies
      8. **Man-in-the-Middle Attacks**: Exploiting HTTP origins in HTTPS applications
      9. **Client-Side Template Injection**: Injecting templates via permissive CORS
      10. **Authentication Bypass**: Using CORS to bypass authentication mechanisms
      """,
      
      business_impact: """
      - Unauthorized access to sensitive customer data and business information
      - Data breach exposing customer personal information and financial data
      - Compliance violations under GDPR, PCI DSS, and other regulatory frameworks
      - Identity theft and financial fraud through exposed user credentials
      - Intellectual property theft through unauthorized API access
      - Reputation damage from security incidents and data exposure
      - Legal liability from compromised customer accounts and data
      - Business disruption from security incidents and incident response
      - Loss of customer trust and potential customer churn
      - Financial losses from fraud and regulatory fines
      """,
      
      technical_impact: """
      - Complete bypass of same-origin policy browser protections
      - Unauthorized access to authenticated API endpoints and resources
      - Exposure of sensitive data through cross-origin requests
      - Authentication and session management bypass
      - CSRF protection circumvention
      - Cross-site scripting attack facilitation and amplification
      - Potential for privilege escalation through API access
      - Database access through compromised API endpoints
      - Internal network scanning and service discovery
      - Credential harvesting and session hijacking
      """,
      
      likelihood: "High - CORS misconfigurations are extremely common due to developer misunderstanding of CORS security implications and convenience of wildcard configurations",
      
      cve_examples: """
      CVE-2024-25124 - CORS middleware insecure configurations in web frameworks
      CVE-2021-27786 - CORS bypass vulnerabilities allowing unauthorized cross-origin requests
      GHSA-fmg4-x8pw-hjhg - Fiber CORS middleware wildcard origin with credentials vulnerability
      CVE-2024-27456 - rack-cors insecure file permissions leading to configuration exposure
      Multiple rack-cors configuration vulnerabilities in Rails applications
      GitHub Advisory Database contains numerous CORS misconfiguration vulnerabilities
      OWASP Top 10 2021 includes security misconfigurations as A05
      Common CORS vulnerabilities in Fortune 500 company APIs and web applications
      """,
      
      compliance_standards: [
        "OWASP Top 10 2021 - A05: Security Misconfiguration",
        "CWE-346: Origin Validation Error",
        "CWE-942: Overly Permissive Cross-domain Whitelist",
        "PCI DSS 6.5.1 - Injection flaws and cross-site scripting",
        "NIST SP 800-53 - SC-23 Session Authenticity",
        "ISO 27001 - A.14.2.5 Secure system engineering principles",
        "ASVS 4.0 - V14.5 HTTP Security Headers Verification Requirements",
        "SANS Top 25 - CWE-346 Origin Validation Error"
      ],
      
      remediation_steps: """
      1. **Secure CORS Configuration (Critical)**:
         ```ruby
         # In config/initializers/cors.rb
         
         # NEVER do this - Dangerous CORS misconfigurations
         Rails.application.config.middleware.insert_before 0, Rack::Cors do
           allow do
             origins '*'                    # DANGEROUS - Wildcard origin
             credentials true               # DANGEROUS - With credentials
             headers :any                   # DANGEROUS - Any headers
             methods :any                   # DANGEROUS - Any methods
           end
         end
         
         # Always use explicit, secure CORS configuration
         Rails.application.config.middleware.insert_before 0, Rack::Cors do
           allow do
             origins 'https://example.com', 'https://api.example.com'  # Specific origins
             credentials true               # Safe with specific origins
             headers %w[Content-Type Authorization X-Requested-With]   # Explicit headers
             methods %w[GET POST PUT DELETE OPTIONS]                   # Explicit methods
             expose %w[X-Total-Count]       # Explicitly expose headers if needed
           end
         ```
      
      2. **Environment-Specific Configuration**:
         ```ruby
         # config/initializers/cors.rb
         Rails.application.config.middleware.insert_before 0, Rack::Cors do
           allow do
             if Rails.env.development?
               # More permissive for development (but still secure)
               origins 'http://localhost:3000', 'http://127.0.0.1:3000'
               credentials true
               headers %w[Content-Type Authorization X-Requested-With]
               methods %w[GET POST PUT DELETE OPTIONS]
             elsif Rails.env.production?
               # Strict configuration for production
               origins 'https://yourdomain.com', 'https://app.yourdomain.com'
               credentials true
               headers %w[Content-Type Authorization]
               methods %w[GET POST PUT DELETE]
             end
           end
         ```
      
      3. **Multiple Resource Configuration**:
         ```ruby
         Rails.application.config.middleware.insert_before 0, Rack::Cors do
           # Public API endpoints (no credentials)
           allow do
             origins 'https://example.com'
             resource '/api/public/*',
               headers: %w[Content-Type],
               methods: %w[GET]
           end
           
           # Authenticated API endpoints
           allow do
             origins 'https://trusted-app.com'
             resource '/api/private/*',
               headers: %w[Content-Type Authorization],
               methods: %w[GET POST PUT DELETE],
               credentials: true
           end
         ```
      
      4. **Dynamic Origin Validation (Advanced)**:
         ```ruby
         # Safe dynamic origin validation
         ALLOWED_ORIGINS = %w[
           https://example.com
           https://app.example.com
           https://staging.example.com
         ].freeze
         
         Rails.application.config.middleware.insert_before 0, Rack::Cors do
           allow do
             origins ->(source, env) {
               # Validate against explicit allowlist
               ALLOWED_ORIGINS.include?(source)
             }
             credentials true
             headers %w[Content-Type Authorization]
             methods %w[GET POST PUT DELETE]
           end
         ```
      
      5. **CORS Security Headers**:
         ```ruby
         # In ApplicationController or specific controllers
         class ApplicationController < ActionController::Base
           before_action :set_cors_headers, if: :cors_request?
           
           private
           
           def cors_request?
             request.headers['Origin'].present?
           end
           
           def set_cors_headers
             origin = request.headers['Origin']
             
             # Validate origin against allowlist
             if valid_origin?(origin)
               response.headers['Access-Control-Allow-Origin'] = origin
               response.headers['Access-Control-Allow-Credentials'] = 'true'
               response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
               response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE'
             end
           end
           
           def valid_origin?(origin)
             allowed_origins = %w[
               https://example.com
               https://app.example.com
             ]
             allowed_origins.include?(origin)
           end
         ```
      """,
      
      prevention_tips: """
      - Never use wildcard "*" origins with credentials: true
      - Always specify explicit allowed origins using HTTPS
      - Use specific headers and methods rather than :any or "*"
      - Regularly audit CORS configurations in all environments
      - Implement origin validation using explicit allowlists
      - Avoid overly permissive regex patterns for dynamic origins
      - Use environment-specific CORS configurations
      - Monitor CORS-related security headers in responses
      - Test CORS configurations with security scanning tools
      - Document and review all CORS policy decisions
      - Implement automated tests for CORS security configurations
      - Regular security training on CORS vulnerabilities for developers
      """,
      
      detection_methods: """
      - Static analysis with Brakeman scanner (detects CORS misconfigurations)
      - Manual code review of config/initializers/cors.rb and controller files
      - Browser developer tools inspection of CORS-related response headers
      - Automated security scanners testing for CORS vulnerabilities
      - Grep/ripgrep patterns: origins.*\\*, headers.*:any, methods.*:any
      - Manual testing with different Origin headers using curl or browser
      - Penetration testing with CORS-specific attack tools
      - Web application security scanners checking CORS policies
      - Runtime monitoring of CORS-related HTTP headers
      - Security-focused linters and IDE plugins for CORS validation
      """,
      
      safe_alternatives: """
      # 1. Production-Ready CORS Configuration
      # config/initializers/cors.rb
      Rails.application.config.middleware.insert_before 0, Rack::Cors do
        allow do
          origins 'https://yourdomain.com', 'https://app.yourdomain.com'
          credentials true
          headers %w[Content-Type Authorization X-Requested-With]
          methods %w[GET POST PUT DELETE OPTIONS]
          expose %w[X-Total-Count X-Pagination-Total]
        end
      end
      
      # 2. Environment-Aware Configuration
      class CorsConfiguration
        def self.configure
          Rails.application.config.middleware.insert_before 0, Rack::Cors do
            allow do
              origins(*allowed_origins)
              credentials true
              headers allowed_headers
              methods allowed_methods
            end
          end
        
        private
        
        def self.allowed_origins
          case Rails.env
          when 'development'
            ['http://localhost:3000', 'http://127.0.0.1:3000']
          when 'staging'
            ['https://staging.yourdomain.com']
          when 'production'
            ['https://yourdomain.com', 'https://app.yourdomain.com']
          else
            []
          end
        end
        
        def self.allowed_headers
          %w[Content-Type Authorization X-Requested-With Accept]
        end
        
        def self.allowed_methods
          %w[GET POST PUT PATCH DELETE OPTIONS]
        end
      
      # In config/initializers/cors.rb
      CorsConfiguration.configure
      
      # 3. Secure Dynamic Origin Validation
      class SecureCorsOriginValidator
        ALLOWED_DOMAINS = %w[
          yourdomain.com
          app.yourdomain.com
          api.yourdomain.com
        ].freeze
        
        def self.call(source, env)
          return false unless source
          
          uri = URI.parse(source) rescue nil
          return false unless uri
          
          # Only allow HTTPS in production
          return false if Rails.env.production? && uri.scheme != 'https'
          
          # Check against explicit domain allowlist
          ALLOWED_DOMAINS.include?(uri.host)
        end
      end
      
      Rails.application.config.middleware.insert_before 0, Rack::Cors do
        allow do
          origins SecureCorsOriginValidator
          credentials true
          headers %w[Content-Type Authorization]
          methods %w[GET POST PUT DELETE]
        end
      
      # 4. API-Specific CORS Configuration
      Rails.application.config.middleware.insert_before 0, Rack::Cors do
        # Public API - no credentials
        allow do
          origins 'https://docs.yourdomain.com'
          resource '/api/v1/public/*',
            headers: %w[Content-Type],
            methods: %w[GET OPTIONS]
        end
        
        # Authenticated API - with credentials
        allow do
          origins 'https://app.yourdomain.com'
          resource '/api/v1/private/*',
            headers: %w[Content-Type Authorization],
            methods: %w[GET POST PUT DELETE OPTIONS],
            credentials: true
        end
        
        # Admin API - highly restricted
        allow do
          origins 'https://admin.yourdomain.com'
          resource '/api/v1/admin/*',
            headers: %w[Content-Type Authorization X-Admin-Token],
            methods: %w[GET POST PUT DELETE],
            credentials: true
        end
      end
      
      # 5. CORS Security Validator
      class CorsSecurityValidator
        def self.validate_configuration!
          # Ensure no wildcard origins with credentials
          if Rails.application.config.middleware.any? { |m| 
            m.klass == Rack::Cors && has_wildcard_with_credentials?(m)
          }
            raise "SECURITY ERROR: Wildcard origins with credentials detected!"
          end
        
        private
        
        def self.has_wildcard_with_credentials?(middleware)
          # Implementation would check middleware configuration
          # This is a simplified example
          false
        end
      end
      
      # In config/environments/production.rb
      config.after_initialize do
        CorsSecurityValidator.validate_configuration!
      end
      """
    }
  end
  
  def ast_enhancement do
    %{
      min_confidence: 0.7,
      
      context_rules: %{
        # CORS configuration methods
        cors_methods: [
          "origins", "headers", "methods", "credentials", "resource", 
          "allow", "expose"
        ],
        
        # Dangerous origin values
        dangerous_origins: [
          "*", ":any", "/.*/", "/.*\\./", "/https?:\\/\\/.*/",
          "true", "lambda", "proc", "->"
        ],
        
        # Dangerous header/method values
        dangerous_values: [":any", "*", "/.*/", "true"],
        
        # CORS middleware classes
        cors_middleware: [
          "Rack::Cors", "ActionDispatch::Cors", "Cors"
        ],
        
        # Safe patterns to reduce false positives
        safe_patterns: [
          ~r/origins\s+["']https:\/\/[^*"']+["']/,    # HTTPS specific origins
          ~r/origins\s+\[.*?["']https:\/\/.*?["'].*?\]/,  # Array of HTTPS origins
          ~r/headers\s+\[.*?["'][^*:]+["'].*?\]/,     # Array of specific headers
          ~r/methods\s+\[.*?["'][^*:]+["'].*?\]/,     # Array of specific methods
          ~r/#.*origins\s+["']?\*["']?/,              # Commented out wildcards
          ~r/origins.*Rails\.env\.development\?/      # Environment-specific
        ]
      },
      
      confidence_rules: %{
        adjustments: %{
          # High confidence for dangerous combinations
          wildcard_origin: +0.4,
          wildcard_with_credentials: +0.6,
          wildcard_headers_methods: +0.3,
          overly_permissive_regex: +0.4,
          dynamic_always_true: +0.5,
          
          # Medium confidence for potentially dangerous patterns
          direct_header_manipulation: +0.3,
          rack_cors_wildcard: +0.2,
          any_keyword_usage: +0.2,
          
          # Lower confidence for safer patterns
          https_specific_origins: -0.4,
          explicit_origin_arrays: -0.5,
          environment_conditional: -0.3,
          commented_configuration: -0.8,
          
          # Context-based adjustments
          in_development_env: -0.4,
          in_test_file: -0.9,
          in_cors_initializer: +0.1,
          has_origin_validation: -0.4,
          
          # File location adjustments
          in_controller: +0.1,
          in_initializer: +0.2
        }
      },
      
      ast_rules: %{
        # CORS analysis
        cors_analysis: %{
          check_cors_middleware: true,
          detect_wildcard_origins: true,
          validate_credentials_usage: true,
          check_header_method_permissions: true
        },
        
        # Origin validation
        origin_validation: %{
          check_origin_patterns: true,
          detect_regex_vulnerabilities: true,
          validate_dynamic_origins: true,
          check_https_enforcement: true
        },
        
        # Configuration analysis
        config_analysis: %{
          check_environment_specific: true,
          detect_credential_combinations: true,
          validate_resource_restrictions: true
        },
        
        # Security validation
        security_validation: %{
          dangerous_combinations: %{
            "wildcard_credentials" => ["origins.*\\*", "credentials.*true"],
            "wildcard_any" => ["origins.*\\*", "headers.*:any"],
            "regex_permissive" => ["origins.*/.*", "credentials.*true"]
          }
        }
      }
    }
  end
end

