defmodule RsolvApi.Security.Patterns.Rails.UnsafeRouteConstraints do
  @moduledoc """
  Rails Unsafe Route Constraints pattern for Rails applications.
  
  This pattern detects broken access control vulnerabilities in Rails route 
  constraints that can be bypassed or allow code execution. Route constraints 
  are intended to restrict access to routes based on request properties, but 
  unsafe implementations can lead to security bypasses or even remote code execution.
  
  ## Background
  
  Rails route constraints allow developers to control which requests can access
  specific routes. However, several dangerous patterns can emerge:
  1. Overly permissive regex constraints (/./) that match everything
  2. Dynamic constraints that interpolate user input into regex patterns
  3. Lambda constraints that use eval() or other dangerous methods
  4. Constraints that always return true, bypassing all security
  5. Subdomain constraints that can be manipulated by attackers
  
  ## Vulnerability Details
  
  The vulnerability occurs when:
  1. Route constraints use overly permissive regex patterns like /.*/
  2. User input is interpolated into constraint regex patterns
  3. Lambda constraints call eval() on user-controlled data
  4. Lambda constraints unconditionally return true
  5. send() or method_missing() are used in constraint logic
  6. System commands are executed within constraint checks
  7. Format or host constraints are overly permissive
  
  ## Known CVEs
  
  - CVE-2020-8264: Rails security constraint bypass through skip callbacks
  - CVE-2016-6316: Possible XSS via User-Friendly URLs in Action View
  - Multiple route constraint bypass vulnerabilities in Rails applications
  - ReDoS attacks via poorly crafted route constraint regex patterns
  
  ## Examples
  
      # Critical - Overly permissive regex
      constraints: { id: /.*/ }
      
      # Critical - User input in constraint regex
      constraints: { slug: /\#{params[:pattern]}/ }
      
      # Critical - Lambda with eval
      constraints: lambda { |req| eval(req.params[:code]) }
      
      # Critical - Always returns true
      constraints: lambda { |req| true }
      
      # Safe - Specific pattern
      constraints: { id: /\\d+/ }
      
      # Safe - Proper validation
      constraints: lambda { |req| ALLOWED_IDS.include?(req.params[:id]) }
  """
  
  use RsolvApi.Security.Patterns.PatternBase
  
  @impl true
  def pattern do
    %RsolvApi.Security.Pattern{
      id: "rails-unsafe-route-constraints",
      name: "Unsafe Route Constraints",
      description: "Route constraints that can be bypassed or allow code execution",
      type: :broken_access_control,
      severity: :high,
      languages: ["ruby"],
      frameworks: ["rails"],
      regex: [
        # Overly permissive regex constraints (/./) - exclude comments
        ~r/^(?!.*#.*constraints).*constraints:\s*\{\s*\w+:\s*\/\.\*\//,
        ~r/^(?!.*#.*constraints).*constraints\s+\w+:\s*\/\.\*\//,
        ~r/^(?!.*#.*constraints).*constraints\(\s*\{\s*\w+:\s*\/\.\*\/\s*\}/,
        ~r/^(?!.*#.*constraints).*constraints\s*\{\s*\w+:\s*\/\.\*\/\s*\}/,
        
        # Parameter interpolation in constraints (dangerous)
        ~r/constraints:\s*\{\s*\w+:\s*\/.*?#\{.*?params/,
        ~r/constraints\s+\w+:\s*\/.*?#\{.*?params/,
        ~r/constraints:\s*\{\s*\w+:\s*\/.*?#\{.*?user_input/,
        ~r/constraints:\s*\{\s*\w+:\s*\/.*?#\{.*?request\.params/,
        ~r/constraints\(\s*\{\s*\w+:\s*\/.*?#\{.*?params/,
        
        # Lambda constraints with eval (critical)
        ~r/constraints:\s*lambda.*?eval\s*\(/,
        ~r/constraints\s+lambda.*?eval\s*\(/,
        ~r/constraints:\s*->\s*\{.*?eval\s*\(/,
        ~r/constraints:\s*proc.*?eval\s*\(/,
        ~r/constraints\s+lambda.*?instance_eval\s*\(/,
        
        # Lambda constraints that always return true (bypass)
        ~r/constraints\s+lambda\s*\{\s*\|[^}]*\|\s*true\s*\}/,
        ~r/constraints:\s*lambda\s*\{\s*\|[^}]*\|\s*true\s*\}/,
        ~r/constraints:\s*->\s*\{\s*true\s*\}/,
        ~r/constraints\s+lambda\s*\{\s*true\s*\}/,
        ~r/constraints:\s*proc\s*\{\s*\|[^}]*\|\s*true\s*\}/,
        ~r/constraints\s+proc\s*\{\s*\|[^}]*\|\s*true\s*\}/,
        
        # Unsafe subdomain constraints
        ~r/constraints\s+subdomain:\s*\/\.\*\//,
        ~r/constraints:\s*\{\s*subdomain:\s*\/\.\*\/\s*\}/,
        ~r/constraints\s+subdomain:\s*\/.*?#\{.*?params/,
        ~r/constraints:\s*\{\s*subdomain:\s*\/.*?#\{.*?user_input/,
        
        # send method calls in constraints (dangerous metaprogramming)
        ~r/constraints:\s*lambda.*?\.send\s*\(/,
        ~r/constraints\s+lambda.*?\.send\s*\(/,
        ~r/constraints:\s*->\s*\{.*?\.send\s*\(/,
        ~r/constraints:\s*proc.*?\.send\s*\(/,
        ~r/constraints\s+proc.*?\.send\s*\(/,
        
        # method_missing calls in constraints
        ~r/constraints:\s*lambda.*?method_missing\s*\(/,
        ~r/constraints\s+lambda.*?method_missing\s*\(/,
        ~r/constraints:\s*->\s*\{.*?method_missing\s*\(/,
        
        # System calls in constraints (command injection)
        ~r/constraints:\s*lambda.*?system\s*\(/,
        ~r/constraints\s+lambda.*?system\s*\(/,
        ~r/constraints:\s*lambda.*?`[^`]*#\{.*?params/,
        ~r/constraints:\s*->\s*\{.*?`[^`]*#\{.*?params/,
        ~r/constraints:\s*proc.*?exec\s*\(/,
        ~r/constraints\s+proc.*?exec\s*\(/,
        
        # Unsafe format constraints
        ~r/constraints:\s*\{\s*format:\s*\/\.\*\/\s*\}/,
        ~r/constraints\s+format:\s*\/\.\*\//,
        ~r/constraints:\s*\{\s*format:\s*\/.*?#\{.*?params/,
        
        # Unsafe host constraints
        ~r/constraints:\s*\{\s*host:\s*\/\.\*\/\s*\}/,
        ~r/constraints\s+host:\s*\/\.\*\//,
        ~r/constraints:\s*\{\s*host:\s*\/.*?#\{.*?params/,
        ~r/constraints\(\s*\{\s*host:\s*\/\.\*.*?\}.*?\)/
      ],
      default_tier: :protected,
      cwe_id: "CWE-285",
      owasp_category: "A01:2021",
      recommendation: "Use specific, restrictive regex patterns for Rails route constraints. Avoid dynamic constraints with user input in Rails routes.",
      test_cases: %{
        vulnerable: [
          "constraints: { id: /.*/ }",
          "constraints: { slug: /\#{params[:pattern]}/ }",
          "constraints: lambda { |req| eval(req.params[:code]) }",
          "constraints lambda { |req| true }"
        ],
        safe: [
          "constraints: { id: /\\d+/ }",
          "constraints: { slug: /[a-z0-9-]+/ }",
          "constraints: lambda { |req| req.subdomain == 'api' }",
          "constraints: { format: /json|xml/ }"
        ]
      }
    }
  end
  
  @impl true
  def vulnerability_metadata do
    %{
      description: """
      Unsafe Route Constraints in Rails applications represent a critical broken access control vulnerability where route constraints intended to restrict 
      access can be bypassed or exploited for code execution. Route constraints 
      are Rails' mechanism for controlling which requests can access specific routes 
      based on request properties like parameters, subdomains, or headers.
      
      The vulnerability manifests in several dangerous patterns:
      1. Overly permissive regex patterns (/./) that match everything, effectively disabling security
      2. Dynamic constraint generation using user input in regex patterns, leading to ReDoS or bypasses
      3. Lambda constraints that execute arbitrary code via eval() on user-controlled data
      4. Unconditional constraint bypasses that always return true
      5. Dangerous metaprogramming patterns using send() or method_missing()
      6. System command execution within constraint evaluation
      7. Subdomain, format, or host constraints that can be manipulated by attackers
      """,
      
      attack_vectors: ~S"""
      1. **Constraint Bypass via Overly Permissive Regex**: constraints: { id: /.*/ } matches any input, bypassing intended restrictions
      2. **ReDoS via Dynamic Regex**: constraints: { param: /#{params[:pattern]}/ } allows catastrophic backtracking patterns
      3. **Remote Code Execution via eval()**: constraints: lambda { |req| eval(req.params[:code]) } executes arbitrary Ruby code
      4. **Authentication Bypass**: constraints lambda { |req| true } always grants access regardless of conditions
      5. **Metaprogramming Exploitation**: constraints: lambda { |req| req.send(params[:method]) } calls arbitrary methods
      6. **Command Injection**: constraints: lambda { |req| system(params[:cmd]) } executes system commands
      7. **Header Injection**: constraints: { host: /#{params[:hostname]}/ } allows host header manipulation
      8. **Subdomain Takeover**: constraints subdomain: /.*/ allows any subdomain to access restricted routes
      9. **Format Bypass**: constraints: { format: /.*/ } bypasses format-based access controls
      10. **Parameter Pollution**: Multiple parameters with same name can bypass constraint logic
      """,
      
      business_impact: """
      - Complete access control bypass allowing unauthorized access to protected resources
      - Administrative panel access by non-admin users leading to data breaches
      - Financial fraud through access to payment and billing systems
      - Customer data exposure via unrestricted access to user records
      - Regulatory compliance violations (GDPR, HIPAA, PCI DSS, SOX)
      - Legal liability from unauthorized access and data breaches
      - Reputation damage from security incidents and data leaks
      - Business disruption from system compromise and downtime
      - Loss of customer trust and potential customer churn
      - Competitive intelligence theft through unauthorized access
      """,
      
      technical_impact: """
      - Elevation of privilege allowing low-privileged users to access admin functions
      - Complete authentication and authorization bypass
      - Remote code execution through eval() in constraint logic
      - System command execution via lambda constraints
      - Data exfiltration through unrestricted database access
      - Application logic manipulation via constraint bypass
      - Session hijacking and account takeover capabilities
      - Cross-tenant data access in multi-tenant applications
      - API endpoint access without proper authentication
      - Administrative interface exposure to public users
      """,
      
      likelihood: "High - Route constraints are commonly misconfigured and developers often use overly permissive patterns for convenience",
      
      cve_examples: [
        "CVE-2020-8264 - Rails security constraint bypass through skip callbacks (CVSS 7.5)",
        "CVE-2016-6316 - Possible XSS via User-Friendly URLs in Action View",
        "CVE-2013-0333 - JSON unsafe object creation vulnerability in JSON backend",
        "CVE-2018-3760 - Path traversal vulnerability in Sprockets via path normalization bypass",
        "CVE-2019-5418 - File Content Disclosure in Action View (related to route handling)",
        "CVE-2019-5419 - Denial of Service in Action View (related to route constraints)",
        "Multiple ReDoS vulnerabilities in Rails route constraint patterns"
      ],
      
      compliance_standards: [
        "OWASP Top 10 2021 - A01: Broken Access Control",
        "CWE-285: Improper Authorization",
        "CWE-22: Path Traversal (for globbing constraints)",
        "CWE-94: Code Injection (for eval in constraints)",
        "PCI DSS 6.5.8 - Improper access control",
        "NIST SP 800-53 - AC-3 Access Enforcement",
        "ISO 27001 - A.9.4.1 Information access restriction",
        "ASVS 4.0 - V4.1 General Access Control Design",
        "SANS Top 25 - CWE-285 Improper Authorization"
      ],
      
      remediation_steps: """
      1. **Use Specific Regex Patterns (Critical)**:
         ```ruby
         # NEVER do this - matches everything
         constraints: { id: /.*/ }                    # DANGEROUS
         
         # Always use specific patterns
         constraints: { id: /\\d+/ }                   # SAFE - Only digits
         constraints: { slug: /[a-z0-9-]+/ }          # SAFE - Alphanumeric with dashes
         constraints: { format: /json|xml|html/ }     # SAFE - Specific formats
         ```
      
      2. **Avoid User Input in Constraints**:
         ```ruby
         # NEVER interpolate user input into constraints
         constraints: { param: /\#{params[:pattern]}/ } # DANGEROUS
         
         # Use predefined whitelists instead
         ALLOWED_PATTERNS = {
           'strict' => /\\A[a-z]+\\z/,
           'numeric' => /\\A\\d+\\z/,
           'mixed' => /\\A[a-z0-9_-]+\\z/
         }.freeze
         
         pattern_key = params[:pattern_type]
         if ALLOWED_PATTERNS.key?(pattern_key)
           constraints: { param: ALLOWED_PATTERNS[pattern_key] }
         end
         ```
      
      3. **Secure Lambda Constraints**:
         ```ruby
         # NEVER use eval or dangerous methods
         constraints: lambda { |req| eval(req.params[:code]) }    # DANGEROUS
         constraints: lambda { |req| req.send(params[:method]) }  # DANGEROUS
         constraints: lambda { |req| true }                       # DANGEROUS
         
         # Use safe, specific validation
         constraints: lambda { |req| 
           req.subdomain == 'api' && req.format.symbol == :json
         }
         
         # Use whitelisting for dynamic behavior
         ADMIN_SUBDOMAINS = %w[admin dashboard management].freeze
         constraints: lambda { |req| 
           ADMIN_SUBDOMAINS.include?(req.subdomain) && 
           req.headers['Authorization'].present?
         }
         ```
      
      4. **Validate Subdomain/Host Constraints**:
         ```ruby
         # Bad - Overly permissive
         constraints subdomain: /.*/                   # DANGEROUS
         constraints: { host: /.*/ }                   # DANGEROUS
         
         # Good - Specific validation
         constraints subdomain: 'api'                  # SAFE - Static string
         constraints: { subdomain: /\\A(api|admin)\\z/ } # SAFE - Specific options
         
         # For dynamic subdomains, use validation
         ALLOWED_SUBDOMAINS = %w[api admin dashboard].freeze
         constraints: lambda { |req| 
           ALLOWED_SUBDOMAINS.include?(req.subdomain)
         }
         ```
      
      5. **Input Validation and Sanitization**:
         ```ruby
         # Add validation at model/controller level
         class User < ApplicationRecord
           validates :slug, format: { 
             with: /\\A[a-z0-9-]+\\z/, 
             message: "only allows lowercase letters, numbers, and dashes" 
           }
         end
         
         # Use strong parameters
         def user_params
           params.require(:user).permit(:name, :email).tap do |p|
             p[:slug] = p[:slug]&.downcase&.gsub(/[^a-z0-9-]/, '')
           end
         end
         ```
      """,
      
      prevention_tips: """
      - Always use specific, restrictive regex patterns in route constraints
      - Never interpolate user input directly into constraint regex patterns
      - Avoid lambda constraints that unconditionally return true
      - Never use eval(), send(), or method_missing() in constraint logic
      - Use predefined whitelists instead of dynamic constraint generation
      - Validate and sanitize all user input before use in routing logic
      - Implement comprehensive logging for constraint evaluation
      - Use static strings instead of regex where possible
      - Apply principle of least privilege - constraints should be as restrictive as possible
      - Regularly audit route definitions for constraint security
      - Use security linters like Brakeman to detect unsafe constraint patterns
      - Implement unit tests specifically for constraint bypass attempts
      """,
      
      detection_methods: """
      - Static analysis with Brakeman scanner (detects most unsafe constraint patterns)
      - Manual code review focusing on route.rb files and constraint definitions
      - Grep/ripgrep patterns: constraints.*\\\\\\*, lambda.*eval, constraints.*true
      - Dynamic testing with bypass payloads: /.*/, \#{system('id')}, always-true conditions  
      - Penetration testing targeting route constraint bypass
      - Automated security scanning with custom rules for Rails constraints
      - Route enumeration and constraint testing tools
      - Code complexity analysis to identify overly complex constraint logic
      - Regular expression analysis for ReDoS vulnerability patterns
      - Integration testing with invalid/malicious constraint inputs
      """,
      
      safe_alternatives: """
      # 1. Use specific regex patterns instead of catch-all
      # Bad
      constraints: { id: /.*/ }
      
      # Good
      constraints: { id: /\\d+/ }                    # Only numeric IDs
      constraints: { slug: /[a-z0-9-]{1,50}/ }       # Alphanumeric slugs
      constraints: { format: /json|xml|html/ }       # Specific formats
      
      # 2. Use whitelist-based validation for dynamic constraints
      class RouteConstraints
        ALLOWED_FORMATS = %w[json xml html csv].freeze
        ALLOWED_SUBDOMAINS = %w[api admin dashboard].freeze
        
        def self.valid_format?(format)
          ALLOWED_FORMATS.include?(format.to_s)
        end
        
        def self.valid_subdomain?(subdomain)
          ALLOWED_SUBDOMAINS.include?(subdomain.to_s)
        end
      end
      
      # Usage
      constraints: lambda { |req| 
        RouteConstraints.valid_format?(req.format.symbol)
      }
      
      # 3. Use object-based constraint classes
      class AdminConstraint
        def matches?(request)
          return false unless request.subdomain == 'admin'
          return false unless request.headers['Authorization'].present?
          
          # Add additional validation logic
          user = authenticate_from_token(request.headers['Authorization'])
          user&.admin?
        end
        
        private
        
        def authenticate_from_token(token)
          # Safe token validation logic
        end
      end
      
      # Usage
      constraints AdminConstraint.new do
        # Admin routes here
      end
      
      # 4. Use Rails built-in constraint helpers
      constraints subdomain: 'api' do
        # API routes
      end
      
      constraints format: :json do
        # JSON-only routes  
      end
      
      # 5. Implement custom constraint validation
      class SecureConstraints
        def self.secure_id_constraint
          { id: /\\A\\d{1,10}\\z/ }  # Max 10 digits
        end
        
        def self.secure_slug_constraint  
          { slug: /\\A[a-z0-9][a-z0-9-]{0,48}[a-z0-9]\\z/ }  # 2-50 chars
        end
        
        def self.api_constraint
          lambda { |req|
            req.subdomain == 'api' &&
            req.format.symbol == :json &&
            req.headers['X-API-Key'].present?
          }
        end
      end
      
      # Usage
      constraints SecureConstraints.secure_id_constraint do
        get 'users/:id', to: 'users#show'
      end
      
      constraints SecureConstraints.api_constraint do
        # Secure API routes
      end
      
      # 6. Environment-based constraints
      constraints lambda { |req| Rails.env.development? } do
        # Development-only routes
      end
      
      # 7. Feature flag constraints
      constraints lambda { |req| FeatureFlag.enabled?(:new_ui) } do
        # Feature-flagged routes
      end
      """
    }
  end
  
  @impl true
  def ast_enhancement do
    %{
      min_confidence: 0.8,
      
      context_rules: %{
        # Patterns that indicate dangerous constraint usage
        dangerous_patterns: [
          "/.*//", "/.*/", "eval(", "system(", "send(", "method_missing(",
          "true }", "params[", "user_input", "request.params"
        ],
        
        # Methods that define constraints
        constraint_methods: [
          "constraints", "lambda", "proc", "->", "match", "get", "post", "put", "delete"
        ],
        
        # Safe constraint patterns to reduce false positives
        safe_patterns: [
          ~r/\\A.*\\z/,                          # Anchored patterns
          ~r/\\d+/,                             # Digit patterns  
          ~r/[a-z0-9-]+/,                       # Alphanumeric patterns
          ~r/json|xml|html/,                    # Specific format lists
          ~r/constraints.*==.*['"].*['"]/,       # String equality checks
          ~r/ALLOWED_|WHITELIST_|VALID_/         # Whitelist constants
        ],
        
        # User input sources in Rails
        user_input_sources: [
          "params", "request.params", "cookies", "session",
          "headers", "query_params", "form_params", "user_input"
        ]
      },
      
      confidence_rules: %{
        adjustments: %{
          # Very high confidence for dangerous patterns
          overly_permissive_regex: +0.5,
          eval_in_constraint: +0.6,
          always_returns_true: +0.4,
          user_input_interpolation: +0.5,
          send_method_usage: +0.4,
          system_command_execution: +0.6,
          
          # Lower confidence for potentially safe patterns
          uses_whitelist_constant: -0.3,
          anchored_regex_pattern: -0.2,
          specific_format_list: -0.2,
          environment_check: -0.4,
          static_string_constraint: -0.5,
          
          # Context-based adjustments
          in_test_file: -0.7,
          in_development_config: -0.3,
          has_additional_validation: -0.2,
          documented_security_review: -0.1
        }
      },
      
      ast_rules: %{
        # Route constraint analysis
        route_analysis: %{
          check_constraint_definitions: true,
          detect_lambda_constraints: true,
          analyze_regex_patterns: true,
          track_user_input_flow: true
        },
        
        # Method call pattern analysis
        method_analysis: %{
          dangerous_methods: ["eval", "send", "method_missing", "system", "exec"],
          constraint_methods: ["constraints", "lambda", "proc"],
          check_method_chaining: true,
          detect_metaprogramming: true
        },
        
        # Regex pattern analysis
        regex_analysis: %{
          detect_overly_permissive: true,
          check_for_redos_patterns: true,
          validate_anchoring: true,
          detect_interpolation: true,
          permissive_patterns: ["/.*//", "/.*/", "/\\w*//", "/\\s*//"]
        },
        
        # Security validation
        security_validation: %{
          check_input_validation: true,
          detect_whitelist_usage: true,
          validate_constraint_logic: true,
          check_authentication_requirements: true
        }
      }
    }
  end
  
  @impl true
  def applies_to_file?(file_path, frameworks \\ nil) do
    # Apply to Ruby files in Rails projects, especially route definitions
    is_ruby_file = String.ends_with?(file_path, ".rb")
    
    # Rails framework check
    frameworks_list = frameworks || []
    is_rails = "rails" in frameworks_list
    
    # Apply to route files and controllers primarily
    # Route constraints are mainly in config/routes.rb but can be in controllers
    _is_rails_file = String.contains?(file_path, "config/routes") ||
                     String.contains?(file_path, "app/controllers/") ||
                     String.contains?(file_path, "config/application") ||
                     String.contains?(file_path, "lib/")
    
    # If no frameworks specified but it looks like Rails, include it
    inferred_rails = frameworks_list == [] && (
      String.contains?(file_path, "config/routes") ||
      String.contains?(file_path, "app/")
    )
    
    is_ruby_file && (is_rails || inferred_rails)
  end
end