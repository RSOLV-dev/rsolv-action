defmodule RsolvApi.Security.Patterns.Rails.Cve202222577 do
  @moduledoc """
  CVE-2022-22577 - XSS Vulnerability in Rails Action Pack.
  
  This vulnerability affects Rails Action Pack versions >= 5.2.0 where Content-Security-Policy 
  (CSP) headers were only sent along with responses that Rails considered as "HTML" responses. 
  This left API requests without CSP headers, and when user input is used to construct CSP headers,
  it could allow attackers to bypass CSP protections and inject malicious directives.
  
  ## Vulnerability Details
  
  CVE-2022-22577 is a cross-site scripting (XSS) vulnerability that occurs when:
  1. Rails applications dynamically construct CSP headers using user input
  2. API endpoints lack proper CSP header protection
  3. User-controlled data is injected into CSP directive values
  4. Nonce values are constructed from user input
  
  ### Attack Example
  ```ruby
  # Vulnerable: User input directly in CSP header
  def api_endpoint
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src \#{params[:allowed_scripts]}"
    render json: { data: data }
  end
  ```
  
  ### Safe Example
  ```ruby  
  # Safe: Static CSP with allowlist validation
  def api_endpoint
    allowed_scripts = ['https://trusted-cdn.com', 'https://api.example.com']
    script_src = params[:script_source] if allowed_scripts.include?(params[:script_source])
    script_src ||= "'self'"
    
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src \#{script_src}"
    render json: { data: data }
  end
  ```
  """
  
  use RsolvApi.Security.Patterns.PatternBase
  
  def pattern do
    %RsolvApi.Security.Pattern{
      id: "rails-cve-2022-22577",
      name: "CVE-2022-22577 - XSS in Action Pack",
      description: "XSS vulnerability in CSP headers allowing script injection through user input",
      type: :xss,
      severity: :medium,
      languages: ["ruby"],
      frameworks: ["rails"],
      regex: [
        # Direct CSP header injection via params or user input (exclude commented lines)
        # Handle both real interpolation #{} and escaped \#{} in test strings
        ~r/^(?!.*[^\\]#[^{]).*response\.headers\[['"]Content-Security-Policy['"]]\s*=.*?\\*#\{params\[/,
        ~r/^(?!.*[^\\]#[^{]).*response\.headers\[['"]CSP['"]]\s*=.*?\\*#\{params\[/,
        ~r/^(?!.*[^\\]#[^{]).*response\.headers\[['"]Content-Security-Policy['"]]\s*=.*?\\*#\{request\./,
        ~r/^(?!.*[^\\]#[^{]).*response\.headers\[['"]Content-Security-Policy['"]]\s*=\s*params\[/,
        
        # CSP policy builder with user input (handle multiline with \\n)
        ~r/content_security_policy[\s\S\\]*?policy\.[\w_]+\s+params\[/,
        ~r/content_security_policy[\s\S\\]*?policy\.[\w_]+.*?\\*#\{params\[/,
        ~r/content_security_policy[\s\S\\]*?policy\.[\w_]+.*?\\*#\{request\./,
        ~r/content_security_policy.*?\\n.*?params\[/,
        
        # Dynamic CSP directive construction
        ~r/policy\.(script_src|style_src|default_src|connect_src|img_src|font_src).*?\\*#\{params\[/,
        ~r/policy\.(script_src|style_src|default_src|connect_src|img_src|font_src).*?\\*#\{request\./,
        ~r/policy\.(script_src|style_src|default_src|connect_src|img_src|font_src).*?\\*#\{user_/,
        ~r/policy\.(script_src|style_src|default_src|connect_src|img_src|font_src)\s+params\[/,
        
        # Nonce injection vulnerabilities (handle multiline)
        ~r/['"]nonce-\\*#\{params\[/,
        ~r/['"]nonce-\\*#\{user_/,
        ~r/['"]nonce-\\*#\{[^}]*params/,
        ~r/params\[:nonce\].*?\\n.*?nonce-\\*#\{/,
        ~r/= params\[:nonce\].*?\\n.*?['"]nonce-\\*#\{/,
        
        # CSP function calls with user input
        ~r/build_csp\(params\[/,
        ~r/set_csp.*?params\[/,
        ~r/csp_policy.*?\\*#\{params\[/,
        ~r/csp_policy.*?\\*#\{request\./
      ],
      cwe_id: "CWE-79",
      owasp_category: "A03:2021",
      recommendation: "Validate and sanitize any user input used in Content-Security-Policy headers. Use allowlists for CSP directive values instead of direct user input.",
      test_cases: %{
        vulnerable: [
          "response.headers[\"Content-Security-Policy\"] = \"default-src \#{params[:csp]}\"",
          "policy.script_src \"'self' \#{params[:external_scripts]}\"",
          "policy.script_src \"'self' 'nonce-\#{params[:nonce]}'\"",
          "response.headers['Content-Security-Policy'] = build_csp(params[:csp_config])"
        ],
        safe: [
          "response.headers[\"Content-Security-Policy\"] = \"default-src 'self'\"",
          "policy.script_src 'self', 'unsafe-inline'",
          "ALLOWED_SOURCES = ['self']; policy.script_src(*ALLOWED_SOURCES)",
          "# response.headers[\"Content-Security-Policy\"] = params[:policy]  # commented out"
        ]
      }
    }
  end
  
  def vulnerability_metadata do
    %{
      description: """
      CVE-2022-22577 is a cross-site scripting (XSS) vulnerability in Rails Action Pack 
      that occurs when Content-Security-Policy (CSP) headers are dynamically constructed 
      using untrusted user input. This vulnerability affects Rails versions >= 5.2.0 
      where CSP headers were only sent with HTML responses, leaving API responses vulnerable. 
      When applications use user-controlled data to build CSP headers, attackers can inject 
      malicious directives to bypass CSP protections and execute arbitrary scripts.
      """,
      attack_vectors: """
      1. CSP Header Injection: Direct injection of malicious directives via params
      2. Policy Builder Exploitation: Manipulating content_security_policy block parameters
      3. Nonce Manipulation: Controlling nonce values through user input parameters
      4. API Response Exploitation: Targeting API endpoints without proper CSP validation
      5. Dynamic Source Injection: Injecting malicious script/style sources via user input
      6. Header Bypass: Exploiting missing CSP headers on non-HTML responses
      """,
      business_impact: """
      - Cross-site scripting attacks leading to session hijacking and data theft
      - Bypass of Content Security Policy protections designed to prevent XSS
      - Injection of malicious scripts to steal sensitive user information
      - Compromise of API endpoints and data exposure through XSS
      - Brand reputation damage from successful XSS attacks
      - Regulatory compliance violations for data protection requirements
      - Legal liability for customer data breaches via XSS exploitation
      """,
      technical_impact: """
      - Complete bypass of Content-Security-Policy protection mechanisms
      - Execution of arbitrary JavaScript code in user browsers
      - Access to sensitive data through DOM manipulation and AJAX requests
      - Session token theft and account takeover capabilities
      - Injection of malicious content and phishing attacks
      - Cross-origin data exfiltration through crafted CSP directives
      - Persistent XSS through stored malicious CSP configurations
      """,
      likelihood: "Medium - Common in Rails applications that dynamically construct CSP headers, especially API endpoints accepting user input for security configurations",
      cve_examples: """
      CVE-2022-22577 - Rails Action Pack XSS vulnerability (CVSS 6.1 Medium)
      Affects: Rails >= 5.2.0, < 5.2.0 (typo in original, should be < 7.0.2.4)
      Fixed in: Rails 7.0.2.4, 6.1.5.1, 6.0.4.8, 5.2.7.1
      
      Related vulnerabilities:
      CVE-2024-54133 - Content Security Policy bypass in Action Dispatch
      GHSA-mm33-5vfq-3mm3 - Cross-site Scripting Vulnerability in Action Pack
      GHSA-vfm5-rmrh-j26v - Possible Content Security Policy bypass in Action Dispatch
      """,
      compliance_standards: [
        "OWASP Top 10 2021 - A03: Injection",
        "CWE-79: Cross-site Scripting (XSS)",
        "CWE-116: Improper Encoding or Escaping of Output",
        "NIST SP 800-53 SI-10 - Information Input Validation",
        "ISO 27001 A.14.2.1 - Secure development policy",
        "PCI DSS 6.5.7 - Cross-site scripting prevention"
      ],
      remediation_steps: """
      1. Validate all user input against strict allowlists before using in CSP headers
      2. Use static CSP configurations with predefined safe directive values
      3. Implement proper input sanitization for any dynamic CSP construction
      4. Apply CSP headers consistently to all response types, not just HTML
      5. Use secure CSP directive values like 'self', 'none', or specific trusted domains
      6. Implement Content Security Policy report-only mode for testing
      7. Regular security testing of CSP configurations and user input validation
      """,
      prevention_tips: """
      - Never use raw user input directly in CSP headers or directive values
      - Implement allowlist-based validation for any dynamic CSP construction
      - Use Rails secure_headers gem for standardized CSP management
      - Apply CSP headers to all response types, including API endpoints
      - Use nonce-based CSP with server-generated cryptographically secure nonces
      - Implement proper escaping and encoding for any user data in headers
      - Regular security audits of CSP configurations and dynamic header construction
      - Always validate user input against strict allowlists before CSP usage
      """,
      detection_methods: """
      - Static analysis tools like Brakeman for Rails CSP usage patterns
      - Code review focusing on response.headers assignments and CSP construction
      - Dynamic testing with CSP injection payloads and malformed directives
      - Security scanning for user input in HTTP header construction
      - CSP violation reporting to monitor bypass attempts
      - Runtime monitoring of CSP header construction patterns
      """,
      safe_alternatives: """
      # Safe CSP configuration with allowlist validation
      class ApiController < ApplicationController
        ALLOWED_SCRIPT_SOURCES = [
          "'self'",
          "https://trusted-cdn.example.com",
          "https://api.googleapis.com"
        ].freeze
        
        def api_endpoint
          # Validate against allowlist
          script_source = params[:script_source]
          validated_source = ALLOWED_SCRIPT_SOURCES.include?(script_source) ? script_source : "'self'"
          
          # Use validated input in CSP
          csp = "default-src 'self'; script-src \#{validated_source}"
          response.headers['Content-Security-Policy'] = csp
          
          render json: { data: data }
        end
      
      # Safe static CSP configuration
      Rails.application.config.content_security_policy do |policy|
        policy.default_src :self
        policy.script_src  :self, 'https://trusted-cdn.example.com'
        policy.style_src   :self, 'https://fonts.googleapis.com'
        policy.connect_src :self, 'https://api.example.com'
      end
      
      # Safe nonce-based CSP
      def secure_endpoint
        nonce = SecureRandom.base64(32)  # Server-generated nonce
        response.headers['Content-Security-Policy'] = "script-src 'nonce-\#{nonce}'"
        render json: { nonce: nonce, data: data }
      end
      """
    }
  end
  
  def ast_enhancement do
    %{
      min_confidence: 0.8,
      
      context_rules: %{
        # CSP-related headers and directives
        csp_headers: [
          "Content-Security-Policy", "CSP", "Content-Security-Policy-Report-Only"
        ],
        
        # CSP directive names
        csp_directives: [
          "default_src", "script_src", "style_src", "img_src", "connect_src",
          "font_src", "object_src", "media_src", "frame_src", "child_src",
          "frame_ancestors", "form_action", "upgrade_insecure_requests"
        ],
        
        # Dangerous input sources
        dangerous_sources: [
          "params", "request.headers", "request.params", "user_input", 
          "session", "cookies", "request.query_parameters"
        ],
        
        # Safe CSP patterns that should reduce confidence
        safe_patterns: [
          ~r/'self'/,                                    # Self reference
          ~r/'none'/,                                    # None directive
          ~r/'unsafe-inline'/,                           # Explicit unsafe inline
          ~r/'unsafe-eval'/,                             # Explicit unsafe eval
          ~r/https:\/\/[\w\-\.]+/,                       # HTTPS URLs
          ~r/ALLOWED_\w+/,                               # Allowlist constants
          ~r/#.*response\.headers.*CSP/,                 # Commented CSP code
          ~r/SecureRandom\./,                            # Secure random nonce
          ~r/Rails\.application\.config\.content_security_policy/ # Static config
        ]
      },
      
      confidence_rules: %{
        adjustments: %{
          # High confidence indicators
          direct_params_usage: +0.4,
          header_injection_pattern: +0.5,
          nonce_manipulation: +0.5,
          multiple_directive_injection: +0.3,
          api_endpoint_context: +0.3,
          
          # Lower confidence adjustments
          static_csp_value: -0.6,
          allowlist_validation: -0.7,
          commented_code: -1.0,
          test_file_context: -0.8,
          secure_random_nonce: -0.5,
          
          # Context-based adjustments
          in_controller_action: +0.2,
          in_api_controller: +0.3,
          in_security_config: -0.4
        }
      },
      
      ast_rules: %{
        # HTTP header analysis
        header_analysis: %{
          check_response_headers: true,
          detect_csp_construction: true,
          validate_header_values: true,
          check_dynamic_headers: true
        },
        
        # CSP specific analysis
        csp_analysis: %{
          check_directive_injection: true,
          detect_nonce_manipulation: true,
          validate_source_lists: true,
          check_policy_builder_usage: true
        },
        
        # Input validation analysis
        input_validation: %{
          check_params_usage: true,
          detect_request_data: true,
          validate_user_input: true,
          check_allowlist_validation: true
        }
      }
    }
  end
  
end

