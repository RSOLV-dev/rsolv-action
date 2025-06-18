defmodule RsolvApi.Security.Patterns.Rails.InsecureSessionConfig do
  @moduledoc """
  Rails Insecure Session Configuration pattern for Rails applications.
  
  This pattern detects session configuration vulnerabilities in Rails applications
  where session cookies are configured without proper security flags. Insecure
  session configurations can lead to session hijacking, cookie theft, and 
  man-in-the-middle attacks.
  
  ## Background
  
  Rails provides several session stores (CookieStore, ActiveRecordStore, etc.)
  that can be configured with various security options. Without proper security
  flags like `secure`, `httponly`, and `same_site`, session cookies become
  vulnerable to various attacks.
  
  ## Vulnerability Details
  
  The vulnerability occurs when:
  1. Session store is configured without `secure: true` flag
  2. Session store is configured without `httponly: true` flag
  3. Session store uses `same_site: :none` without proper justification
  4. Session store uses weak or hardcoded secrets
  5. Basic session store configuration without any security options
  
  ## Known CVEs
  
  - CVE-2024-26144: Rails Active Storage Sensitive Session Information Leak (CVSS 5.3)
  - CVE-2016-6316: Ruby on Rails Action Record Session Store Replay Vulnerability
  - Multiple session fixation vulnerabilities in Rails applications
  - Session hijacking vulnerabilities due to missing security flags
  
  ## Examples
  
      # Critical - No security flags
      config.session_store :cookie_store, key: '_app_session'
      
      # Critical - Explicit secure: false
      config.session_store :cookie_store, secure: false
      
      # Critical - Explicit httponly: false
      config.session_store :cookie_store, httponly: false
      
      # Critical - same_site: :none (dangerous for CSRF)
      config.session_store :cookie_store, same_site: :none
      
      # Safe - Proper security flags
      config.session_store :cookie_store, key: '_app_session', secure: true, httponly: true, same_site: :strict
  """
  
  use RsolvApi.Security.Patterns.PatternBase
  
  def pattern do
    %RsolvApi.Security.Pattern{
      id: "rails-insecure-session-config",
      name: "Insecure Session Configuration",
      description: "Rails session configuration without proper security flags",
      type: :security_misconfiguration,
      severity: :medium,
      languages: ["ruby"],
      frameworks: ["rails"],
      regex: [
        # Session store configurations with explicit secure: false
        ~r/config\.session_store.*?secure:\s*false/,
        ~r/Rails\.application\.config\.session_store.*?secure:\s*false/,
        
        # Session store configurations with explicit httponly: false
        ~r/config\.session_store.*?httponly:\s*false/,
        ~r/Rails\.application\.config\.session_store.*?httponly:\s*false/,
        
        # Session store configurations with same_site: :none
        ~r/config\.session_store.*?same_site:\s*:none/,
        ~r/Rails\.application\.config\.session_store.*?same_site:\s*:none/,
        
        # Basic session store with key but no security flags (exclude comments)
        ~r/^(?!.*#).*config\.session_store\s*:cookie_store,\s*key:(?!.*secure\s*:\s*true)/,
        ~r/^(?!.*#).*config\.session_store\s*:active_record_store,\s*key:/,
        ~r/^(?!.*#).*config\.session_store\s*:memory_store,\s*key:/,
        ~r/^(?!.*#).*Rails\.application\.config\.session_store\s*:cookie_store(?!.*secure\s*:\s*(true|Rails\.env\.production\?))/,
        
        # Session store with very basic configuration (no options at all, exclude comments)
        ~r/^(?!.*#).*config\.session_store\s*:cookie_store\s*$/,
        ~r/^(?!.*#).*Rails\.application\.config\.session_store\s*:cookie_store\s*$/,
        ~r/^(?!.*#).*config\.session_store\s*:active_record_store\s*$/,
        ~r/^(?!.*#).*config\.session_store\s*:memory_store\s*$/,
        
        # Weak session secrets (short secrets)
        ~r/config\.session_store.*?secret:\s*["'][^"']{1,8}["']/,
        ~r/Rails\.application\.config\.session_store.*?secret:\s*["'][^"']{1,8}["']/,
        
        # Session store with disabled format constraints
        ~r/config\.session_store.*?format:\s*false/,
        ~r/config\.session_store.*?format:\s*nil/,
        ~r/Rails\.application\.config\.session_store.*?format:\s*false/,
        ~r/Rails\.application\.config\.session_store.*?format:\s*nil/
      ],
      default_tier: :ai,
      cwe_id: "CWE-614",
      owasp_category: "A05:2021",
      recommendation: "Configure Rails sessions with secure: true, httponly: true, and same_site: :strict for HTTPS environments. Review Rails session store configuration.",
      test_cases: %{
        vulnerable: [
          "config.session_store :cookie_store, key: '_app_session'",
          "config.session_store :cookie_store, secure: false",
          "config.session_store :cookie_store, httponly: false",
          "config.session_store :cookie_store, same_site: :none"
        ],
        safe: [
          "config.session_store :cookie_store, key: '_app_session', secure: true, httponly: true, same_site: :strict",
          "config.session_store :cookie_store, secure: true, httponly: true",
          "config.session_store :cookie_store, secure: Rails.env.production?, httponly: true"
        ]
      }
    }
  end
  
  def vulnerability_metadata do
    %{
      description: """
      Insecure Session Configuration in Rails applications represents a security 
      misconfiguration vulnerability where session cookies are configured without 
      proper security flags. This exposes applications to session hijacking, 
      cookie theft, and man-in-the-middle attacks. Rails session cookies without 
      the `secure` flag can be transmitted over unencrypted HTTP connections, 
      while cookies without the `httponly` flag can be accessed via JavaScript, 
      making them vulnerable to XSS attacks.
      
      The vulnerability is particularly dangerous because:
      1. It affects the core authentication mechanism of the application
      2. Session cookies contain sensitive authentication data
      3. Compromised sessions can lead to complete account takeover
      4. The vulnerability is often overlooked during development
      5. It affects all users of the application once deployed
      """,
      
      attack_vectors: """
      1. **Man-in-the-Middle Attack**: Intercepting session cookies over HTTP connections
      2. **WiFi Eavesdropping**: Capturing session cookies on unsecured networks
      3. **XSS Cookie Theft**: document.cookie access to steal httponly: false sessions
      4. **Session Replay**: Reusing intercepted session cookies for unauthorized access
      5. **CSRF with same_site: :none**: Cross-site request forgery attacks
      6. **Cookie Injection**: Injecting malicious session data when validation is weak
      7. **Session Fixation**: Forcing users to use attacker-controlled session IDs
      8. **Network Sniffing**: Passive interception of session cookies in transit
      9. **Browser History**: Session cookies stored in browser history/cache
      10. **Proxy Caching**: Session cookies cached by intermediate proxies (CVE-2024-26144)
      """,
      
      business_impact: """
      - Complete user account takeover through session hijacking
      - Unauthorized access to user data and functionality
      - Identity theft and impersonation of legitimate users
      - Data breach exposing sensitive customer information
      - Regulatory compliance violations (GDPR, PCI DSS, HIPAA)
      - Legal liability from compromised user accounts
      - Reputation damage from security incidents
      - Loss of customer trust and business
      - Financial fraud through unauthorized transactions
      - Business disruption from security incidents
      """,
      
      technical_impact: """
      - Complete bypass of authentication mechanisms
      - Unauthorized access to protected resources
      - Ability to perform actions as authenticated users
      - Access to user's personal and sensitive data
      - Potential for privilege escalation
      - Session persistence across security updates
      - Difficulty in detecting and tracing attacks
      - Compromise of audit trails and logging
      - Potential for lateral movement within the application
      - Database access through compromised admin sessions
      """,
      
      likelihood: "High - Session security misconfigurations are very common, especially in development environments that get promoted to production",
      
      cve_examples: """
      CVE-2024-26144 - Rails Active Storage Sensitive Session Information Leak (CVSS 5.3)
      CVE-2016-6316 - Ruby on Rails Action Record Session Store Replay Vulnerability
      CVE-2015-7576 - Rails Action Pack Session Timing Attack Vulnerability
      CVE-2014-0081 - Rails XML Processing Vulnerability affecting session handling
      CVE-2013-0155 - Rails SQL Injection via nested query parameters affecting sessions
      CVE-2012-2660 - Rails SQL injection vulnerability via deep symbol manipulation in sessions
      Multiple session fixation vulnerabilities in Rails applications without proper session management
      Session hijacking vulnerabilities in Rails apps with insecure cookie configurations
      """,
      
      compliance_standards: [
        "OWASP Top 10 2021 - A05: Security Misconfiguration",
        "CWE-614: Sensitive Cookie in HTTPS Session Without 'Secure' Attribute",
        "CWE-1004: Sensitive Cookie Without 'HttpOnly' Flag",
        "PCI DSS 6.5.10 - Broken authentication and session management",
        "NIST SP 800-53 - SC-23 Session Authenticity",
        "ISO 27001 - A.14.2.5 Secure system engineering principles",
        "ASVS 4.0 - V3.3 Session Management Verification Requirements",
        "SANS Top 25 - CWE-614 Sensitive Cookie Issues"
      ],
      
      remediation_steps: """
      1. **Configure Secure Session Flags (Critical)**:
         ```ruby
         # In config/application.rb or config/environments/production.rb
         
         # NEVER do this - Vulnerable session configuration
         config.session_store :cookie_store, key: '_app_session'          # DANGEROUS
         config.session_store :cookie_store, secure: false               # DANGEROUS
         config.session_store :cookie_store, httponly: false             # DANGEROUS
         config.session_store :cookie_store, same_site: :none            # DANGEROUS
         
         # Always configure with proper security flags
         config.session_store :cookie_store, 
           key: '_app_session',
           secure: Rails.env.production?,  # true in production, false in development
           httponly: true,                 # Prevent JavaScript access
           same_site: :strict              # CSRF protection
         
         # Production-only secure configuration
         config.session_store :cookie_store,
           key: '_app_session',
           secure: true,                   # HTTPS only
           httponly: true,                 # No JavaScript access
           same_site: :strict,             # Strict CSRF protection
           expire_after: 24.hours          # Session timeout
         ```
      
      2. **Environment-Specific Configuration**:
         ```ruby
         # config/environments/production.rb
         Rails.application.configure do
           config.session_store :cookie_store,
             key: '_app_session',
             secure: true,                 # Force HTTPS in production
             httponly: true,
             same_site: :strict,
             expire_after: 30.minutes      # Short session timeout
         end
         
         # config/environments/development.rb
         Rails.application.configure do
           config.session_store :cookie_store,
             key: '_app_session_dev',
             secure: false,                # Allow HTTP in development
             httponly: true,               # Still protect from XSS
             same_site: :lax               # More lenient for development
         end
         
         # config/environments/test.rb
         Rails.application.configure do
           config.session_store :active_record_store,  # Use database for tests
             key: '_app_session_test'
         end
         ```
      
      3. **Secure Session Management Helpers**:
         ```ruby
         # In ApplicationController
         class ApplicationController < ActionController::Base
           # Force session regeneration on login
           def secure_login(user)
             reset_session                 # Prevent session fixation
             session[:user_id] = user.id
             session[:login_time] = Time.current
             session[:ip_address] = request.remote_ip
           end
           
           # Secure logout
           def secure_logout
             reset_session                 # Clear all session data
             redirect_to login_path
           end
           
           # Session security validation
           before_action :validate_session_security
           
           private
           
           def validate_session_security
             if session[:user_id].present?
               # Check session age
               if session[:login_time] && session[:login_time] < 24.hours.ago
                 reset_session
                 redirect_to login_path, alert: 'Session expired'
                 return
               end
               
               # Check IP address (optional, can be problematic with NAT)
               # if session[:ip_address] != request.remote_ip
               #   reset_session
               #   redirect_to login_path, alert: 'Session security violation'
               #   return
               # end
             end
           end
         ```
      
      4. **Session Secret Management**:
         ```ruby
         # NEVER hardcode secrets
         # BAD:
         config.session_store :cookie_store, secret: 'hardcoded_secret'
         
         # GOOD: Use Rails credentials
         config.session_store :cookie_store, 
           secret_key_base: Rails.application.credentials.secret_key_base
         
         # Or use environment variables
         config.session_store :cookie_store,
           secret_key_base: ENV['SECRET_KEY_BASE']
         
         # Generate strong secrets
         # rails secret
         # Store in config/credentials.yml.enc (Rails 5.2+)
         ```
      """,
      
      prevention_tips: """
      - Always set secure: true for production HTTPS environments
      - Always set httponly: true to prevent JavaScript access to session cookies
      - Use same_site: :strict or :lax for CSRF protection (avoid :none)
      - Never hardcode session secrets; use Rails credentials or environment variables
      - Implement session timeout and regeneration on authentication
      - Use different session keys for different environments
      - Regularly rotate session secrets
      - Monitor session security configurations in CI/CD pipelines
      - Use security linters like Brakeman to detect insecure configurations
      - Implement proper session invalidation on logout
      - Consider using database-backed sessions for sensitive applications
      - Regular security audits of session management code
      """,
      
      detection_methods: """
      - Static analysis with Brakeman scanner (detects insecure session configurations)
      - Manual code review of config/application.rb and config/environments/ files
      - Grep/ripgrep patterns: session_store.*secure.*false, session_store.*httponly.*false
      - Browser developer tools inspection of Set-Cookie headers
      - Web application security scanners checking cookie security flags
      - Penetration testing with session hijacking attempts
      - Runtime monitoring of session cookie attributes
      - Security-focused linters and IDE plugins
      - Automated configuration audits in CI/CD pipelines
      - Manual verification of cookie flags in production environments
      """,
      
      safe_alternatives: """
      # 1. Production-Ready Session Configuration
      # config/environments/production.rb
      Rails.application.configure do
        config.session_store :cookie_store,
          key: '_app_session',
          secure: true,                    # HTTPS only
          httponly: true,                  # No JavaScript access
          same_site: :strict,              # Strong CSRF protection
          expire_after: 30.minutes,        # Session timeout
          secret_key_base: Rails.application.credentials.secret_key_base
      end
      
      # 2. Development-Friendly Configuration
      # config/environments/development.rb
      Rails.application.configure do
        config.session_store :cookie_store,
          key: '_app_session_dev',
          secure: false,                   # Allow HTTP in development
          httponly: true,                  # Still protect from XSS
          same_site: :lax                  # More lenient for development
      end
      
      # 3. Database-Backed Sessions (More Secure)
      # Gemfile
      gem 'activerecord-session_store'
      
      # Generate session migration
      # rails generate session_migration
      
      # config/application.rb
      config.session_store :active_record_store,
        key: '_app_session',
        secure: Rails.env.production?,
        httponly: true,
        same_site: :strict,
        expire_after: 24.hours
      
      # 4. Redis-Backed Sessions (Scalable)
      # Gemfile
      gem 'redis-rails'
      
      # config/application.rb
      config.session_store :redis_store,
        servers: [ENV['REDIS_URL']],
        expire_after: 30.minutes,
        key: '_app_session',
        secure: Rails.env.production?,
        httponly: true,
        same_site: :strict
      
      # 5. Conditional Security Configuration
      class SecureSessionConfig
        def self.configure(config)
          if Rails.env.production?
            config.session_store :cookie_store,
              key: '_app_session',
              secure: true,
              httponly: true,
              same_site: :strict,
              expire_after: 20.minutes
          elsif Rails.env.staging?
            config.session_store :cookie_store,
              key: '_app_session_staging',
              secure: true,
              httponly: true,
              same_site: :lax,
              expire_after: 1.hour
          else
            config.session_store :cookie_store,
              key: '_app_session_dev',
              secure: false,
              httponly: true,
              same_site: :lax
          end
      end
      
      # In config/application.rb
      SecureSessionConfig.configure(config)
      
      # 6. Session Security Validator
      class SessionSecurityValidator
        def self.validate_production_config!
          store = Rails.application.config.session_store
          options = Rails.application.config.session_options || {}
          
          if Rails.env.production?
            raise "Production session must be secure!" unless options[:secure]
            raise "Production session must be httponly!" unless options[:httponly]
            raise "Production session should not use same_site: :none!" if options[:same_site] == :none
          end
        end
      
      # In config/environments/production.rb
      config.after_initialize do
        SessionSecurityValidator.validate_production_config!
      end
      """
    }
  end
  
  def ast_enhancement do
    %{
      min_confidence: 0.6,
      
      context_rules: %{
        # Session configuration methods
        session_config_methods: [
          "session_store", "config.session_store", 
          "Rails.application.config.session_store"
        ],
        
        # Security flags that should be present
        security_flags: [
          "secure", "httponly", "same_site"
        ],
        
        # Dangerous same_site values
        dangerous_same_site: [":none", "none"],
        
        # Session store types
        session_stores: [
          "cookie_store", "active_record_store", "memory_store", 
          "redis_store", "cache_store"
        ],
        
        # Safe patterns to reduce false positives
        safe_patterns: [
          ~r/secure:\s*true/,                    # Has secure flag
          ~r/secure:\s*Rails\.env\.production\?/, # Environment-based secure
          ~r/httponly:\s*true/,                  # Has httponly flag
          ~r/same_site:\s*:strict/,              # Strict same_site
          ~r/same_site:\s*:lax/,                 # Lax same_site (acceptable)
          ~r/secret_key_base:\s*Rails\.application\.credentials/, # Proper secret management
          ~r/secret_key_base:\s*ENV\[/           # Environment-based secrets
        ]
      },
      
      confidence_rules: %{
        adjustments: %{
          # High confidence for explicit insecure flags
          explicit_secure_false: +0.4,
          explicit_httponly_false: +0.4,
          same_site_none: +0.3,
          weak_session_secret: +0.5,
          
          # Medium confidence for missing security flags
          missing_security_flags: +0.3,
          basic_session_config: +0.2,
          
          # Lower confidence for safer configurations
          has_secure_flag: -0.5,
          has_httponly_flag: -0.4,
          environment_based_config: -0.3,
          proper_secret_management: -0.4,
          
          # Context-based adjustments
          in_development_env: -0.6,
          in_test_file: -0.8,
          commented_config: -0.9,
          has_session_timeout: -0.2,
          
          # File location adjustments
          in_production_config: +0.2,
          in_application_config: +0.1
        }
      },
      
      ast_rules: %{
        # Configuration analysis
        config_analysis: %{
          check_session_store_calls: true,
          detect_missing_security_flags: true,
          validate_flag_values: true,
          check_secret_management: true
        },
        
        # Security flag validation
        flag_validation: %{
          required_flags: ["secure", "httponly"],
          dangerous_values: %{
            "secure" => [false],
            "httponly" => [false],
            "same_site" => [:none]
          }
        },
        
        # Environment context analysis
        environment_analysis: %{
          check_environment_files: true,
          validate_production_config: true,
          detect_development_leakage: true
        },
        
        # Secret management analysis
        secret_analysis: %{
          detect_hardcoded_secrets: true,
          validate_secret_sources: true,
          check_secret_strength: true
        }
      }
    }
  end
  
end

