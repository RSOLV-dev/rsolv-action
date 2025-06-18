defmodule RsolvApi.Security.Patterns.Rails.CallbackSecurityBypass do
  @moduledoc """
  Rails Callback Security Bypass pattern for Rails applications.
  
  This pattern detects insecure usage of skip_before_action and similar
  callback skip methods where user input is used in conditions, potentially
  allowing attackers to bypass security constraints like authentication
  and authorization.
  
  ## Background
  
  Rails uses callback filters (before_action, around_action, after_action)
  to enforce security constraints like authentication and authorization.
  The skip_*_action methods allow bypassing these callbacks under certain
  conditions. When user-controlled input is used in these conditions, it
  creates a security vulnerability.
  
  ## Vulnerability Details
  
  The vulnerability occurs when:
  1. User input (params) is used directly in skip callback conditions
  2. Lambda/proc conditions evaluate user-controlled data
  3. Dynamic conditions based on request parameters
  4. eval() is used with user input in conditions
  
  ## Examples
  
      # VULNERABLE - User can bypass authentication
      skip_before_action :authenticate, if: -> { params[:skip] }
      
      # VULNERABLE - Direct params usage
      skip_around_action :authorize, if: params[:bypass]
      
      # VULNERABLE - eval with user input
      skip_after_action :log_action, if: -> { eval(params[:condition]) }
      
      # SAFE - Predefined method
      skip_before_action :authenticate, if: :public_action?
      
      # SAFE - No user input
      skip_before_action :authenticate, only: [:index, :show]
  """
  
  use RsolvApi.Security.Patterns.PatternBase
  
  def pattern do
    %RsolvApi.Security.Pattern{
      id: "rails-callback-security-bypass",
      name: "Rails Callback Security Bypass",
      description: "Bypass of security constraints through skip callback conditions",
      type: :broken_access_control,
      severity: :high,
      languages: ["ruby"],
      frameworks: ["rails"],
      regex: [
        # skip_before_action with params in lambda (exclude comments)
        ~r/^(?!.*#).*skip_before_(?:action|filter).*?if:\s*->\s*\{[^}]*params\[/m,
        
        # skip_around_action with direct params usage (exclude comments)
        ~r/^(?!.*#).*skip_around_(?:action|filter).*?if:\s*params\[/m,
        
        # skip_after_action with eval in lambda (exclude comments)
        ~r/^(?!.*#).*skip_after_(?:action|filter).*?if:\s*->\s*\{[^}]*eval\s*\(/m,
        
        # Any skip with params in complex lambda (exclude comments)
        ~r/^(?!.*#).*skip_(?:before|around|after)_(?:action|filter).*?if:\s*->\s*\{[^}]*params\[/m,
        
        # Skip with unless and params (exclude comments)
        ~r/^(?!.*#).*skip_(?:before|around|after)_(?:action|filter).*?unless:\s*->\s*\{[^}]*params\[/m,
        
        # Legacy _filter versions (exclude comments)
        ~r/^(?!.*#).*skip_before_filter.*?if:\s*->\s*\{[^}]*params\[/m
      ],
      default_tier: :ai,
      cwe_id: "CWE-285",
      owasp_category: "A01:2021",
      recommendation: "Never use user input in Rails skip callback conditions. Use safe, predefined conditions in Rails controllers.",
      test_cases: %{
        vulnerable: [
          "skip_before_action :authenticate, if: -> { params[:skip] }"
        ],
        safe: [
          "skip_before_action :authenticate, if: :public_action?"
        ]
      }
    }
  end
  
  def vulnerability_metadata do
    %{
      description: """
      Rails Callback Security Bypass is a critical vulnerability that occurs when
      user-controlled input is used in conditions for skipping security callbacks.
      Rails filters (before_action, around_action, after_action) are commonly used
      to enforce authentication, authorization, and other security constraints.
      When developers use skip_*_action methods with conditions based on user input,
      attackers can manipulate these conditions to bypass critical security checks.
      
      This vulnerability is particularly dangerous because:
      1. It can completely bypass authentication mechanisms
      2. Authorization checks can be circumvented
      3. Security logging and audit trails can be skipped
      4. Rate limiting and abuse prevention can be defeated
      5. The bypass is often silent and leaves no trace
      """,
      
      attack_vectors: """
      1. **Direct Parameter Manipulation**: Attacker adds ?skip=true for authentication bypass
      2. **Boolean Injection**: Using params[:admin]=true to skip authorization checks
      3. **Eval Exploitation**: Injecting malicious code through eval(params[:condition])
      4. **Logic Manipulation**: Crafting parameters to satisfy complex skip conditions
      5. **Type Confusion**: Using unexpected parameter types to trigger skips
      6. **Parameter Pollution**: Multiple parameter values to confuse skip logic
      7. **Null Byte Injection**: Using null bytes to bypass string comparisons
      8. **Unicode Bypass**: Using unicode equivalents to bypass checks
      9. **Case Sensitivity**: Exploiting case-sensitive comparisons
      10. **Timing Attacks**: Using race conditions in callback evaluation
      """,
      
      business_impact: """
      - Complete authentication bypass allowing unauthorized access to user accounts
      - Authorization bypass enabling privilege escalation to admin functions
      - Data breach through access to protected resources and sensitive information
      - Compliance violations from bypassed security controls (SOC2, PCI-DSS, HIPAA)
      - Financial fraud through bypassed payment verification callbacks
      - Audit trail gaps from skipped logging callbacks
      - Reputation damage from security incidents and data breaches
      - Legal liability from unauthorized access to customer data
      - Business logic bypass affecting critical workflows
      - Competitive disadvantage from exposed proprietary information
      """,
      
      technical_impact: """
      - Authentication mechanisms completely bypassed
      - Authorization checks rendered ineffective
      - Session validation skipped
      - CSRF protection bypassed
      - Rate limiting defeated
      - Security headers not applied
      - Logging and monitoring bypassed
      - Input validation skipped
      - Output encoding bypassed
      - Security middleware ineffective
      """,
      
      likelihood: "High - Developers often use params in skip conditions for flexibility without realizing the security implications",
      
      cve_examples: """
      While specific CVEs for callback bypass are rare (often application-specific),
      the pattern has been observed in many Rails security audits:
      
      - Authentication bypass in popular Rails CMSs through skip_before_action
      - Admin panel access through manipulated skip conditions
      - API authentication bypass using params-based skips
      - Payment verification bypass in e-commerce platforms
      - Multi-factor authentication bypass through callback manipulation
      
      Related vulnerabilities:
      - CWE-285: Improper Authorization
      - CWE-863: Incorrect Authorization
      - CWE-287: Improper Authentication
      - CWE-284: Improper Access Control
      """,
      
      compliance_standards: [
        "OWASP Top 10 2021 - A01: Broken Access Control",
        "CWE-285: Improper Authorization",
        "CWE-863: Incorrect Authorization",
        "CWE-287: Improper Authentication",
        "PCI DSS 6.5.8 - Improper access control",
        "NIST SP 800-53 - AC-3 Access Enforcement",
        "ISO 27001 - A.9.4 System and application access control",
        "ASVS 4.0 - V4 Access Control Verification Requirements",
        "SANS Top 25 - CWE-285 Improper Authorization"
      ],
      
      remediation_steps: """
      1. **Never Use User Input in Skip Conditions**:
         ```ruby
         # NEVER DO THIS - User input in skip condition
         class UsersController < ApplicationController
           skip_before_action :authenticate, if: -> { params[:public] }  # VULNERABLE
           skip_before_action :authorize, if: -> { params[:skip_auth] }  # VULNERABLE
         end
         
         # SAFE - Use predefined methods
         class UsersController < ApplicationController
           skip_before_action :authenticate, if: :public_endpoint?
           skip_before_action :authorize, only: [:index, :show]
           
           private
           
           def public_endpoint?
             %w[index show about].include?(action_name)
           end
         ```
      
      2. **Use Static Conditions Only**:
         ```ruby
         # SAFE - Static action lists
         class PublicController < ApplicationController
           skip_before_action :authenticate_user, only: [:home, :about, :contact]
           skip_after_action :track_activity, except: [:download]
         end
         
         # SAFE - Environment-based skips
         class DevelopmentController < ApplicationController
           skip_before_action :require_https, if: -> { Rails.env.development? }
         end
         ```
      
      3. **Implement Secure Public Endpoints**:
         ```ruby
         # Instead of conditional skips, use separate controllers
         class PublicController < ApplicationController
           # No authentication required for any action
         end
         
         class AuthenticatedController < ApplicationController
           before_action :authenticate_user!
         end
         
         class Admin::BaseController < AuthenticatedController
           before_action :require_admin!
         end
         ```
      
      4. **Secure Callback Design Pattern**:
         ```ruby
         class ApplicationController < ActionController::Base
           # Define security callbacks at the top level
           before_action :authenticate_user!
           before_action :check_authorization
           before_action :log_activity
           
           protected
           
           # Use method-based conditions, never params
           def requires_authentication?
             true  # Override in subclasses if needed
           end
           
           def authenticate_user!
             return unless requires_authentication?
             # Authentication logic
           end
         
         class PublicPagesController < ApplicationController
           # Override the method, not the callback
           def requires_authentication?
             false
           end
         end
         ```
      
      5. **Audit Existing Code**:
         ```ruby
         # Search for vulnerable patterns
         # grep -r "skip_.*_action.*params" app/controllers/
         # grep -r "skip_.*_filter.*params" app/controllers/
         
         # Use a security scanner
         # bundle exec brakeman -A
         ```
      """,
      
      prevention_tips: """
      - Never use request parameters in callback skip conditions
      - Use static lists for actions that should skip callbacks
      - Implement separate controllers for public vs authenticated endpoints
      - Use method-based conditions that don't rely on user input
      - Regular security audits of callback usage
      - Code review checklist for callback skips
      - Automated scanning for vulnerable patterns
      - Developer training on secure callback usage
      - Centralize authentication/authorization logic
      - Use framework security features properly
      """,
      
      detection_methods: """
      - Static analysis tools (Brakeman) can detect params in skip conditions
      - Code review focusing on skip_*_action usage
      - Grep/search for skip patterns with params
      - Security testing with parameter manipulation
      - Automated security scanning in CI/CD
      - Manual penetration testing of authentication flows
      - Monitoring for unexpected authentication bypasses
      - Log analysis for suspicious access patterns
      """,
      
      safe_alternatives: """
      # Safe Alternatives Using Predefined Conditions
      
      # 1. Separate Public and Private Controllers
      class PublicController < ApplicationController
        # No authentication needed
      end
      
      class SecureController < ApplicationController
        before_action :authenticate_user!
      end
      
      # 2. Method-Based Conditions (Predefined Logic)
      class PostsController < SecureController
        skip_before_action :authenticate_user!, if: :public_post?
        
        private
        
        def public_post?
          # Check database with predefined conditions, not params
          @post = Post.find(params[:id])
          @post.public?
        end
      
      # 3. Action-Based Skips
      class ProductsController < ApplicationController
        skip_before_action :authenticate_user!, only: [:index, :show]
        before_action :authenticate_user!, only: [:new, :create, :edit, :update, :destroy]
      end
      
      # 4. Explicit Public Actions
      class ApiController < ApplicationController
        PUBLIC_ACTIONS = %w[status health version].freeze
        
        before_action :authenticate_api_user!, unless: :public_action?
        
        private
        
        def public_action?
          PUBLIC_ACTIONS.include?(action_name)
        end
      end
      
      # 5. Role-Based Conditions
      class AdminController < ApplicationController
        before_action :require_admin!
        
        # Skip for super admins only - based on user role, not params
        skip_before_action :log_admin_action, if: :super_admin?
        
        private
        
        def super_admin?
          current_user&.super_admin?
        end
      end
      """
    }
  end
  
  def ast_enhancement do
    %{
      min_confidence: 0.8,
      
      context_rules: %{
        # Callback methods that can be skipped
        callback_methods: [
          "skip_before_action", "skip_after_action", "skip_around_action",
          "skip_before_filter", "skip_after_filter", "skip_around_filter"
        ],
        
        # Dangerous conditions
        dangerous_conditions: [
          "params[", "request.params", "params.",
          "eval(", "instance_eval", "class_eval"
        ],
        
        # Safe patterns
        safe_patterns: [
          ~r/if:\s*:[a-z_]+\??$/,              # Symbol method reference
          ~r/only:\s*\[/,                      # Action list
          ~r/except:\s*\[/,                    # Exception list
          ~r/if:\s*->\s*\{\s*Rails\.env/,     # Rails env check
          ~r/if:\s*->\s*\{\s*[A-Z]/           # Constant reference
        ],
        
        # Common security callbacks
        security_callbacks: [
          "authenticate", "authenticate_user", "authenticate_admin",
          "authorize", "require_login", "check_authorization",
          "verify_authenticity_token", "ensure_authenticated"
        ]
      },
      
      confidence_rules: %{
        adjustments: %{
          # High confidence for dangerous patterns
          params_in_condition: +0.5,
          eval_in_condition: +0.7,
          security_callback_skip: +0.4,
          
          # Lower confidence for safe patterns
          symbol_method_condition: -0.6,
          static_action_list: -0.8,
          rails_env_condition: -0.7,
          constant_condition: -0.5,
          
          # Context adjustments
          in_controller: +0.2,
          in_concern: +0.2,
          in_application_controller: +0.3,
          
          # File location adjustments
          in_test_file: -0.9,
          in_spec_file: -0.9,
          commented_line: -1.0
        }
      },
      
      ast_rules: %{
        # Callback analysis
        callback_analysis: %{
          detect_skip_methods: true,
          detect_user_input_conditions: true,
          detect_eval_usage: true,
          analyze_condition_complexity: true
        },
        
        # Condition analysis
        condition_analysis: %{
          check_if_conditions: true,
          check_unless_conditions: true,
          detect_lambda_procs: true,
          analyze_condition_body: true
        },
        
        # Security impact analysis
        security_analysis: %{
          identify_security_callbacks: true,
          assess_bypass_impact: true,
          check_authentication_skips: true,
          check_authorization_skips: true
        },
        
        # Safe pattern detection
        safe_pattern_detection: %{
          method_references: true,
          static_lists: true,
          environment_checks: true,
          constant_checks: true
        }
      }
    }
  end
  
end

