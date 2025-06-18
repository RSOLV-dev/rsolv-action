defmodule RsolvApi.Security.Patterns.Rails.MissingStrongParameters do
  @moduledoc """
  Missing Strong Parameters vulnerability pattern for Rails applications.
  
  This pattern detects Rails controllers using params without permit(), which
  allows mass assignment vulnerabilities where attackers can modify any model
  attribute including sensitive fields like role, admin status, or internal IDs.
  
  ## Background
  
  Rails 4+ introduced Strong Parameters to prevent mass assignment vulnerabilities.
  Before Rails 4, attr_accessible and attr_protected were used, but these were
  model-level protections that could be accidentally bypassed.
  
  ## Vulnerability Details
  
  Mass assignment occurs when user input is directly passed to model create/update
  methods without filtering. This allows attackers to set any model attribute,
  potentially escalating privileges or modifying protected data.
  
  ## Known CVEs
  
  - CVE-2020-8164: Rails parameter parsing vulnerability allowing bypass
  - CVE-2013-0276: attr_protected bypass in Rails 2.3.x and 3.0.x
  - CVE-2012-2694: Mass assignment vulnerability in Rails 3.x
  
  ## Examples
  
      # Vulnerable - allows any parameter
      @user = User.create(params[:user])
      
      # Vulnerable - dangerous permit!
      @user = User.create(params.permit!)
      
      # Safe - explicitly permits only allowed fields
      @user = User.create(user_params)
      
      def user_params
        params.require(:user).permit(:name, :email)
      end
  """
  
  use RsolvApi.Security.Patterns.PatternBase
  
  def pattern do
    %RsolvApi.Security.Pattern{
      id: "rails-missing-strong-parameters",
      name: "Missing Strong Parameters",
      description: "Rails controllers using params without permit() allowing mass assignment",
      type: :mass_assignment,
      severity: :high,
      languages: ["ruby"],
      frameworks: ["rails"],
      regex: [
        # Direct params usage in create/update
        ~r/\.(create|update|update_attributes|assign_attributes)\s*\(\s*params\[:[^\]]+\]/,
        # Direct params with bang methods
        ~r/\.(create!|update!)\s*\(\s*params\[:[^\]]+\]/,
        # ActiveRecord.new with params
        ~r/\.new\s*\(\s*params\[:[^\]]+\]/,
        # Dangerous permit! usage
        ~r/\.permit!\s*(?:\)|$)/,
        # insert_all/upsert_all with params
        ~r/\.(insert_all|upsert_all)\s*\(\s*params\[:[^\]]+\]/
      ],
      default_tier: :ai,
      cwe_id: "CWE-915",
      owasp_category: "A01:2021",
      recommendation: "Use strong parameters with permit(): params.require(:model).permit(:field1, :field2). Never use permit! in production.",
      test_cases: %{
        vulnerable: [
          "@user = User.create(params[:user])",
          "@post.update(params[:post])",
          "User.new(params[:user])",
          "params.permit!",
          "User.insert_all(params[:users])"
        ],
        safe: [
          "@user = User.create(user_params)",
          "params.require(:user).permit(:name, :email)",
          "@user = User.create(params.require(:user).permit(:name))"
        ]
      }
    }
  end
  
  def vulnerability_metadata do
    %{
      description: """
      Mass assignment vulnerabilities occur when user-supplied data is passed directly
      to model create/update methods without proper filtering. This allows attackers
      to modify any model attribute, including sensitive fields that should be protected.
      
      In Rails applications, this commonly happens when developers use params[:model]
      directly instead of using Strong Parameters to explicitly permit allowed fields.
      This can lead to privilege escalation, data tampering, and unauthorized access.
      """,
      
      attack_vectors: """
      1. **Privilege Escalation**: Adding role=admin or admin=true to requests
      2. **Account Takeover**: Modifying user_id or email fields
      3. **Data Tampering**: Changing prices, quantities, or status fields
      4. **Bypassing Validation**: Setting internal fields like confirmed_at
      5. **Association Manipulation**: Changing foreign keys to access other data
      """,
      
      business_impact: """
      - Unauthorized privilege escalation to admin accounts
      - Financial loss through price manipulation
      - Data breach via unauthorized data access
      - Compliance violations (GDPR, PCI-DSS)
      - Reputation damage from security incidents
      """,
      
      technical_impact: """
      - Complete bypass of authorization controls
      - Ability to modify any database column
      - Potential for SQL injection via nested attributes
      - Session hijacking through user_id manipulation
      - Audit trail corruption
      """,
      
      likelihood: "High - Very common in Rails applications, especially legacy code",
      
      cve_examples: [
        "CVE-2020-8164 - Rails parameter parsing allowing Strong Parameters bypass",
        "CVE-2013-0276 - Rails attr_protected bypass vulnerability",
        "CVE-2012-2694 - Rails mass assignment vulnerability in protected attributes"
      ],
      
      compliance_standards: [
        "OWASP Top 10 2021 - A01: Broken Access Control",
        "CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes",
        "PCI DSS 6.5.8 - Improper access control",
        "ISO 27001 - A.14.2.5 Secure system engineering principles"
      ],
      
      remediation_steps: """
      1. **Implement Strong Parameters**:
         ```ruby
         def user_params
           params.require(:user).permit(:name, :email, :phone)
         end
         
         @user = User.create(user_params)
         ```
      
      2. **Never use permit!** in production code
      
      3. **Use nested attributes carefully**:
         ```ruby
         params.require(:user).permit(:name, addresses_attributes: [:street, :city])
         ```
      
      4. **Validate permitted parameters**:
         ```ruby
         def user_params
           params.require(:user).permit(:name, :email).tap do |permitted|
             permitted[:email] = permitted[:email].downcase if permitted[:email]
           end
         end
         ```
      
      5. **Audit existing code** for direct params usage
      """,
      
      prevention_tips: """
      - Always use strong parameters in Rails 4+
      - Create private parameter methods for each model
      - Use RuboCop's Rails/StrongParameters cop
      - Implement parameter logging for security audits
      - Regular security reviews of controller code
      - Use form objects for complex parameter handling
      """,
      
      detection_methods: """
      - Static analysis with tools like Brakeman
      - Code review checklist for params usage
      - Automated testing of mass assignment protection
      - Runtime parameter monitoring
      - Security scanning in CI/CD pipeline
      """,
      
      safe_alternatives: """
      # Instead of:
      @user = User.create(params[:user])
      
      # Use:
      @user = User.create(user_params)
      
      private
      def user_params
        params.require(:user).permit(:name, :email, :bio)
      end
      
      # For updates:
      if @user.update(user_params)
        redirect_to @user
      else
        render :edit
      end
      
      # For complex scenarios, use form objects:
      class UserRegistrationForm
        include ActiveModel::Model
        
        attr_accessor :name, :email, :terms_accepted
        
        validates :terms_accepted, acceptance: true
        
        def save
          return false unless valid?
          User.create!(name: name, email: email)
        end
      end
      """
    }
  end
  
  def ast_enhancement do
    %{
      min_confidence: 0.8,
      
      context_rules: %{
        # Rails version affects Strong Parameters availability
        rails_versions: %{
          "< 4.0" => "Strong Parameters not available, check for attr_accessible",
          ">= 4.0" => "Strong Parameters should be used"
        },
        
        # Look for controller indicators
        controller_indicators: [
          "class.*Controller",
          "ApplicationController",
          "ActionController::Base",
          "ActionController::API"
        ],
        
        # Private parameter methods are good
        parameter_method_indicators: [
          "def.*_params",
          "params.require.*permit",
          "params.permit"
        ]
      },
      
      confidence_rules: %{
        # Increase confidence
        adjustments: %{
          # High confidence if in controller action
          in_controller_action: +0.3,
          # Lower confidence if parameter method exists
          has_params_method: -0.2,
          # High confidence for permit!
          uses_permit_bang: +0.4,
          # Lower confidence if in test file
          in_test_file: -0.5,
          # Higher confidence if params comes from request
          params_from_request: +0.2,
          # Lower confidence if params is a local variable
          params_is_local: -0.3,
          # Very high confidence for well-known patterns
          known_vulnerable_pattern: +0.5,
          # Lower if wrapped in safe method
          wrapped_in_safe_method: -0.4,
          # Adjust based on method
          create_method: +0.2,
          update_method: +0.2,
          new_method: +0.1,
          # Strong params method name penalty
          strong_params_method_penalty: -0.6
        }
      },
      
      ast_rules: %{
        # Check for parameter filtering
        parameter_analysis: %{
          # Look for .permit usage
          check_permit_usage: true,
          # Look for require usage  
          check_require_usage: true,
          # Flag permit! as always vulnerable
          flag_permit_bang: true,
          # Check if params is filtered elsewhere
          check_filtered_params: true
        },
        
        # Method context analysis
        method_analysis: %{
          # Is this in a controller action?
          check_controller_context: true,
          # Is there a private params method?
          check_params_method: true,
          # Is this in a before_action?
          check_before_action: true
        },
        
        # Rails-specific analysis
        rails_analysis: %{
          # Check Rails version if available
          check_rails_version: true,
          # Look for Strong Parameters gem in old Rails
          check_strong_parameters_gem: true,
          # Check for attr_accessible (old style)
          check_attr_accessible: true
        }
      }
    }
  end
  
  # Base PatternBase implementation now handles Rails controller targeting
end

