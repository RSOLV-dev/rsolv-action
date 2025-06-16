defmodule RsolvApi.Security.Patterns.Rails.DangerousAttrAccessible do
  @moduledoc """
  Dangerous attr_accessible usage pattern for Rails applications.
  
  This pattern detects overly permissive attr_accessible declarations in Rails 2.x 
  and 3.x applications that can lead to mass assignment vulnerabilities. This was
  Rails' primary defense against mass assignment before Strong Parameters in Rails 4.
  
  ## Background
  
  Before Rails 4, the attr_accessible and attr_protected methods were used to control
  mass assignment. However, these approaches had significant weaknesses:
  - attr_protected uses blacklisting (dangerous - you might forget fields)
  - attr_accessible uses whitelisting (safer but still error-prone)
  - Missing attr_accessible means ALL attributes are assignable
  
  ## Vulnerability Details
  
  The vulnerability occurs when:
  1. attr_accessible includes sensitive fields (admin, role, etc.)
  2. Models lack any attr_accessible declaration (everything is assignable)
  3. Using attr_accessible with :as => :admin options carelessly
  4. Including password or token fields in attr_accessible
  
  ## Known CVEs
  
  - CVE-2013-0276: ActiveRecord attr_protected bypass vulnerability
  - CVE-2012-2660: Rails mass assignment vulnerability affecting GitHub
  - CVE-2012-2694: Mass assignment vulnerability in Rails 3.x
  
  ## Examples
  
      # Vulnerable - admin field exposed
      attr_accessible :name, :email, :admin
      
      # Vulnerable - no protection at all
      class User < ActiveRecord::Base
        # No attr_accessible means all fields are assignable!
      end
      
      # Vulnerable - role escalation possible
      attr_accessible :name, :email, as: :admin
      
      # Safe - only safe fields exposed
      attr_accessible :name, :email, :bio
      attr_protected :admin, :role, :permissions
  """
  
  use RsolvApi.Security.Patterns.PatternBase
  
  @impl true
  def pattern do
    %RsolvApi.Security.Pattern{
      id: "rails-dangerous-attr-accessible",
      name: "Dangerous attr_accessible Usage",
      description: "Overly permissive attr_accessible in older Rails versions or missing protection",
      type: :mass_assignment,
      severity: :high,
      languages: ["ruby"],
      frameworks: ["rails"],
      regex: [
        # Dangerous fields in attr_accessible (not in comments)
        ~r/^[^#]*attr_accessible\s+.*?:(?:admin|role|is_admin|administrator|permissions|user_role)\b/m,
        # Password/token fields exposed (not in comments)
        ~r/^[^#]*attr_accessible\s+.*?:(?:password_digest|encrypted_password|api_key|authentication_token|session_token)\b/m,
        # Using as: :admin option (dangerous context)
        ~r/^[^#]*attr_accessible\s+.*?\bas:\s*:(?:admin|administrator|superuser)\b/m,
        # Using :as => :admin option (hash rocket syntax)
        ~r/^[^#]*attr_accessible\s+.*?:as\s*=>\s*:(?:admin|administrator|superuser)\b/m,
        # ActiveRecord model without attr_accessible (matches the whole class)
        ~r/class\s+\w+\s*<\s*ActiveRecord::Base(?:(?!attr_accessible|attr_protected|end).)*?end/ms
      ],
      default_tier: :protected,
      cwe_id: "CWE-915",
      owasp_category: "A01:2021",
      recommendation: "Upgrade to Rails 4+ and use strong parameters. If using older Rails, carefully restrict attr_accessible fields.",
      test_cases: %{
        vulnerable: [
          "attr_accessible :name, :email, :admin",
          "attr_accessible :role, :username",
          "class User < ActiveRecord::Base\nend"
        ],
        safe: [
          "attr_accessible :name, :email, :bio",
          "attr_protected :admin, :role",
          "params.require(:user).permit(:name, :email)"
        ]
      }
    }
  end
  
  @impl true
  def vulnerability_metadata do
    %{
      description: """
      Mass assignment vulnerabilities in Rails 2.x and 3.x occur when attr_accessible
      is misconfigured or missing entirely. This allows attackers to set any model
      attribute through HTTP parameters, potentially escalating privileges or accessing
      protected data.
      
      The attr_accessible/attr_protected mechanism was Rails' first attempt at preventing
      mass assignment, but it had significant flaws that led to high-profile breaches
      including the GitHub hack of 2012 where Egor Homakov demonstrated the vulnerability
      by adding his SSH key to the Rails repository.
      """,
      
      attack_vectors: """
      1. **Direct Privilege Escalation**: POST user[admin]=true or user[role]=admin
      2. **Account Takeover**: Modifying user_id or email to hijack accounts  
      3. **Password Override**: Setting password_digest directly to bypass hashing
      4. **Token Theft**: Accessing or modifying API keys and session tokens
      5. **Association Manipulation**: Changing foreign keys to access other users' data
      6. **Bypass Validation**: Setting internal fields like confirmed_at or verified
      """,
      
      business_impact: """
      - Complete system compromise through admin privilege escalation
      - Data breach affecting all users and sensitive information
      - Financial fraud through price or balance manipulation
      - Reputation damage from high-profile security incidents
      - Legal liability for data protection violations
      """,
      
      technical_impact: """
      - Arbitrary database field modification
      - Complete bypass of business logic and validations
      - Authentication and authorization bypass
      - Potential for SQL injection through nested attributes
      - Session hijacking and impersonation
      """,
      
      likelihood: "Very High - Common mistake in Rails 2.x/3.x applications",
      
      cve_examples: [
        "CVE-2013-0276 - ActiveRecord attr_protected bypass allowing mass assignment",
        "CVE-2012-2660 - GitHub mass assignment vulnerability via public key upload",
        "CVE-2012-2694 - Rails mass assignment vulnerability in protected attributes",
        "CVE-2012-2661 - Rails SQL injection via nested mass assignment"
      ],
      
      compliance_standards: [
        "OWASP Top 10 2021 - A01: Broken Access Control",
        "CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes",
        "PCI DSS 6.5.8 - Improper access control",
        "NIST SP 800-53 - AC-3 Access Enforcement"
      ],
      
      remediation_steps: """
      1. **Immediate Fix for Rails 2.x/3.x**:
         ```ruby
         # Remove dangerous fields from attr_accessible
         attr_accessible :name, :email, :bio
         
         # Explicitly protect sensitive fields
         attr_protected :admin, :role, :permissions
         
         # Or use role-based accessible attributes
         attr_accessible :name, :email
         attr_accessible :name, :email, :admin, as: :admin
         ```
      
      2. **Upgrade to Rails 4+ (Recommended)**:
         ```ruby
         # Use Strong Parameters instead
         def user_params
           params.require(:user).permit(:name, :email, :bio)
         end
         ```
      
      3. **Audit Existing Models**:
         - Search for models without attr_accessible
         - Review all attr_accessible declarations
         - Remove sensitive fields from white lists
      
      4. **Add Protection Gradually**:
         ```ruby
         # Start with attr_protected for critical fields
         attr_protected :id, :admin, :created_at, :updated_at
         
         # Then implement proper attr_accessible
         attr_accessible :name, :email, :profile_attributes
         ```
      """,
      
      prevention_tips: """
      - Upgrade to Rails 4+ and use strong parameters
      - Never include role/permission fields in attr_accessible
      - Use attr_protected as defense in depth
      - Regular security audits of model attributes
      - Enable config.active_record.whitelist_attributes = true
      - Use role-based attr_accessible when needed
      - Document which attributes should be mass-assignable
      """,
      
      detection_methods: """
      - Static analysis with Brakeman scanner
      - grep for models without attr_accessible
      - Review all attr_accessible declarations
      - Automated testing of mass assignment protection
      - Security code reviews focusing on models
      """,
      
      safe_alternatives: """
      # Rails 2.x/3.x - Proper attr_accessible usage
      class User < ActiveRecord::Base
        # Whitelist only safe attributes
        attr_accessible :name, :email, :bio, :avatar
        
        # Different accessible attributes for admins
        attr_accessible :name, :email, :bio, :avatar, :featured, as: :admin
        
        # Explicitly protect dangerous fields
        attr_protected :admin, :role, :confirmed_at
      end
      
      # Rails 4+ - Strong Parameters (Recommended)
      class UsersController < ApplicationController
        def user_params
          if current_user.admin?
            params.require(:user).permit(:name, :email, :admin, :role)
          else
            params.require(:user).permit(:name, :email, :bio)
          end
        end
      end
      
      # Form objects for complex scenarios
      class UserRegistrationForm
        include ActiveModel::Model
        
        attr_accessor :name, :email, :terms_accepted
        
        validates :terms_accepted, acceptance: true
        
        def save
          User.create!(name: name, email: email)
        end
      end
      """
    }
  end
  
  @impl true
  def ast_enhancement do
    %{
      min_confidence: 0.8,
      
      context_rules: %{
        # Rails version affects attr_accessible availability
        rails_version_checks: %{
          "< 2.0" => "attr_accessible not available",
          "2.0-3.2" => "attr_accessible is primary mass assignment protection",
          ">= 4.0" => "Should use Strong Parameters instead"
        },
        
        # Look for model indicators
        model_indicators: [
          "< ActiveRecord::Base",
          "< ApplicationRecord",
          "include ActiveModel",
          "app/models/"
        ],
        
        # Dangerous attribute names
        dangerous_attributes: [
          "admin", "role", "is_admin", "administrator",
          "permissions", "user_role", "privilege",
          "password_digest", "encrypted_password",
          "api_key", "authentication_token", "session_token"
        ]
      },
      
      confidence_rules: %{
        adjustments: %{
          # High confidence for dangerous fields
          has_dangerous_fields: +0.4,
          # Lower confidence if attr_protected exists
          has_attr_protected: -0.2,
          # High confidence for missing protection
          missing_any_protection: +0.5,
          # Lower confidence in Rails 4+
          rails_4_or_higher: -0.3,
          # Higher confidence in model files
          in_model_file: +0.2,
          # Very high for as: :admin usage
          uses_admin_context: +0.4,
          # Lower if commented out
          is_commented: -0.8
        }
      },
      
      ast_rules: %{
        # Analyze attribute lists
        attribute_analysis: %{
          check_field_names: true,
          dangerous_field_patterns: [
            ~r/admin|role|permission/i,
            ~r/password|token|key/i,
            ~r/privilege|access/i
          ],
          safe_field_patterns: [
            ~r/name|email|bio|description/i,
            ~r/title|content|body/i
          ]
        },
        
        # Model structure analysis
        model_analysis: %{
          check_protection_presence: true,
          check_model_hierarchy: true,
          check_validation_presence: true
        },
        
        # Rails-specific analysis
        rails_analysis: %{
          check_rails_version: true,
          check_gemfile_for_protected_attributes: true,
          prefer_strong_parameters: true
        }
      }
    }
  end
  
  @impl true
  def applies_to_file?(file_path, frameworks \\ nil) do
    # Apply to Ruby model files in Rails projects
    is_ruby_file = String.ends_with?(file_path, ".rb")
    
    # Check if it's a model file
    is_model = String.contains?(file_path, "model") ||
               String.contains?(file_path, "app/models/")
    
    # Rails framework check
    frameworks_list = frameworks || []
    is_rails = "rails" in frameworks_list
    
    # If no frameworks specified but it's in app/models, assume Rails
    inferred_rails = frameworks_list == [] && String.contains?(file_path, "app/models/")
    
    is_ruby_file && (is_model && (is_rails || inferred_rails))
  end
end