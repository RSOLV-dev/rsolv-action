defmodule Rsolv.Security.Patterns.Ruby.MassAssignment do
  @moduledoc """
  Pattern for detecting mass assignment vulnerabilities in Ruby on Rails applications.
  
  This pattern identifies when Active Record models are created or updated using
  unfiltered parameters from user input (typically params hash). Without strong
  parameters protection, attackers can modify any attribute of the model, including
  sensitive fields like admin flags, user roles, or foreign keys.
  
  ## Vulnerability Details
  
  Mass assignment occurs when Rails applications pass user-controlled data directly
  to model creation or update methods without filtering. This allows attackers to
  set any attribute on the model, potentially bypassing application logic and
  security controls.
  
  ### Attack Example
  ```ruby
  # Vulnerable controller
  def create
    @user = User.create(params[:user])  # Dangerous!
  end
  
  # Attack: POST with malicious parameters
  params[:user] = {
    name: "attacker",
    email: "attacker@evil.com", 
    admin: true,                    # Escalate privileges
    account_id: 1                   # Access other accounts
  }
  ```
  """
  
  use Rsolv.Security.Patterns.PatternBase
  alias Rsolv.Security.Pattern
  
  @impl true
  def pattern do
    %Pattern{
      id: "ruby-mass-assignment",
      name: "Mass Assignment Vulnerability",
      description: "Detects unfiltered params in model operations",
      type: :mass_assignment,
      severity: :high,
      languages: ["ruby"],
      regex: [
        ~r/\.(create|update|update_attributes|assign_attributes)\s*\(\s*params\[/,
        ~r/\.(create!|update!)\s*\(\s*params\[/,
        ~r/\.new\s*\(\s*params\[/,
        ~r/\.(insert|upsert)\s*\(\s*params\[/
      ],
      cwe_id: "CWE-915",
      owasp_category: "A01:2021",
      recommendation: "Use strong parameters in Rails: params.require(:model).permit(:field1, :field2)",
      test_cases: %{
        vulnerable: [
          "User.create(params[:user])",
          "user.update_attributes(params[:user])"
        ],
        safe: [
          "User.create(user_params)",
          "user.update(user_params)",
          "params.require(:user).permit(:name, :email)"
        ]
      }
    }
  end
  
  @impl true
  def vulnerability_metadata do
    %{
      description: """
      Mass assignment vulnerabilities allow attackers to modify object attributes
      that should be protected from user input. In Rails applications, this typically
      occurs when passing the params hash directly to Active Record methods without
      using strong parameters for filtering.
      
      The vulnerability gained notoriety in 2012 when Egor Homakov exploited a mass
      assignment vulnerability to gain commit access to the Rails repository on GitHub.
      This incident led to significant changes in how Rails handles parameter filtering,
      resulting in the introduction of strong parameters in Rails 4.
      
      Common attack scenarios include:
      - Privilege escalation by setting admin or role attributes
      - Account takeover by modifying user_id or account_id foreign keys
      - Bypassing business logic by setting state or status fields
      - Data manipulation by changing timestamps or counters
      - Access control bypass by modifying permission-related attributes
      
      The vulnerability is particularly dangerous because:
      - It's often invisible in code reviews if reviewers aren't security-aware
      - Attackers can discover vulnerable attributes through various means
      - The impact can range from data corruption to complete system compromise
      - It affects any model attribute unless explicitly protected
      """,
      references: [
        %{
          type: :cwe,
          id: "CWE-915",
          title: "Improperly Controlled Modification of Dynamically-Determined Object Attributes",
          url: "https://cwe.mitre.org/data/definitions/915.html"
        },
        %{
          type: :owasp,
          id: "A01:2021",
          title: "OWASP Top 10 2021 - A01 Broken Access Control",
          url: "https://owasp.org/Top10/A01_2021-Broken_Access_Control/"
        },
        %{
          type: :owasp,
          id: "mass_assignment",
          title: "OWASP Mass Assignment Cheat Sheet",
          url: "https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html"
        },
        %{
          type: :research,
          id: "github_hack_2012",
          title: "How Homakov hacked GitHub and Rails security",
          url: "https://gist.github.com/peternixey/1978249"
        }
      ],
      attack_vectors: [
        "Setting admin flags: params[:user][:admin] = true",
        "Changing ownership: params[:post][:user_id] = victim_id",
        "Bypassing payment: params[:order][:paid] = true",
        "Modifying timestamps: params[:subscription][:expires_at] = '2099-12-31'",
        "Escalating permissions: params[:member][:role] = 'owner'",
        "Account linking: params[:profile][:account_id] = target_account",
        "Status manipulation: params[:application][:status] = 'approved'",
        "Balance modification: params[:wallet][:balance] = 999999"
      ],
      real_world_impact: [
        "GitHub 2012: Repository access compromise via public key injection",
        "Privilege escalation allowing regular users to become administrators",
        "Financial fraud through order status or payment flag manipulation",
        "Data breaches by accessing other users' accounts via foreign key modification",
        "Business logic bypass leading to unauthorized resource access",
        "Reputation damage from security incidents and data breaches",
        "Compliance violations when protected data is exposed"
      ],
      cve_examples: [
        %{
          id: "CVE-2020-8164",
          description: "Strong Parameters bypass in Rails ActionPack",
          severity: "high",
          cvss: 7.5,
          note: "Allows bypassing strong parameters protection via crafted requests"
        },
        %{
          id: "CVE-2014-3514",
          description: "Rails Active Record create_with bypass",
          severity: "high",
          cvss: 7.5,
          note: "create_with method completely bypassed strong parameters"
        },
        %{
          id: "CVE-2013-1854",
          description: "Rails Active Record symbol DoS via mass assignment",
          severity: "medium",
          cvss: 5.0,
          note: "Converting hash keys to symbols caused memory exhaustion"
        },
        %{
          id: "GitHub-2012",
          description: "GitHub mass assignment hack by Egor Homakov",
          severity: "critical",
          cvss: 9.0,
          note: "Allowed adding public keys to any repository"
        }
      ],
      detection_notes: """
      This pattern detects mass assignment by looking for:
      - Direct use of params hash in Active Record methods
      - Methods like create, update, new with params[] as argument
      - Both bang (!) and non-bang versions of methods
      - Modern methods like insert and upsert
      
      The pattern uses multiple regex expressions to catch various forms
      of mass assignment across different Rails versions and coding styles.
      
      Note: This pattern may have false positives if params[] is used
      in a safe context (e.g., params[:id] for finding records).
      """,
      safe_alternatives: [
        "Use strong parameters: params.require(:user).permit(:name, :email)",
        "Create private methods for parameter filtering (user_params)",
        "Explicitly set each attribute: User.new(name: params[:name])",
        "Use form objects or service objects for complex updates",
        "Implement attribute-level protection with attr_accessible (Rails 3)",
        "Regular security audits with tools like Brakeman",
        "Code review focusing on parameter handling",
        "Automated tests verifying parameter filtering"
      ],
      additional_context: %{
        common_mistakes: [
          "Assuming hidden form fields are secure",
          "Trusting client-side validation",
          "Using params.permit! (permits everything)",
          "Forgetting to update permitted parameters when adding fields",
          "Not protecting API endpoints with strong parameters"
        ],
        secure_patterns: [
          "def user_params\n  params.require(:user).permit(:name, :email)\nend",
          "User.create(user_params)",
          "current_user.posts.create(post_params)",
          "params.fetch(:user, {}).permit(:name)",
          "ActionController::Parameters.new(user: {...}).require(:user).permit(...)"
        ],
        rails_evolution: [
          "Rails 3: attr_accessible and attr_protected in models",
          "Rails 4+: Strong Parameters in controllers (default)",
          "params.permit replaces attr_accessible",
          "Protection is now mandatory, not optional",
          "create_with vulnerability fixed in Rails 4.0.9 and 4.1.5"
        ]
      }
    }
  end
  
  @doc """
  Returns AST enhancement rules to reduce false positives.
  
  This enhancement helps distinguish between actual vulnerabilities and
  safe parameter usage patterns like permitted parameters or safe contexts.
  
  ## Examples
  
      iex> enhancement = Rsolv.Security.Patterns.Ruby.MassAssignment.ast_enhancement()
      iex> Map.keys(enhancement) |> Enum.sort()
      [:ast_rules, :confidence_rules, :context_rules, :min_confidence]
      
      iex> enhancement = Rsolv.Security.Patterns.Ruby.MassAssignment.ast_enhancement()
      iex> enhancement.min_confidence
      0.75
  """
  @impl true
  def ast_enhancement do
    %{
      ast_rules: %{
        node_type: "MethodCall",
        receiver_patterns: ["ActiveRecord", "Model", "ApplicationRecord"],
        method_names: ["create", "update", "update_attributes", "assign_attributes", "new", "create!", "update!", "insert", "upsert"],
        argument_analysis: %{
          check_params_usage: true,
          detect_params_hash: true,
          look_for_permit: false
        }
      },
      context_rules: %{
        exclude_paths: [
          ~r/test/,
          ~r/spec/,
          ~r/features/,
          ~r/db\/migrate/
        ],
        check_strong_params: true,
        safe_methods: [
          "permit",
          "require", 
          "fetch",
          "slice",
          "except"
        ],
        safe_param_names: [
          "permitted_params",
          "safe_params",
          "_params",
          "filtered_params",
          "sanitized_params"
        ]
      },
      confidence_rules: %{
        base: 0.6,
        adjustments: %{
          "direct_params_hash" => 0.4,
          "in_controller" => 0.2,
          "no_permit_nearby" => 0.3,
          "in_api_controller" => 0.2,
          "uses_strong_params" => -0.8,
          "safe_param_method" => -0.7,
          "in_test_code" => -1.0
        }
      },
      min_confidence: 0.75
    }
  end
end
