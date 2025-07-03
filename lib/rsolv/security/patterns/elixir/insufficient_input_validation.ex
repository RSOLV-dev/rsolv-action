defmodule Rsolv.Security.Patterns.Elixir.InsufficientInputValidation do
  @moduledoc """
  Insufficient Input Validation vulnerability pattern for Elixir/Phoenix applications.

  This pattern detects Ecto changeset operations that cast sensitive fields 
  without proper validation, potentially allowing privilege escalation and 
  unauthorized access to restricted functionality.

  ## Vulnerability Details

  Insufficient input validation occurs when applications accept user input for
  sensitive fields without proper validation and authorization checks:
  - Direct casting of role/admin/permission fields allows privilege escalation  
  - Missing validation enables users to modify their own authorization levels
  - Uncontrolled field access bypasses intended security boundaries
  - Sensitive status/approval fields can be manipulated by unauthorized users

  ## Technical Impact

  Security risks through:
  - Privilege escalation allowing users to grant themselves administrative access
  - Authorization bypass enabling access to restricted functionality and data
  - Data integrity compromise through manipulation of critical business fields
  - Account takeover via role manipulation and permission escalation

  ## Examples

  Vulnerable patterns:
  ```elixir
  # VULNERABLE - Direct casting of role field without validation
  cast(user, params, [:email, :password, :role])
  
  # VULNERABLE - Admin field accessible to user input
  cast(account, user_params, [:name, :admin, :email])
  
  # VULNERABLE - Permission fields exposed in changeset
  cast(changeset, attrs, [:permissions, :verified, :status])
  
  # VULNERABLE - Financial approval fields unprotected
  cast(payment, params, [:amount, :approved, :status])
  ```

  Safe alternatives:
  ```elixir
  # SAFE - Role assignment through separate authorized function
  user
  |> cast(params, [:email, :name])
  |> validate_required([:email, :name])
  |> assign_role_if_authorized(current_user, params["role"])
  
  # SAFE - Whitelist validation for sensitive fields
  user
  |> cast(params, [:email, :name])
  |> validate_inclusion(:role, ["user", "moderator"])
  |> validate_admin_permissions()
  
  # SAFE - Separate changesets for different privilege levels
  case current_user.role do
    "admin" -> admin_changeset(user, params)
    _ -> user_changeset(user, Map.drop(params, ["role", "admin"]))
  end
  ```

  ## Attack Scenarios

  1. **Privilege Escalation**: Attacker modifies role parameter to "admin" when 
     updating their profile, gaining administrative access to the system

  2. **Financial Fraud**: User manipulates approval/status fields in payment 
     forms to bypass approval workflows and authorize transactions

  3. **Account Verification Bypass**: Attacker sets verified/active status 
     directly to bypass email verification and account approval processes

  ## References

  - CWE-20: Improper Input Validation
  - OWASP Top 10 2021 - A03: Injection  
  - Ecto Changeset Security Best Practices
  - Phoenix Authorization Patterns
  """

  use Rsolv.Security.Patterns.PatternBase

  @impl true
  def pattern do
    %Rsolv.Security.Pattern{
      id: "elixir-insufficient-input-validation",
      name: "Insufficient Input Validation",
      description: "Ecto changeset casting sensitive fields without proper validation enables privilege escalation",
      type: :input_validation,
      severity: :medium,
      languages: ["elixir"],
      frameworks: ["phoenix", "ecto"],
      regex: [
        # cast with role, admin, or permission fields - exclude comments
        ~r/^(?!\s*#).*cast\s*\(\s*[^,]+\s*,\s*[^,]+\s*,\s*\[[^\]]*(?::role|:admin|:permissions|:superuser|:is_admin|:moderator)/m,
        
        # cast with status, approval, or verification fields - exclude comments  
        ~r/^(?!\s*#).*cast\s*\(\s*[^,]+\s*,\s*[^,]+\s*,\s*\[[^\]]*(?::status|:approved|:confirmed|:verified|:active|:suspended)/m,
        
        # cast with balance, amount, or financial fields - exclude comments
        ~r/^(?!\s*#).*cast\s*\(\s*[^,]+\s*,\s*[^,]+\s*,\s*\[[^\]]*(?::balance|:amount|:price|:cost|:fee)/m,
        
        # Ecto.Changeset.cast with sensitive fields - exclude comments
        ~r/^(?!\s*#).*Ecto\.Changeset\.cast\s*\(\s*[^,]+\s*,\s*[^,]+\s*,\s*\[[^\]]*(?::role|:admin|:permissions|:status|:approved)/m,
        
        # Pipeline syntax with cast and sensitive fields - exclude comments
        ~r/^(?!\s*#).*\|>\s*cast\s*\(\s*[^,]+\s*,\s*\[[^\]]*(?::role|:admin|:permissions|:status|:approved|:verified|:superuser)/m,
        
        # Multi-line Ecto.Changeset.cast patterns - exclude comments
        ~r/^(?!\s*#).*Ecto\.Changeset\.cast\s*\([^)]*\[[^\]]*(?::permissions|:role|:admin)/ms
      ],
      cwe_id: "CWE-20",
      owasp_category: "A03:2021",
      recommendation: "Validate sensitive fields through separate authorization checks and use field whitelisting",
      test_cases: %{
        vulnerable: [
          ~S|cast(user, params, [:email, :password, :role])|,
          ~S|cast(account, user_params, [:name, :admin, :email])|,
          ~S|cast(payment, params, [:amount, :approved, :status])|,
          "user |> cast(params, [:email, :role])"
        ],
        safe: [
          ~S|cast(user, params, [:email, :name, :bio])|,
          ~S"""
          user
          |> cast(params, [:email, :name])
          |> validate_required([:email, :name])
          |> validate_inclusion(:role, ["user", "admin"])
          """,
          ~S|put_change(changeset, :role, "user")|,
          ~S|assign_role_if_authorized(changeset, current_user, role)|
        ]
      }
    }
  end

  @impl true
  def vulnerability_metadata do
    %{
      attack_vectors: """
      1. Privilege escalation by submitting role/admin fields in user update requests without proper validation to gain unauthorized access
      2. Authorization bypass through manipulation of permission and verification status fields lacking input validation  
      3. Financial fraud via direct modification of approval, balance, and transaction status fields with insufficient validation
      4. Account verification bypass by setting verified/active status without proper input validation and authorization
      5. Workflow bypass attacks targeting approval and confirmation fields in business processes due to missing validation
      """,
      business_impact: """
      Medium: Insufficient input validation can result in:
      - Financial losses through unauthorized transaction approvals and payment manipulation
      - Data breaches via privilege escalation enabling access to sensitive customer information
      - Compliance violations related to access control and authorization requirements
      - Operational disruption through unauthorized changes to critical business workflows
      - Reputation damage from security incidents involving customer account compromises
      """,
      technical_impact: """
      Medium: Input validation vulnerabilities enable:
      - privilege escalation allowing users to gain administrative access and elevated permissions
      - Authorization bypass circumventing intended access controls and security boundaries
      - Data integrity compromise through unauthorized modification of critical business fields
      - Workflow disruption via manipulation of approval, status, and verification mechanisms
      - Account takeover through role manipulation and permission escalation attacks
      """,
      likelihood: "High: Common oversight in rapid development cycles where security validation is not properly implemented",
      cve_examples: [
        "CWE-20: Improper Input Validation",
        "CWE-863: Incorrect Authorization", 
        "CVE-2021-44228: Log4Shell privilege escalation via input validation bypass",
        "OWASP Top 10 A03:2021 - Injection and Input Validation"
      ],
      compliance_standards: [
        "OWASP Top 10 2021 - A03: Injection",
        "NIST Cybersecurity Framework - PR.AC: Access Control", 
        "ISO 27001 - A.9.2: User access management",
        "PCI DSS - Requirement 7: Restrict access by business need to know"
      ],
      remediation_steps: """
      1. Implement separate changesets for different user privilege levels and contexts
      2. Use field whitelisting to explicitly control which fields can be modified
      3. Add authorization checks before allowing modification of sensitive fields
      4. Validate sensitive field values against predefined allowlists and business rules
      5. Implement role-based field access controls in changeset functions
      6. Use Ecto's validate_inclusion/3 for strict validation of enumerated fields
      """,
      prevention_tips: """
      1. Never allow direct user input to modify role, admin, or permission fields
      2. Use separate authorized functions for privilege-related field modifications
      3. Implement strict whitelist validation for all sensitive enumerated fields
      4. Create context-specific changesets that only expose appropriate fields
      5. Use Ecto changeset validations to enforce business rules and constraints
      6. Implement proper authorization checks before applying changeset modifications
      """,
      detection_methods: """
      1. Static code analysis scanning for cast/3 calls with sensitive field arrays
      2. Code reviews focusing on changeset implementations and field exposure
      3. Dynamic testing with privilege escalation payloads in form submissions
      4. Security scanning tools like Sobelow checking for authorization bypasses
      5. Penetration testing with role manipulation and field tampering attempts
      """,
      safe_alternatives: """
      1. Authorized field modification: assign_role_if_authorized(changeset, current_user, role)
      2. Field whitelisting with validation: validate_inclusion(:role, ["user", "moderator"])
      3. Context-specific changesets: admin_changeset vs user_changeset functions
      4. Explicit field control: Map.drop(params, ["role", "admin", "permissions"])
      5. Business rule validation: validate_business_rules(changeset, current_user)
      6. Separate authorization layer: authorize_field_access(field, current_user)
      """
    }
  end

  @impl true  
  def ast_enhancement do
    %{
      min_confidence: 0.7,
      context_rules: %{
        sensitive_fields: [
          "role", "admin", "permissions", "superuser", "is_admin", "moderator",
          "status", "approved", "confirmed", "verified", "active", "suspended",
          "balance", "amount", "price", "cost", "fee", "payment_status"
        ],
        validation_functions: [
          "validate_required",
          "validate_inclusion", 
          "validate_format",
          "validate_length",
          "validate_number",
          "validate_change"
        ],
        authorization_functions: [
          "authorize",
          "can?",
          "permitted?",
          "validate_permissions",
          "check_role",
          "admin_only"
        ],
        safe_assignment_functions: [
          "put_change",
          "assign_role",
          "set_default_role",
          "authorize_field_change"
        ]
      },
      confidence_rules: %{
        base: 0.7,
        adjustments: %{
          sensitive_field_bonus: 0.3,
          multiple_sensitive_fields_bonus: 0.2,
          validation_present_penalty: -0.8,
          authorization_check_penalty: -0.9,
          safe_assignment_penalty: -0.6,
          whitelist_validation_penalty: -0.7
        }
      },
      ast_rules: %{
        node_type: "input_validation_analysis",
        changeset_analysis: %{
          check_cast_calls: true,
          cast_functions: ["cast", "Ecto.Changeset.cast"],
          check_field_lists: true,
          detect_sensitive_fields: true
        },
        validation_analysis: %{
          check_validation_chain: true,
          validation_functions: ["validate_required", "validate_inclusion", "validate_format"],
          check_business_rules: true,
          detect_authorization_checks: true
        },
        context_analysis: %{
          check_changeset_context: true,
          distinguish_admin_vs_user: true,
          check_field_whitelisting: true,
          context_radius: 5
        }
      }
    }
  end
end
