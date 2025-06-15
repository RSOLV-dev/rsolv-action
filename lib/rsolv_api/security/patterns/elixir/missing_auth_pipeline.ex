defmodule RsolvApi.Security.Patterns.Elixir.MissingAuthPipeline do
  @moduledoc """
  Missing Authentication Pipeline vulnerability pattern for Elixir/Phoenix applications.

  This pattern detects Phoenix controllers that handle sensitive operations without 
  proper authentication pipelines or plugs, leading to broken access control vulnerabilities.

  ## Vulnerability Details

  Missing authentication occurs when:
  - Sensitive controllers (Admin, User, Account) lack authentication plugs
  - Critical operations are accessible without user verification
  - Controllers bypass authentication pipelines
  - Administrative functions are exposed to unauthenticated users
  - User management features lack proper access controls

  ## Technical Impact

  Broken access control through:
  - Unauthorized access to administrative functions
  - User data exposure and manipulation without authentication
  - Privilege escalation attacks through unprotected endpoints
  - Account takeover via unprotected user management functions
  - Data breaches through unrestricted resource access

  ## Examples

  Vulnerable patterns:
  ```elixir
  # VULNERABLE - Admin controller without authentication
  defmodule MyAppWeb.AdminController do
    use MyAppWeb, :controller
    
    def index(conn, _params) do
      # Administrative functions without auth
    end
  end
  
  # VULNERABLE - User management without protection
  defmodule AppWeb.UserController do
    use AppWeb, :controller
    
    def delete(conn, %{"id" => id}) do
      # User deletion without verification
    end
  end
  
  # VULNERABLE - Account settings accessible to anyone
  defmodule WebApp.AccountController do
    use WebApp, :controller
    
    def update_password(conn, params) do
      # Password changes without authentication
    end
  end
  ```

  Safe alternatives:
  ```elixir
  # SAFE - Proper authentication plug
  defmodule MyAppWeb.AdminController do
    use MyAppWeb, :controller
    
    plug :authenticate_admin
    
    def index(conn, _params) do
      # Protected administrative functions
    end
  end
  
  # SAFE - Pipeline-level authentication
  defmodule AppWeb.UserController do
    use AppWeb, :controller
    
    pipe_through [:browser, :require_authenticated_user]
    
    def show(conn, _params) do
      # Protected user operations
    end
  end
  
  # SAFE - Multiple authentication layers
  defmodule WebApp.AccountController do
    use WebApp, :controller
    
    plug MyApp.AuthPlug
    plug :require_owner_or_admin
    
    def edit(conn, _params) do
      # Doubly protected account operations
    end
  end
  ```

  ## Attack Scenarios

  1. **Administrative Bypass**: Attackers access admin controllers directly
     without authentication, gaining full control over the application

  2. **User Enumeration**: Unprotected user controllers reveal user data
     and allow unauthorized profile modifications

  3. **Account Takeover**: Direct access to account management functions
     enables password changes and profile hijacking

  4. **Data Manipulation**: Unprotected CRUD operations allow unauthorized
     data creation, modification, and deletion

  ## References

  - CWE-306: Missing Authentication for Critical Function
  - OWASP Top 10 2021 - A01: Broken Access Control  
  - Phoenix Security Guide: https://hexdocs.pm/phoenix/security.html
  - Phoenix Authentication: https://hexdocs.pm/phoenix/Mix.Tasks.Phx.Gen.Auth.html
  - Pow Authentication Library: https://powauth.com/
  """

  use RsolvApi.Security.Patterns.PatternBase

  @impl true
  def pattern do
    %RsolvApi.Security.Pattern{
      id: "elixir-missing-auth-pipeline",
      name: "Missing Authentication Pipeline",
      description: "Phoenix controllers handling sensitive operations without proper authentication plugs or pipelines",
      type: :authentication,
      severity: :high,
      languages: ["elixir"],
      frameworks: ["phoenix"],
      regex: [
        # Controllers with sensitive names missing authentication (with or without Web)
        ~r/defmodule\s+\w+(?:Web)?\.(?:Admin|User|Account)(?:\w+)?Controller\s+do(?:(?!plug\s+(?::(?:authenticate|require_|auth)|\w+\.\w*(?:Auth|Authenticate)\w*))(?!pipe_through\s+\[[^\]]*(?:auth|require_|authenticate)[^\]]*\]).)*?def\s+/s,
        
        # More specific sensitive controller patterns
        ~r/defmodule\s+\w+(?:Web)?\.(?:AdminController|UserController|AccountController|UserManagementController|AccountSettingsController)\s+do(?:(?!plug\s+(?::(?:authenticate|require_|auth)|\w+\.\w*(?:Auth|Authenticate)\w*))(?!pipe_through\s+\[[^\]]*(?:auth|require_|authenticate)[^\]]*\]).)*?def\s+/s,
        
        # Management and Settings controllers without authentication
        ~r/defmodule\s+\w+(?:Web)?\.\w*(?:Management|Settings)\w*Controller\s+do(?:(?!plug\s+(?::(?:authenticate|require_|auth)|\w+\.\w*(?:Auth|Authenticate)\w*))(?!pipe_through\s+\[[^\]]*(?:auth|require_|authenticate)[^\]]*\]).)*?def\s+/s,
        
        # Controllers with sensitive method names but no auth
        ~r/defmodule\s+\w+(?:Web)?\.\w+Controller\s+do(?:(?!plug\s+(?::(?:authenticate|require_|auth)|\w+\.\w*(?:Auth|Authenticate)\w*))(?!pipe_through\s+\[[^\]]*(?:auth|require_|authenticate)[^\]]*\]).)*?def\s+(?:delete|update_password|admin_|manage_)/s
      ],
      default_tier: :protected,
      cwe_id: "CWE-306",
      owasp_category: "A01:2021",
      recommendation: "Add authentication plugs like :authenticate_user or use authenticated pipelines like [:browser, :require_authenticated_user]",
      test_cases: %{
        vulnerable: [
          ~S|defmodule MyAppWeb.AdminController do
  use MyAppWeb, :controller
  def index(conn, _params) do|,
          ~S|defmodule AppWeb.UserController do
  use AppWeb, :controller

  def show(conn, %{"id" => id}) do|,
          ~S|defmodule WebApp.AccountController do
  use WebApp, :controller
  def edit(conn, _params) do|
        ],
        safe: [
          ~S|defmodule MyAppWeb.AdminController do
  use MyAppWeb, :controller
  
  plug :authenticate_admin
  
  def index(conn, _params) do|,
          ~S|defmodule AppWeb.UserController do
  use AppWeb, :controller
  plug :require_authenticated_user
  def show(conn, _params) do|,
          ~S|defmodule WebApp.AccountController do
  use WebApp, :controller
  
  pipe_through [:browser, :require_authenticated_user]
  
  def edit(conn, _params) do|
        ]
      }
    }
  end

  @impl true
  def vulnerability_metadata do
    %{
      attack_vectors: """
      1. Direct Access: Unauthorized access to administrative and user management functions
      2. Privilege Escalation: Accessing higher-privilege operations without proper authentication
      3. Account Takeover: Modifying user accounts and passwords without verification
      4. Data Manipulation: Unauthorized CRUD operations on sensitive resources
      """,
      business_impact: """
      High: Missing authentication can lead to:
      - Complete compromise of administrative functions
      - Unauthorized access to all user data and accounts
      - Regulatory compliance violations (GDPR, HIPAA, SOX)
      - Massive data breaches and privacy violations
      - Financial losses from security incidents and lawsuits
      - Total loss of customer trust and reputation damage
      """,
      technical_impact: """
      High: Broken access control can cause:
      - Complete bypassing of application security controls
      - Unauthorized access to any functionality or data
      - Account takeovers and identity theft
      - Administrative privilege escalation attacks
      - Data corruption and integrity violations
      - System compromise and lateral movement
      """,
      likelihood: "High: Very common when authentication is implemented inconsistently across controllers",
      cve_examples: [
        "CWE-306: Missing Authentication for Critical Function",
        "OWASP Top 10 A01:2021 - Broken Access Control",
        "CVE-2019-16278: Missing authentication in admin panel",
        "CVE-2020-35489: Authentication bypass in user management"
      ],
      compliance_standards: [
        "OWASP Top 10 2021 - A01: Broken Access Control",
        "NIST Cybersecurity Framework - PR.AC: Access Control", 
        "ISO 27001 - A.9.1: Access Control Management",
        "PCI DSS - Requirement 7: Restrict access by business need-to-know"
      ],
      remediation_steps: """
      1. Add authentication plugs to all sensitive controllers
      2. Use pipeline-level authentication for consistent protection
      3. Implement role-based access control for different user types
      4. Add authorization checks beyond basic authentication
      5. Audit all controller endpoints for proper access controls
      6. Use Phoenix.LiveView authentication generators for consistency
      """,
      prevention_tips: """
      1. Use Phoenix authentication generators (mix phx.gen.auth)
      2. Implement consistent authentication patterns across all controllers
      3. Use pipeline-level authentication for group protection
      4. Add authorization layers beyond basic authentication
      5. Regular security audits of all controller endpoints
      6. Follow principle of least privilege for all operations
      """,
      detection_methods: """
      1. Static code analysis for controller patterns and authentication
      2. Code review focusing on controller security and access patterns
      3. Dynamic testing with unauthenticated request attempts
      4. Security penetration testing of all controller endpoints
      5. Automated security scanning for missing authentication
      """,
      safe_alternatives: """
      1. Use authentication plugs: plug :authenticate_user, :require_admin
      2. Implement pipeline authentication: pipe_through [:browser, :auth]
      3. Add role-based authorization: plug :require_role, :admin
      4. Use Phoenix authentication libraries (Pow, Guardian, Authex)
      5. Implement custom authentication modules with proper error handling
      6. Use LiveView authentication for consistent UI protection
      """
    }
  end

  @impl true  
  def ast_enhancement do
    %{
      min_confidence: 0.8,
      context_rules: %{
        exclude_test_files: true,
        test_file_patterns: [
          ~r/_test\.exs$/,
          ~r/\/test\//,
          ~r/test_helper\.exs$/
        ],
        sensitive_controller_patterns: [
          "Admin",
          "User", 
          "Account",
          "Management",
          "Settings"
        ],
        authentication_indicators: [
          "plug :authenticate",
          "plug :require_",
          "plug :auth",
          "pipe_through.*auth",
          "pipe_through.*require_"
        ],
        safe_pipelines: [
          ":require_authenticated_user",
          ":auth", 
          ":authenticate",
          ":require_admin"
        ],
        check_controller_sensitivity: true,
        check_method_sensitivity: true
      },
      confidence_rules: %{
        base: 0.8,
        adjustments: %{
          test_context_penalty: -0.6,
          sensitive_controller_bonus: 0.2,
          administrative_bonus: 0.15,
          management_bonus: 0.1,
          public_controller_penalty: -0.4,
          pipeline_auth_penalty: -0.8
        }
      },
      ast_rules: %{
        node_type: "controller_analysis",
        controller_analysis: %{
          check_controller_definition: true,
          check_controller_name: true,
          sensitive_patterns: ["Admin", "User", "Account", "Management", "Settings"],
          controller_methods: ["def "],
          framework_patterns: ["Phoenix.Controller", "use.*:controller"]
        },
        authentication_analysis: %{
          check_authentication_plugs: true,
          check_pipeline_authentication: true,
          auth_plug_patterns: ["plug :authenticate", "plug :require_", "plug :auth"],
          pipeline_patterns: ["pipe_through.*auth", "pipe_through.*require_"],
          safe_auth_indicators: [":authenticate_user", ":require_authenticated_user", ":auth"]
        },
        method_analysis: %{
          check_sensitive_methods: true,
          check_crud_operations: true,
          sensitive_method_names: ["delete", "update_password", "admin_", "manage_", "destroy"],
          crud_methods: ["create", "update", "delete", "destroy"]
        },
        security_analysis: %{
          check_access_control: true,
          check_authorization_layers: true,
          authorization_patterns: ["plug :require_role", "plug :authorize", "plug.*permission"],
          security_frameworks: ["Guardian", "Pow", "Authex"]
        }
      }
    }
  end
end