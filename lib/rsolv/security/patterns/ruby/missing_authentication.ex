defmodule Rsolv.Security.Patterns.Ruby.MissingAuthentication do
  @moduledoc """
  Pattern for detecting missing authentication in Rails controllers.

  This pattern identifies Rails controllers that lack authentication filters like
  `before_action :authenticate_user!` or `before_filter :authenticate_admin`. These
  missing authentication checks can lead to unauthorized access to sensitive data
  and functionality.

  ## Vulnerability Details

  Authentication is a fundamental security control that verifies user identity before
  granting access to resources. In Rails applications, authentication is typically
  implemented using before_action filters (formerly before_filter in older versions).
  When controllers lack these filters, any user can access the actions, potentially
  exposing sensitive data or administrative functions.

  ### Attack Example
  ```ruby
  # Vulnerable controller
  class AdminController < ApplicationController
    def users
      @users = User.all  # Anyone can access this!
    end
    
    def delete_user
      User.find(params[:id]).destroy  # No auth check!
    end
  end

  # Attack: Direct access to admin endpoints
  GET /admin/users     # Lists all users
  DELETE /admin/users/1 # Deletes user without authentication
  ```
  """

  use Rsolv.Security.Patterns.PatternBase
  alias Rsolv.Security.Pattern

  @impl true
  def pattern do
    %Pattern{
      id: "ruby-broken-access-control-missing-auth",
      name: "Missing Authentication in Rails Controller",
      description: "Detects Rails controllers without authentication filters",
      type: :authentication,
      severity: :high,
      languages: ["ruby"],
      regex:
        ~r/class\s+\w+Controller\s*<\s*ApplicationController(?:(?!before_action|before_filter|authenticate).)*end/s,
      cwe_id: "CWE-862",
      owasp_category: "A01:2021",
      recommendation: "Add before_action :authenticate_user! to protect sensitive actions",
      test_cases: %{
        vulnerable: [
          ~S|class AdminController < ApplicationController
  def users
    @users = User.all
  end
end|
        ],
        safe: [
          ~S|class AdminController < ApplicationController
  before_action :authenticate_user!
  before_action :require_admin
  
  def users
    @users = User.all
  end
end|
        ]
      }
    }
  end

  @impl true
  def vulnerability_metadata do
    %{
      description: """
      Missing authentication is one of the most critical security vulnerabilities in web
      applications. When Rails controllers lack proper authentication filters, they allow
      unrestricted access to potentially sensitive functionality. This can lead to data
      breaches, unauthorized modifications, and complete system compromise.

      In Rails applications, authentication is typically enforced using before_action
      filters (or before_filter in older versions). These filters run before controller
      actions and can halt execution if authentication fails. Common authentication
      libraries like Devise provide helpers such as `authenticate_user!` that integrate
      seamlessly with this pattern.

      The vulnerability is particularly dangerous in:
      - Admin controllers exposing user management functions
      - API controllers returning sensitive data
      - Controllers handling financial transactions
      - Settings or configuration controllers
      - Report generation endpoints

      Even if routes are "hidden" or unpublished, attackers can discover them through
      various means including directory brute-forcing, leaked documentation, or source
      code analysis.
      """,
      references: [
        %{
          type: :cwe,
          id: "CWE-862",
          title: "Missing Authorization",
          url: "https://cwe.mitre.org/data/definitions/862.html"
        },
        %{
          type: :owasp,
          id: "A01:2021",
          title: "OWASP Top 10 2021 - A01 Broken Access Control",
          url: "https://owasp.org/Top10/A01_2021-Broken_Access_Control/"
        },
        %{
          type: :research,
          id: "rails_authentication",
          title: "Ruby on Rails Security Guide - Authentication",
          url: "https://guides.rubyonrails.org/security.html#user-management"
        },
        %{
          type: :research,
          id: "devise_security",
          title: "Devise Authentication Security Best Practices",
          url: "https://github.com/heartcombo/devise#controller-filters-and-helpers"
        }
      ],
      attack_vectors: [
        "Direct URL access: GET /admin/users without any authentication",
        "API endpoint enumeration: Testing /api/v1/users, /api/v1/admin, etc.",
        "Parameter manipulation: Accessing other users' data via ID parameters",
        "Privilege escalation: Regular users accessing admin functions",
        "Data harvesting: Bulk downloading sensitive information",
        "State manipulation: Modifying application settings or user roles",
        "Cross-tenant access: Accessing data from other organizations",
        "Timing attacks: Inferring valid endpoints from response times"
      ],
      real_world_impact: [
        "Complete database exposure through unprotected admin panels",
        "User account takeover via profile modification endpoints",
        "Financial loss through unauthorized transaction access",
        "Compliance violations (GDPR, HIPAA) from data exposure",
        "Reputational damage from security breaches",
        "Legal liability from leaked personal information",
        "Competitive disadvantage from exposed business data"
      ],
      cve_examples: [
        %{
          id: "CVE-2019-16109",
          description: "Devise authentication bypass via blank confirmation token",
          severity: "high",
          cvss: 7.5,
          note: "Allowed account confirmation without valid token"
        },
        %{
          id: "CVE-2021-22904",
          description: "Rails timing attack in token authentication",
          severity: "medium",
          cvss: 5.3,
          note: "DoS vulnerability in Action Controller authentication"
        },
        %{
          id: "CVE-2024-45409",
          description: "GitLab SAML authentication bypass",
          severity: "critical",
          cvss: 10.0,
          note: "Complete authentication bypass via SAML assertion forgery"
        },
        %{
          id: "CVE-2023-7028",
          description: "GitLab account takeover via password reset",
          severity: "critical",
          cvss: 10.0,
          note: "Zero-click account takeover through email manipulation"
        }
      ],
      detection_notes: """
      This pattern detects missing authentication by looking for:
      - Controller classes inheriting from ApplicationController
      - Absence of authentication-related before_action/before_filter declarations
      - The pattern uses negative lookahead to ensure no auth methods are present

      The regex searches for the entire controller definition and fails to match
      if it finds authentication keywords like 'before_action', 'before_filter',
      or 'authenticate' anywhere within the controller.

      Note: This pattern may have false positives for:
      - Public controllers that intentionally lack authentication
      - Controllers using alternative authentication methods
      - Partial controller definitions in code snippets
      """,
      safe_alternatives: [
        "Use before_action :authenticate_user! for Devise authentication",
        "Implement custom before_action filters for role-based access",
        "Use skip_before_action only for specific public actions",
        "Apply authentication at the route level with constraints",
        "Implement API token authentication for machine clients",
        "Use OAuth2/JWT for modern API authentication",
        "Apply defense in depth with multiple auth layers",
        "Audit all controllers for proper authentication coverage",
        "Use Rails security scanners like Brakeman regularly"
      ],
      additional_context: %{
        common_mistakes: [
          "Assuming 'hidden' URLs are secure without authentication",
          "Forgetting to add authentication to new controllers",
          "Skipping authentication for 'internal' APIs",
          "Using only client-side authentication checks",
          "Relying on security through obscurity"
        ],
        secure_patterns: [
          "ApplicationController with default authentication for all",
          "Explicit skip_before_action for public endpoints only",
          "Role-based authorization after authentication",
          "API versioning with proper auth for each version",
          "Regular security audits of all controllers"
        ],
        rails_specific_notes: [
          "before_action replaced before_filter in Rails 4+",
          "Devise's authenticate_user! is the most common pattern",
          "CanCanCan/Pundit for authorization after authentication",
          "API authentication often uses tokens instead of sessions",
          "Rails 5+ API mode requires explicit auth implementation"
        ]
      }
    }
  end

  @doc """
  Returns AST enhancement rules to reduce false positives.

  This enhancement helps distinguish between actual vulnerabilities and
  intentionally public controllers or alternative authentication methods.

  ## Examples

      iex> enhancement = Rsolv.Security.Patterns.Ruby.MissingAuthentication.ast_enhancement()
      iex> Map.keys(enhancement) |> Enum.sort()
      [:ast_rules, :confidence_rules, :context_rules, :min_confidence]
      
      iex> enhancement = Rsolv.Security.Patterns.Ruby.MissingAuthentication.ast_enhancement()
      iex> enhancement.min_confidence
      0.7
  """
  @impl true
  def ast_enhancement do
    %{
      ast_rules: %{
        node_type: "ClassDefinition",
        class_name_patterns: ["Controller$"],
        inheritance_patterns: [
          "ApplicationController",
          "ActionController::Base",
          "ActionController::API"
        ],
        method_analysis: %{
          look_for_actions: true,
          action_patterns: ["index", "show", "new", "create", "edit", "update", "destroy"],
          sensitive_patterns: ["admin", "user", "account", "setting", "config", "payment"]
        }
      },
      context_rules: %{
        exclude_paths: [
          ~r/test/,
          ~r/spec/,
          ~r/public_controller/i,
          ~r/health_check/i,
          ~r/status_controller/i
        ],
        exclude_if_contains: [
          "skip_before_action :authenticate",
          "skip_authorization",
          "allow_unauthenticated"
        ],
        safe_controller_patterns: [
          "PublicController",
          "HomeController",
          "SessionsController",
          "RegistrationsController",
          "PasswordsController",
          "HealthCheckController"
        ]
      },
      confidence_rules: %{
        base: 0.5,
        adjustments: %{
          "has_sensitive_action_names" => 0.3,
          "is_admin_controller" => 0.4,
          "is_api_controller" => 0.2,
          "has_user_data_access" => 0.3,
          "is_public_controller" => -0.8,
          "has_alternative_auth" => -0.6,
          "in_test_code" => -1.0
        }
      },
      min_confidence: 0.7
    }
  end
end
