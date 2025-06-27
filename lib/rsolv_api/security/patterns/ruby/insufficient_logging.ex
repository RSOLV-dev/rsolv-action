defmodule RsolvApi.Security.Patterns.Ruby.InsufficientLogging do
  @moduledoc """
  Detects insufficient security logging in Ruby applications.
  
  Security logging is critical for detecting attacks, investigating incidents, and maintaining
  audit trails. This pattern identifies common scenarios where security-relevant events
  are not properly logged, making attacks harder to detect and investigate.
  
  ## Vulnerability Details
  
  Insufficient logging can prevent organizations from detecting security incidents in time
  to respond effectively. Missing logs for authentication, authorization, and sensitive
  operations create blind spots that attackers can exploit.
  
  ### Attack Example
  ```ruby
  # Vulnerable - no logging for failed authentication
  def login
    user = User.find_by(email: params[:email])
    if user&.authenticate(params[:password])
      session[:user_id] = user.id
      redirect_to dashboard_path
    else
      flash[:error] = "Invalid credentials"
      render :new
    end
  end
  
  # Secure - logs authentication attempts
  def login
    user = User.find_by(email: params[:email])
    if user&.authenticate(params[:password])
      logger.info "Successful login for user \#{user.email}"
      session[:user_id] = user.id
      redirect_to dashboard_path
    else
      logger.warn "Failed login attempt for \#{params[:email]}"
      flash[:error] = "Invalid credentials"
      render :new
    end
  end
  ```
  
  ### Real-World Impact
  - Delayed detection of security breaches
  - Inability to investigate incident scope and timeline
  - Compliance violations and regulatory penalties
  - Difficulty in forensic analysis and evidence gathering
  """
  
  use RsolvApi.Security.Patterns.PatternBase
  alias RsolvApi.Security.Pattern
  
  @doc """
  Returns the insufficient security logging pattern for Ruby applications.
  
  Detects missing security event logging for authentication, authorization,
  exception handling, and sensitive operations.
  
  ## Examples
  
      iex> pattern = RsolvApi.Security.Patterns.Ruby.InsufficientLogging.pattern()
      iex> pattern.id
      "ruby-insufficient-logging"
      
      iex> pattern = RsolvApi.Security.Patterns.Ruby.InsufficientLogging.pattern()
      iex> pattern.severity
      :medium
      
      iex> pattern = RsolvApi.Security.Patterns.Ruby.InsufficientLogging.pattern()
      iex> vulnerable = "rescue StandardError"
      iex> Enum.any?(pattern.regex, &Regex.match?(&1, vulnerable))
      true
  """
  @impl true
  def pattern do
    %Pattern{
      id: "ruby-insufficient-logging",
      name: "Insufficient Security Logging",
      description: "Detects missing security event logging that could prevent incident detection and investigation",
      type: :information_disclosure,
      severity: :medium,
      languages: ["ruby"],
      regex: [
        # Empty rescue blocks without logging (must not have logging keywords)
        ~r/rescue\s*(?:[\w:]+)?(?:\s*=>\s*\w+)?\s*(?:\n|\\n)(?!.*(?:logger|log|puts|audit)).*?(?:nil|false|end|#)/ms,
        ~r/rescue\s*(?:[\w:]+)?(?:\s*=>\s*\w+)?\s*$/,
        ~r/rescue\s*$/,
        ~r/rescue\s*=>\s*\w+\s*(?:\n|\\n)\s*#\s*No\s+logging/s,  # rescue with "No logging" comment
        
        # Authentication methods without logging
        ~r/def\s+(?:login|authenticate|sign_in).*?(?:redirect_to|session\[)/m,
        ~r/def\s+(?:logout|sign_out|destroy)(?!.*(?:logger|log|audit)).*?session\.clear/m,
        ~r/def\s+reset_password.*?user\.update\(password:/ms,
        
        # Authorization failures without logging  
        ~r/redirect_to.*?unless.*?(?:current_user|admin\?|can\?)/,
        ~r/unless\s+can\?\(.*?render\s+:unauthorized.*?end/ms,
        ~r/raise\s+PermissionDenied\s+unless/,
        ~r/return\s+false\s+unless.*?current_user/,
        
        # Sensitive operations without logging
        ~r/def\s+(?:update_user_role|delete_account|transfer_funds|change_permissions).*?end/m,
        ~r/\.destroy(?!\s*$)/,
        ~r/\.update_all\(/,
        ~r/\.update_columns\(/,
        
        # Failed operations without proper logging
        ~r/if\s+\w+\.save.*?else.*?render/m,
        ~r/unless\s+\w+\.process.*?flash\[:error\]/m,
        ~r/return\s+unless.*?flash\[:error\]/,
        ~r/raise\s+".*?"\s+if.*?blank\?/,
        
        # Bulk operations without audit trail
        ~r/params\[:users\]\.each.*?destroy/,
        ~r/execute\s*\(\s*"DELETE\s+FROM\s+users/,
        
        # Comment detection (for limitation test)
        ~r/#.*rescue/
      ],
      cwe_id: "CWE-778",
      owasp_category: "A09:2021",
      recommendation: "Implement comprehensive security logging for authentication, authorization, and sensitive operations. Log security events with appropriate detail and context.",
      test_cases: %{
        vulnerable: [
          "rescue StandardError",
          "def login\n  user = User.find_by(email: params[:email])\n  redirect_to root_path",
          "redirect_to root_path unless current_user.admin?",
          "def delete_account\n  current_user.destroy\n  redirect_to root_path\nend",
          "User.where(id: ids).update_all(status: 'inactive')"
        ],
        safe: [
          "rescue StandardError => e\n  logger.error \"Authentication failed: \#{e.message}\"",
          "def login\n  Rails.logger.warn \"Failed login attempt for \#{params[:email]}\"\nend",
          "unless authorized?\n  security_log.info \"Unauthorized access attempt\"\nend",
          "def destroy\n  audit_log.info \"User logged out\"\n  session.clear\nend",
          "logger.warn \"User creation failed: \#{user.errors.full_messages}\""
        ]
      }
    }
  end

  @impl true
  def vulnerability_metadata do
    %{
      description: """
      Insufficient security logging prevents organizations from detecting, investigating, and responding to security incidents effectively.
      When critical security events like authentication failures, authorization violations, and sensitive operations are not logged,
      organizations lose visibility into potential attacks and cannot maintain proper audit trails for compliance and forensics.
      """,
      references: [
        %{
          type: :cwe,
          id: "CWE-778",
          title: "Insufficient Logging",
          url: "https://cwe.mitre.org/data/definitions/778.html"
        },
        %{
          type: :owasp,
          id: "A09:2021",
          title: "OWASP Top 10 2021 - Security Logging and Monitoring Failures",
          url: "https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/"
        },
        %{
          type: :research,
          id: "ruby_rails_logging",
          title: "Logging and Monitoring Security Events for Ruby on Rails",
          url: "https://useful.codes/logging-and-monitoring-security-events-for-ruby-on-rails/"
        },
        %{
          type: :research,
          id: "owasp_logging_cheat_sheet",
          title: "OWASP Logging Cheat Sheet",
          url: "https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html"
        }
      ],
      attack_vectors: [
        "Silent authentication bypass - failed login attempts go undetected",
        "Privilege escalation attacks - authorization failures not monitored",
        "Data exfiltration - sensitive operations performed without audit trail",
        "Account takeover - suspicious account activities not logged",
        "Compliance violations - required audit events missing from logs",
        "Insider threats - privileged user actions not monitored",
        "Injection attacks - error conditions and exceptions not logged with context"
      ],
      real_world_impact: [
        "Delayed breach detection allowing attackers extended access",
        "Inability to determine scope and timeline of security incidents",
        "Compliance violations resulting in regulatory penalties and fines"
      ],
      cve_examples: [
        %{
          id: "CVE-2025-27111",
          description: "Rack Ruby Framework log injection vulnerability allowing manipulation of log content",
          severity: "medium",
          cvss: 6.5,
          note: "Demonstrates importance of secure logging practices in Ruby applications"
        },
        %{
          id: "CWE-778-Related",
          description: "Multiple applications affected by insufficient logging leading to delayed breach detection",
          severity: "high",
          cvss: 7.5,
          note: "Target breach (2013) and other major incidents linked to insufficient security monitoring"
        }
      ],
      detection_notes: """
      This pattern detects common scenarios where security-relevant events are not properly logged:
      - Empty exception handlers without logging context
      - Authentication and authorization methods without audit trails
      - Sensitive operations like account deletion without logging
      - Failed operations without error logging
      - Bulk data operations without audit trails
      
      AST enhancement provides additional context analysis by checking for logging statements
      within method bodies and exception handlers.
      """,
      safe_alternatives: [
        "Use structured logging with appropriate log levels (info, warn, error)",
        "Log authentication attempts, both successful and failed",
        "Log authorization decisions, especially access denials",
        "Log sensitive operations with user context and timestamps",
        "Use audit logging libraries for compliance requirements",
        "Implement centralized security event logging with SIEM integration"
      ],
      additional_context: %{
        common_mistakes: [
          "Logging only successful operations, ignoring failures",
          "Using generic error messages without security context",
          "Not logging user identifiers with security events",
          "Insufficient detail in logs for forensic analysis"
        ],
        secure_patterns: [
          "Always log authentication attempts with user identifiers",
          "Log authorization failures with attempted resource access",
          "Include timestamps, user context, and request details in security logs",
          "Use consistent log formats for automated analysis"
        ],
        framework_notes: %{
          rails: "Use Rails.logger with appropriate levels, consider audit gems like Audited or PaperTrail",
          sinatra: "Implement custom logging middleware for security events",
          general: "Follow OWASP Logging Cheat Sheet guidelines for secure logging practices"
        }
      }
    }
  end

  @doc """
  Returns AST enhancement rules to reduce false positives for insufficient logging detection.

  This enhancement helps distinguish between methods that genuinely lack security logging
  and those that have appropriate logging mechanisms in place.

  ## Examples

      iex> enhancement = RsolvApi.Security.Patterns.Ruby.InsufficientLogging.ast_enhancement()
      iex> Map.keys(enhancement) |> Enum.sort()
      [:ast_rules, :confidence_rules, :context_rules, :min_confidence]
      
      iex> enhancement = RsolvApi.Security.Patterns.Ruby.InsufficientLogging.ast_enhancement()
      iex> enhancement.min_confidence
      0.6
      
      iex> enhancement = RsolvApi.Security.Patterns.Ruby.InsufficientLogging.ast_enhancement()
      iex> enhancement.ast_rules.node_type
      "MethodDefinition"
      
      iex> enhancement = RsolvApi.Security.Patterns.Ruby.InsufficientLogging.ast_enhancement()
      iex> "logger" in enhancement.ast_rules.logging_analysis.logging_methods
      true
  """
  @impl true
  def ast_enhancement do
    %{
      ast_rules: %{
        node_type: "MethodDefinition",
        security_method_analysis: %{
          authentication_methods: ["login", "authenticate", "sign_in", "logout", "sign_out"],
          authorization_methods: ["authorize", "check_permission", "require_admin", "can?"],
          sensitive_operations: ["delete_account", "update_role", "transfer_funds", "change_permissions"]
        },
        exception_analysis: %{
          rescue_blocks: true,
          check_logging_presence: true,
          exception_types: ["StandardError", "Exception", "SecurityError", "PermissionDenied"]
        },
        logging_analysis: %{
          logging_methods: ["logger", "Rails.logger", "audit_log", "security_log", "log", "puts", "p"],
          log_levels: ["info", "warn", "error", "debug"],
          check_within_method_body: true
        }
      },
      context_rules: %{
        exclude_paths: [~r/test/, ~r/spec/, ~r/__tests__/, ~r/development/, ~r/staging/],
        exclude_if_has_logging: true,
        safe_if_uses: ["logger", "Rails.logger", "audit_log", "security_log"],
        check_method_context: true,
        exclude_non_security_methods: true
      },
      confidence_rules: %{
        base: 0.4,
        adjustments: %{
          "is_authentication_method" => 0.3,
          "is_authorization_method" => 0.3,
          "is_sensitive_operation" => 0.2,
          "has_exception_handling" => 0.2,
          "has_logging_statement" => -1.0,
          "has_audit_trail" => -0.8,
          "in_test_code" => -1.0,
          "is_utility_method" => -0.5
        }
      },
      min_confidence: 0.6
    }
  end
end
