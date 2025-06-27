defmodule RsolvApi.Security.Patterns.Ruby.DebugModeEnabled do
  @moduledoc """
  Pattern for detecting debug mode enabled in Ruby applications.
  
  This pattern identifies when debugging code or debugging libraries are left 
  enabled in production Ruby applications, which can lead to information 
  disclosure, remote code execution, and security bypasses.
  
  ## Vulnerability Details
  
  Debug mode enabled vulnerabilities occur when development debugging tools,
  breakpoints, or verbose logging are left active in production environments.
  These tools can expose sensitive information, provide unauthorized access
  to application internals, or even enable remote code execution.
  
  ### Attack Example
  ```ruby
  # Vulnerable Rails application with debug code
  class UsersController < ApplicationController
    def show
      user = User.find(params[:id])
      
      # VULNERABLE: Pry breakpoint left in production
      binding.pry if Rails.env.production?
      
      # VULNERABLE: Sensitive data logged in debug mode
      Rails.logger.debug "User password hash: \#{user.password_digest}"
      Rails.logger.debug "API keys: \#{user.api_keys.pluck(:key)}"
      
      # VULNERABLE: Capybara debugging helpers
      save_and_open_page if Rails.env.development?
      
      render json: user
    end
  end
  
  # Attack scenarios:
  # 1. Attacker triggers pry breakpoint, gains REPL access to production
  # 2. Debug logs leak passwords, API keys, session tokens
  # 3. Capybara saves sensitive page content to public directories
  ```
  
  **Real-world Impact:**
  CVE-2019-5420 demonstrated how Rails development mode with debug enabled
  could lead to remote code execution through secret_key_base exposure.
  
  **Safe Alternative:**
  ```ruby
  # SECURE: No debug code in production
  class UsersController < ApplicationController 
    def show
      user = User.find(params[:id])
      
      # SECURE: Proper logging without sensitive data
      Rails.logger.info "User \#{user.id} accessed profile"
      
      render json: user.as_json(except: [:password_digest])
    end
  end
  ```
  """
  
  use RsolvApi.Security.Patterns.PatternBase
  alias RsolvApi.Security.Pattern
  
  @impl true
  def pattern do
    %Pattern{
      id: "ruby-debug-mode",
      name: "Debug Mode Enabled",
      description: "Detects debugging code that might leak information or provide unauthorized access",
      type: :information_disclosure,
      severity: :medium,
      languages: ["ruby"],
      regex: [
        ~r/require\s+['\"]pry['\"]/,           # require 'pry'
        ~r/binding\.pry/,                     # binding.pry breakpoints
        ~r/\bpry\b/,                          # pry calls
        ~r/\bbyebug\b/,                       # byebug debugger
        ~r/\bdebugger\b/,                     # debugger statements
        ~r/save_and_open_page/,               # Capybara debugging
        ~r/save_and_open_screenshot/,         # Capybara screenshot debug
        ~r/\bsave_page\b/,                    # Capybara save_page
        ~r/\bsave_screenshot\b/,              # Capybara save_screenshot
        ~r/Rails\.logger\.debug.*?(password|secret|key|token|credential)/i,  # Sensitive debug logs
        ~r/logger\.(?:debug|info|warn).*?(password|secret|key|token|credential|credit|card|cc_)/i,  # Other logger sensitive logs
        ~r/puts.*?(password|secret|key|token|credential)/i  # Print statements with sensitive data
      ],
      cwe_id: "CWE-489",
      owasp_category: "A05:2021",
      recommendation: "Remove all debugging code, breakpoints, and sensitive logging before deploying to production",
      test_cases: %{
        vulnerable: [
          ~S|require 'pry'|,
          ~S|binding.pry|,
          ~S|byebug|,
          ~S|debugger|,
          ~S|save_and_open_page|,
          ~S|Rails.logger.debug "Password: #{password}"|,
          ~S|puts "API key: #{api_key}"|
        ],
        safe: [
          ~S|Rails.logger.info "User logged in: #{user.email}"|,
          ~S|# binding.pry # Commented out debug|,
          ~S|logger.info "Cache cleared"|,
          ~S|Rails.logger.debug "Processing request #{request.id}"|
        ]
      }
    }
  end
  
  @impl true
  def vulnerability_metadata do
    %{
      description: """
      Debug mode enabled is an information disclosure vulnerability that occurs when
      development debugging tools, breakpoints, verbose logging, or testing utilities
      are left active in production environments. This can lead to sensitive information
      exposure, unauthorized access to application internals, or remote code execution.
      
      **How Debug Mode Vulnerabilities Work:**
      Ruby applications commonly use debugging gems like Pry, Byebug, or built-in
      debugger statements during development. When these tools remain active in
      production, they can:
      - Create interactive breakpoints that expose application state
      - Log sensitive information like passwords, API keys, and session tokens
      - Save debugging artifacts (screenshots, page dumps) containing sensitive data
      - Provide REPL access to attackers who can trigger breakpoints
      
      **Ruby-Specific Debug Tools:**
      - **Pry**: Interactive Ruby debugger with REPL capabilities
      - **Byebug**: Step-through debugger for Ruby 2.x and 3.x
      - **Debugger**: Built-in Ruby debugging functionality
      - **Capybara**: Testing framework with debugging helpers like save_and_open_page
      - **Rails.logger**: Framework logging that can leak sensitive data
      
      **Critical Security Impact:**
      Debug mode vulnerabilities are particularly dangerous because they can:
      - **Remote Code Execution**: Interactive debuggers provide shell access
      - **Credential Exposure**: Debug logs often contain passwords, tokens, keys
      - **Session Hijacking**: Debug output may expose session identifiers
      - **Business Logic Exposure**: Application internals revealed through debugging
      - **Compliance Violations**: Sensitive data logged in plain text
      
      **Rails-Specific Vulnerabilities:**
      The Accorian security research and CVE-2019-5420 demonstrate how Rails
      development mode with debugging enabled can lead to remote code execution.
      The Rails console and debugging tools provide full application access,
      making these vulnerabilities extremely severe.
      
      **Common Attack Scenarios:**
      - Triggering pry breakpoints to gain interactive access to production systems
      - Harvesting credentials from debug logs written to files or stdout
      - Accessing Capybara-generated debugging artifacts containing sensitive pages
      - Exploiting verbose error pages that leak application structure and data
      """,
      references: [
        %{
          type: :cwe,
          id: "CWE-489",
          title: "Active Debug Code",
          url: "https://cwe.mitre.org/data/definitions/489.html"
        },
        %{
          type: :cwe,
          id: "CWE-200",
          title: "Exposure of Sensitive Information to an Unauthorized Actor",
          url: "https://cwe.mitre.org/data/definitions/200.html"
        },
        %{
          type: :owasp,
          id: "A05:2021",
          title: "OWASP Top 10 2021 - A05 Security Misconfiguration",
          url: "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"
        },
        %{
          type: :research,
          id: "accorian_rails_rce",
          title: "Debugging Misconfiguration: Ruby on Rails Remote Code Execution",
          url: "https://medium.com/@accorian/debugging-misconfiguration-ruby-on-rails-remote-code-execution-e15d9c34ef0a"
        },
        %{
          type: :research,
          id: "rails_debug_akto",
          title: "Rails Debug Mode Enabled - Security Vulnerability",
          url: "https://www.akto.io/test/rails-debug-mode-enabled"
        },
        %{
          type: :research,
          id: "beagle_rails_debug",
          title: "Rails Debug Mode Enabled Security Risk",
          url: "https://beaglesecurity.com/blog/vulnerability/rails-debug-mode-enabled.html"
        },
        %{
          type: :research,
          id: "owasp_rails_cheatsheet",
          title: "OWASP Ruby on Rails Security Cheat Sheet",
          url: "https://cheatsheetseries.owasp.org/cheatsheets/Ruby_on_Rails_Cheat_Sheet.html"
        }
      ],
      attack_vectors: [
        "Interactive breakpoint exploitation: Trigger binding.pry or byebug to gain REPL access",
        "Log harvesting: Extract passwords, API keys, tokens from debug logs",
        "Capybara artifact access: Retrieve saved pages/screenshots containing sensitive data",
        "Error page exploitation: Leverage verbose debug error pages for reconnaissance",
        "Session token extraction: Harvest session identifiers from debug output",
        "Database credential exposure: Access database connection strings in debug logs",
        "API key leakage: Extract third-party service credentials from debug statements",
        "Source code disclosure: Use debugging tools to examine application internals",
        "Environment variable exposure: Access secrets through debug console access",
        "Memory dump analysis: Extract sensitive data from debugging memory snapshots"
      ],
      real_world_impact: [
        "CVE-2019-5420: Rails development mode secret_key_base remote code execution vulnerability",
        "Accorian research: Rails debugging console leading to full system compromise",
        "Multiple Rails applications exposed through Shodan with debug consoles accessible",
        "Production systems compromised through forgotten binding.pry statements",
        "API keys and database credentials leaked through Rails.logger.debug statements",
        "Capybara save_and_open_page exposing sensitive user data in public directories",
        "Byebug left enabled allowing attackers to execute arbitrary Ruby code",
        "Debug logging containing credit card numbers and personal information",
        "Session hijacking through debug logs containing authentication tokens",
        "OWASP Railsgoat demonstrating multiple debug-related vulnerabilities"
      ],
      cve_examples: [
        %{
          id: "CVE-2019-5420",
          description: "Rails development mode secret_key_base remote code execution",
          severity: "critical",
          cvss: 9.8,
          note: "Debug mode enables file writes and code execution via crafted cookies"
        },
        %{
          id: "CVE-2021-3129",
          description: "Laravel debug mode remote code execution (similar vulnerability pattern)",
          severity: "critical",
          cvss: 9.8,
          note: "Debug mode with APP_DEBUG=true allowing file writes and RCE"
        },
        %{
          id: "CVE-2013-0156",
          description: "Rails XML parameter parsing with debug information disclosure",
          severity: "high",
          cvss: 7.5,
          note: "Debug mode exposed internal application structure and data"
        }
      ],
      detection_notes: """
      This pattern detects debug mode vulnerabilities by identifying Ruby debugging
      tools, breakpoints, and sensitive information logging:
      
      **Primary Detection Points:**
      - Pry debugging: require 'pry', binding.pry statements
      - Byebug debugging: byebug statements and require statements  
      - Debugger statements: Ruby's built-in debugger calls
      - Capybara helpers: save_and_open_page, save_and_open_screenshot
      - Sensitive logging: Rails.logger or other loggers with sensitive data
      
      **Ruby-Specific Patterns:**
      - Pry breakpoints: Most common Ruby debugging tool
      - Byebug statements: Step-through debugging
      - Rails.logger.debug: Framework-specific logging
      - Capybara testing helpers: Integration test debugging tools
      - puts statements: Simple print debugging with sensitive data
      
      **False Positive Considerations:**
      - Commented out debug statements (should be excluded)
      - Debug statements in test files (lower severity)
      - Non-sensitive debug logging (request IDs, timestamps)
      - Method names containing "debug" (false positives)
      
      **Detection Enhancements:**
      The AST enhancement provides context-aware analysis:
      - Environment detection (production vs development context)
      - Sensitive data pattern matching in log statements
      - Test file exclusion for debugging helpers
      - Breakpoint vs method call distinction
      """,
      safe_alternatives: [
        "Use Rails.logger.info for non-sensitive operational logging",
        "Remove all binding.pry and byebug statements before production deployment",
        "Use proper Rails environment checks: if Rails.env.development?",
        "Implement structured logging without sensitive data exposure",
        "Use Rails production logging levels (info, warn, error) instead of debug",
        "Configure log rotation and secure log storage for production",
        "Use monitoring tools instead of debug statements for production insights",
        "Implement proper error handling without exposing internal details"
      ],
      additional_context: %{
        common_mistakes: [
          "Leaving binding.pry statements in production code",
          "Using Rails.logger.debug with passwords, tokens, or API keys",
          "Deploying with byebug or debugger statements still active",
          "Not removing Capybara debugging helpers before production",
          "Using puts for debugging with sensitive information",
          "Assuming debug statements are harmless if not triggered",
          "Not checking log files for accidentally logged sensitive data",
          "Enabling verbose error pages in production environments"
        ],
        secure_patterns: [
          ~S"Rails.logger.info 'User #{user.id} performed action' # Safe logging",
          "# binding.pry # Properly commented out debug code",
          ~S"Rails.logger.debug 'Processing request #{request.id}' # Non-sensitive debug",
          "raise 'Custom error' unless valid? # Proper error handling",
          "if Rails.env.development? # Proper environment checks",
          "Rails.logger.warn 'Invalid attempt detected' # Appropriate log level"
        ],
        ruby_specific: %{
          debug_tools: [
            "Pry: Interactive Ruby debugger with REPL and introspection",
            "Byebug: Step-through debugger for Ruby 2.x and 3.x applications",
            "Debug gem: New Ruby 3.1+ debugging capabilities",
            "IRB: Interactive Ruby shell (less common for breakpoints)",
            "Capybara: Web testing framework with debugging utilities"
          ],
          rails_specific: [
            "Rails.logger: Framework logging system with multiple levels",
            "Rails.env: Environment detection for conditional debugging",
            "Development mode: Automatic reloading and verbose error pages",
            "Debug gem integration: Rails 7+ includes debug gem by default",
            "Console debugging: Rails console provides full application access"
          ],
          mitigation_strategies: [
            "Use CI/CD pipeline checks to prevent debug code deployment",
            "Implement pre-commit hooks to detect debug statements",
            "Configure production logging levels to exclude debug output",
            "Use environment-specific configuration for debugging tools",
            "Implement proper monitoring instead of debug logging",
            "Regular security audits of production logs for sensitive data"
          ]
        }
      }
    }
  end
  
  @doc """
  Returns AST enhancement rules to reduce false positives.
  
  This enhancement helps distinguish between actual security issues and
  acceptable debug patterns.
  
  ## Examples
  
      iex> enhancement = RsolvApi.Security.Patterns.Ruby.DebugModeEnabled.ast_enhancement()
      iex> Map.keys(enhancement) |> Enum.sort()
      [:ast_rules, :confidence_rules, :context_rules, :min_confidence]
      
      iex> enhancement = RsolvApi.Security.Patterns.Ruby.DebugModeEnabled.ast_enhancement()
      iex> enhancement.min_confidence
      0.7
  """
  @impl true
  def ast_enhancement do
    %{
      ast_rules: %{
        node_type: "CallExpression",
        method_names: ["pry", "byebug", "debugger", "save_and_open_page", "save_and_open_screenshot"],
        require_names: ["pry", "byebug", "debugger"],
        logging_analysis: %{
          check_logger_calls: true,
          logger_methods: ["debug", "info", "warn", "error"],
          logger_objects: ["Rails.logger", "logger", "Logger"],
          sensitive_data_patterns: [
            "password", "secret", "key", "token", "credential",
            "auth", "session", "cookie", "api_key", "access_token"
          ]
        },
        statement_analysis: %{
          check_breakpoints: true,
          check_print_statements: true,
          print_methods: ["puts", "print", "p", "pp"]
        }
      },
      context_rules: %{
        exclude_paths: [
          ~r/test/,
          ~r/spec/,
          ~r/fixtures/,
          ~r/factories/,
          ~r/seeds/,
          ~r/db\/migrate/,
          ~r/examples/,
          ~r/demo/
        ],
        check_environment_context: true,
        danger_environments: ["production", "staging", "prod"],
        safe_environments: ["development", "test", "dev"],
        environment_patterns: [
          ~r/Rails\.env\.production\?/,
          ~r/Rails\.env\.staging\?/,
          ~r/ENV\[.production.\]/,
          ~r/if\s+Rails\.env\.development\?/
        ],
        comment_exclusion: true,
        debug_specific: %{
          require_actual_calls: true,
          distinguish_method_vs_breakpoint: true,
          check_conditional_debugging: true,
          sensitive_data_severity_boost: true
        }
      },
      confidence_rules: %{
        base: 0.5,
        adjustments: %{
          "in_production_context" => 0.4,
          "unconditional_breakpoint" => 0.3,
          "sensitive_data_logged" => 0.4,
          "capybara_helpers" => 0.2,
          "logging_with_interpolation" => 0.2,
          "conditional_on_development" => -0.4,
          "in_test_file" => -0.5,
          "commented_out" => -1.0,
          "method_definition" => -0.8,
          "safe_logging_level" => -0.3,
          "non_sensitive_data" => -0.2
        }
      },
      min_confidence: 0.7
    }
  end
end
