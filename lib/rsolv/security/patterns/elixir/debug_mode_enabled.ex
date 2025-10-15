defmodule Rsolv.Security.Patterns.Elixir.DebugModeEnabled do
  @moduledoc """
  Debug Mode Enabled vulnerability pattern for Elixir/Phoenix applications.

  This pattern detects potentially dangerous debug mode configurations and debug function
  usage that can lead to information disclosure in production environments.

  ## Vulnerability Details

  Debug mode can expose sensitive information in several ways:
  - Configuration files with `debug: true` enable verbose error messages
  - `IO.inspect/2` calls can leak sensitive data to logs
  - Phoenix debug annotations reveal internal application structure
  - Debug-level logging can expose credentials and internal state
  - `dbg/1` calls (introduced in Elixir 1.14) for debugging

  ## Technical Impact

  Information disclosure through:
  - Detailed error messages revealing application internals
  - Sensitive data logged via `IO.inspect/2` or `dbg/1`
  - Stack traces exposing code structure and file paths
  - Phoenix debug annotations showing template information
  - Debug logs containing credentials or session tokens

  ## Examples

  Vulnerable configuration:
  ```elixir
  # config/prod.exs - VULNERABLE
  config :my_app, debug: true
  config :phoenix_live_view, debug_heex_annotations: true
  config :logger, level: :debug
  ```

  Vulnerable debug code:
  ```elixir
  # VULNERABLE - exposes user data
  def create_user(params) do
    IO.inspect(params, label: "User creation")
    user_data |> dbg()
    User.create(params)
  end
  ```

  Safe alternatives:
  ```elixir
  # config/prod.exs - SAFE
  config :my_app, debug: false
  config :phoenix_live_view, debug_heex_annotations: false
  config :logger, level: :info

  # SAFE - use structured logging
  def create_user(params) do
    Logger.info("Creating user", user_id: params["id"])
    User.create(params)
  end
  ```

  ## Attack Scenarios

  1. **Configuration Information Disclosure**: `debug: true` in production exposes
     detailed error messages that reveal application structure and internal logic

  2. **Sensitive Data Logging**: `IO.inspect/2` calls can log user credentials,
     session tokens, and personal information to application logs

  3. **Stack Trace Information Disclosure**: Debug mode stack traces reveal
     file paths, function names, and application architecture

  4. **Phoenix Template Information**: Debug annotations expose template structure
     and variable names that can aid in further attacks

  ## References

  - Paraxial Elixir Security Best Practices: https://paraxial.io/blog/elixir-best
  - Fluid Attacks Console Functions: https://help.fluidattacks.com/portal/en/kb/articles/criteria-fixes-elixir-066
  - OWASP Top 10 2021 - A05 Security Misconfiguration
  - CWE-489: Active Debug Code
  """

  use Rsolv.Security.Patterns.PatternBase

  @impl true
  def pattern do
    %Rsolv.Security.Pattern{
      id: "elixir-debug-mode-enabled",
      name: "Debug Mode Enabled",
      description:
        "Debug mode configurations and debug function usage that can expose sensitive information in production",
      type: :information_disclosure,
      severity: :medium,
      languages: ["elixir"],
      frameworks: ["phoenix"],
      regex: [
        # Config debug: true patterns
        ~r/config\s+:[^,]+.*debug:\s*true/s,
        ~r/config\s*\(\s*:[^,]+.*debug:\s*true\s*\)/s,

        # Phoenix LiveView debug annotations
        ~r/debug_heex_annotations:\s*true/,

        # IO.inspect patterns
        ~r/IO\.inspect\s*\(|IO\.inspect\s+[^(]/,

        # dbg/1 patterns (Elixir 1.14+)
        ~r/\bdbg\s*\(/,
        ~r/\|\s*>\s*dbg\s*\(\s*\)/,

        # Logger debug level in config
        ~r/config\s+:logger,\s*level:\s*:debug/,

        # Mix.env debug checks that may still execute in prod (avoid :dev checks)
        ~r/if\s+Mix\.env\(\)\s*!=\s*:prod\s+do.*IO\.inspect/s,
        ~r/unless\s+Mix\.env\(\)\s*==\s*:prod\s+do.*IO\.inspect/s
      ],
      cwe_id: "CWE-489",
      owasp_category: "A05:2021",
      recommendation:
        "Disable debug configurations in production and replace debug function calls with proper logging",
      test_cases: %{
        vulnerable: [
          ~S|config :my_app, debug: true|,
          ~S|IO.inspect(user_data)|,
          ~S|dbg(sensitive_info)|,
          ~S|config :phoenix_live_view, debug_heex_annotations: true|,
          ~S|config :logger, level: :debug|
        ],
        safe: [
          ~S|config :my_app, debug: false|,
          ~S|Logger.debug("User action", user_id: user.id)|,
          ~S|config :phoenix_live_view, debug_heex_annotations: false|,
          ~S|config :logger, level: :info|
        ]
      }
    }
  end

  @impl true
  def vulnerability_metadata do
    %{
      attack_vectors: """
      1. Configuration Information Disclosure: Debug mode enabled in production reveals detailed error messages
      2. Sensitive Data Logging: IO.inspect/dbg calls log credentials, tokens, and personal data
      3. Stack Trace Exposure: Debug mode exposes application structure through detailed stack traces
      4. Template Information Disclosure: Phoenix debug annotations reveal internal template structure
      """,
      business_impact: """
      High: Information disclosure can lead to:
      - Exposure of user credentials and sensitive data
      - Revelation of application architecture aiding further attacks
      - Compliance violations (GDPR, CCPA) due to data leakage
      - Loss of customer trust from security incidents
      """,
      technical_impact: """
      Medium: Debug mode can expose:
      - Application configuration and environment variables
      - Database schema and query structures
      - Internal API endpoints and authentication mechanisms
      - Session tokens and security keys in logs
      """,
      likelihood:
        "Medium: Debug configurations commonly left enabled accidentally in production deployments",
      cve_examples: [
        "CWE-489: Active Debug Code",
        "CWE-532: Insertion of Sensitive Information into Log File",
        "CWE-200: Information Exposure"
      ],
      compliance_standards: [
        "OWASP Top 10 2021 - A05: Security Misconfiguration",
        "OWASP Top 10 2021 - A09: Security Logging and Monitoring Failures",
        "PCI DSS Requirement 6.5.5: Improper Error Handling",
        "NIST Cybersecurity Framework - PR.DS: Data Security"
      ],
      remediation_steps: """
      1. Review all configuration files for debug settings
      2. Set debug: false in production configuration
      3. Replace IO.inspect/dbg calls with proper Logger statements
      4. Disable Phoenix debug annotations in production
      5. Set appropriate log levels for production environment
      6. Implement log scrubbing for sensitive data
      """,
      prevention_tips: """
      1. Use environment-specific configuration files
      2. Implement CI/CD checks for debug configurations
      3. Use structured logging instead of debug functions
      4. Regularly audit production configurations
      5. Implement log rotation and access controls
      6. Use logging libraries that support data filtering
      """,
      detection_methods: """
      1. Static code analysis for debug function usage
      2. Configuration file auditing for debug settings
      3. Log analysis for sensitive data patterns
      4. Runtime monitoring for debug mode indicators
      5. Security scanning for information disclosure
      """,
      safe_alternatives: """
      1. Use Logger.debug/2 with appropriate log levels
      2. Implement structured logging with filtered sensitive data
      3. Use Mix.env() checks for development-only debug code
      4. Configure separate logging for development vs production
      5. Use telemetry for production monitoring instead of debug prints
      """
    }
  end

  @impl true
  def ast_enhancement do
    %{
      min_confidence: 0.7,
      context_rules: %{
        exclude_development_files: true,
        development_file_patterns: [
          ~r/\/dev\.exs$/,
          ~r/\/test\.exs$/,
          ~r/_test\.exs$/,
          ~r/\/test\//,
          ~r/\/priv\/repo\/seeds/
        ],
        production_indicators: [
          "prod.exs",
          "production",
          "config/runtime.exs"
        ],
        check_environment_context: true,
        sensitive_config_keys: [
          "debug",
          "debug_heex_annotations",
          "logger",
          "level"
        ]
      },
      confidence_rules: %{
        base: 0.7,
        adjustments: %{
          config_file_bonus: 0.2,
          production_file_bonus: 0.3,
          io_inspect_with_sensitive_data: 0.2,
          multiple_debug_patterns: 0.1
        }
      },
      ast_rules: %{
        node_type: "debug_analysis",
        config_analysis: %{
          check_config_calls: true,
          check_debug_keys: true,
          config_functions: ["config", "import_config"],
          debug_keys: ["debug", "debug_heex_annotations", "level"]
        },
        debug_function_analysis: %{
          check_io_inspect: true,
          check_dbg_calls: true,
          debug_functions: ["IO.inspect", "dbg", "IO.puts"],
          check_argument_sensitivity: true
        },
        environment_analysis: %{
          check_mix_env: true,
          check_conditional_debug: true,
          production_environments: ["prod", "production"],
          unsafe_conditions: ["!=", "not", "unless"]
        }
      }
    }
  end
end
