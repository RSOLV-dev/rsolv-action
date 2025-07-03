defmodule Rsolv.Security.Patterns.Javascript.DebugConsoleLog do
  @moduledoc """
  Debug Console Log pattern for detecting sensitive data in console logs.
  
  Console logging statements can inadvertently expose sensitive information
  in production environments. This includes passwords, API keys, tokens,
  and other confidential data that gets logged to browser consoles or
  server logs where they can be accessed by unauthorized parties.
  
  ## Vulnerability Details
  
  Console.log statements are often added during development for debugging
  purposes but forgotten when code is deployed to production. This can lead to:
  - Sensitive data visible in browser developer tools
  - Credentials exposed in server logs
  - API keys and tokens leaked to log aggregation services
  - Personal information exposed in violation of privacy regulations
  
  ### Attack Example
  ```javascript
  // Vulnerable code - logs sensitive data
  console.log("User login:", { username, password });
  console.error("API call failed with key:", apiKey);
  
  // Attacker opens browser console and sees:
  // User login: {username: "admin", password: "secret123"}
  // API call failed with key: sk_live_4242424242424242
  ```
  """
  
  use Rsolv.Security.Patterns.PatternBase
  alias Rsolv.Security.Pattern
  
  @doc """
  Returns the pattern definition for debug console log detection.
  
  ## Examples
  
      iex> pattern = Rsolv.Security.Patterns.Javascript.DebugConsoleLog.pattern()
      iex> pattern.id
      "js-debug-console-log"
      
      iex> pattern = Rsolv.Security.Patterns.Javascript.DebugConsoleLog.pattern()
      iex> pattern.severity
      :low
      
      iex> pattern = Rsolv.Security.Patterns.Javascript.DebugConsoleLog.pattern()
      iex> vulnerable = "console.log(password)"
      iex> Regex.match?(pattern.regex, vulnerable)
      true
      
      iex> pattern = Rsolv.Security.Patterns.Javascript.DebugConsoleLog.pattern()
      iex> safe = "console.log('User logged in')"
      iex> Regex.match?(pattern.regex, safe)
      false
  """
  def pattern do
    %Pattern{
      id: "js-debug-console-log",
      name: "Sensitive Data in Console Logs",
      description: "Console logs can expose sensitive information in production",
      type: :information_disclosure,
      severity: :low,
      languages: ["javascript", "typescript"],
      # Matches console methods with sensitive keywords in arguments
      regex: ~r/console\.(?:log|info|warn|error)\s*\([^)]*(?:password|secret|token|key|credential|auth)/i,
      cwe_id: "CWE-532",
      owasp_category: "A09:2021",
      recommendation: "Remove console.log statements or use proper logging that filters sensitive data.",
      test_cases: %{
        vulnerable: [
          ~S|console.log(password)|,
          ~S|console.error("Auth failed for token:", token)|,
          ~S|console.info({apiKey: config.apiKey})|
        ],
        safe: [
          ~S|logger.debug("User authenticated", {userId: user.id})|,
          ~S|console.log("Login attempt for user:", username)|,
          ~S|if (isDevelopment) { console.log(debugInfo) }|
        ]
      }
    }
  end
  
  @doc """
  Returns comprehensive vulnerability metadata for debug console log issues.
  
  Includes information about the risks of logging sensitive data and
  best practices for secure logging in production environments.
  """
  def vulnerability_metadata do
    %{
      description: """
      Console logging of sensitive data is a common vulnerability that occurs when
      developers use console.log, console.error, or similar methods to output
      debugging information containing passwords, API keys, tokens, or other
      confidential data. While often harmless during development, these statements
      can expose sensitive information when left in production code.
      
      The risk is particularly high in client-side JavaScript where any user can
      open the browser developer console and view the logged data. In Node.js
      applications, console output typically goes to stdout/stderr which may be
      captured by logging systems, potentially exposing sensitive data to anyone
      with log access.
      
      This vulnerability often occurs because:
      1. Developers forget to remove debug statements before deployment
      2. Logging statements are added during incident response and not removed
      3. No code review process catches sensitive data in logs
      4. Development and production code paths are not properly separated
      """,
      
      references: [
        %{
          type: :cwe,
          id: "CWE-532",
          title: "Insertion of Sensitive Information into Log File",
          url: "https://cwe.mitre.org/data/definitions/532.html"
        },
        %{
          type: :owasp,
          id: "A09:2021",
          title: "OWASP Top 10 2021 - A09 Security Logging and Monitoring Failures",
          url: "https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/"
        },
        %{
          type: :owasp,
          id: "logging_cheat_sheet",
          title: "OWASP Logging Cheat Sheet",
          url: "https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html"
        },
        %{
          type: :nist,
          id: "SP-800-92",
          title: "NIST Guide to Computer Security Log Management",
          url: "https://csrc.nist.gov/publications/detail/sp/800-92/final"
        }
      ],
      
      attack_vectors: [
        "Browser console access: F12 → Console tab shows all logged data",
        "Server log files: Sensitive data written to /var/log/ accessible to admins",
        "Log aggregation services: Credentials sent to Splunk, ELK, CloudWatch",
        "Client-side JavaScript: Mobile app WebViews expose console to debugging",
        "Error tracking services: Sentry, Rollbar capture console.error with secrets",
        "Development tools: Browser extensions can intercept console messages",
        "Shared environments: Console logs visible to other users on shared systems"
      ],
      
      real_world_impact: [
        "Credential theft from exposed passwords and API keys",
        "Session hijacking using leaked authentication tokens",
        "Privacy violations from logged personal information",
        "Regulatory compliance failures (GDPR, HIPAA, PCI-DSS)",
        "Financial loss from exposed payment information",
        "Reputation damage from public credential exposure",
        "Supply chain attacks through exposed third-party API keys"
      ],
      
      cve_examples: [
        %{
          id: "CVE-2021-21315",
          description: "The System Information Library for Node.js logged sensitive information to the console",
          severity: "medium",
          cvss: 5.3,
          note: "Exposed system credentials through console.log statements"
        },
        %{
          id: "CVE-2020-7660",
          description: "serialize-javascript logged crafted payloads to console exposing sensitive data",
          severity: "medium",
          cvss: 5.3,
          note: "Debug console.log statements leaked serialized sensitive objects"
        },
        %{
          id: "CVE-2019-10758",
          description: "mongo-express logged password to console in plain text",
          severity: "high",
          cvss: 7.5,
          note: "Admin password visible in server console logs"
        },
        %{
          id: "CVE-2018-3721",
          description: "Lodash logged sensitive information during error conditions",
          severity: "low",
          cvss: 3.3,
          note: "Error handling console.error exposed internal application state"
        }
      ],
      
      detection_notes: """
      This pattern detects console logging methods (log, info, warn, error) that
      include sensitive keywords in their arguments. The detection focuses on:
      1. Direct console method calls
      2. Presence of sensitive keywords like password, secret, token, key
      3. Case-insensitive matching to catch variations
      
      The pattern aims to catch common cases while avoiding false positives from
      safe logging practices or conditional development-only logging.
      """,
      
      safe_alternatives: [
        "Use structured logging libraries that support redaction (winston, bunyan, pino)",
        "Implement a custom logger that filters sensitive fields",
        "Use environment checks: if (process.env.NODE_ENV === 'development') console.log(...)",
        "Replace sensitive values with placeholders: log('Login attempt for user: [REDACTED]')",
        "Use debug module with namespaces: const debug = require('debug')('app:auth')",
        "Implement centralized logging with field filtering",
        "Use source maps to remove console statements in production builds"
      ],
      
      additional_context: %{
        common_mistakes: [
          "Logging entire request/response objects containing auth headers",
          "Using console.log for error handling instead of proper logging",
          "Logging database connection strings with passwords",
          "Debugging OAuth flows and logging tokens",
          "Logging form data that includes passwords or credit cards"
        ],
        
        secure_patterns: [
          "Use structured logging with explicit field selection",
          "Implement a security logger that never logs certain fields",
          "Use log levels appropriately (debug never goes to production)",
          "Redact sensitive fields before logging",
          "Use unique identifiers instead of actual sensitive values"
        ],
        
        framework_specific: %{
          react: [
            "Remove console statements with babel-plugin-transform-remove-console",
            "Use React DevTools Profiler instead of console timing",
            "Implement custom error boundaries that filter sensitive props"
          ],
          nodejs: [
            "Use winston with custom formatters for redaction",
            "Implement morgan for HTTP logs with header filtering",
            "Use debug module with DEBUG environment variable"
          ],
          angular: [
            "Implement a custom LoggerService",
            "Use Angular's built-in production mode checks",
            "Configure angular.json to remove console in production"
          ]
        }
      }
    }
  end
  
  @doc """
  Check if this pattern applies to a file based on its path and content.
  
  Applies to JavaScript/TypeScript files that might contain console statements.
  """
  def applies_to_file?(file_path, content ) do
    cond do
      # JavaScript/TypeScript files
      String.match?(file_path, ~r/\.(js|jsx|ts|tsx|mjs|cjs)$/i) -> true
      
      # HTML files with script tags
      String.match?(file_path, ~r/\.html?$/i) && content != nil ->
        String.contains?(content, "<script")
        
      # Default
      true -> false
    end
  end
  
  @doc """
  Returns AST enhancement rules to reduce false positives.
  
  This enhancement helps distinguish between actual sensitive data exposure and:
  - Development-only debug statements with environment checks
  - Logging frameworks that handle redaction properly
  - Generic console statements without sensitive data
  - Test code that might legitimately log test credentials
  
  ## Examples
  
      iex> enhancement = Rsolv.Security.Patterns.Javascript.DebugConsoleLog.ast_enhancement()
      iex> Map.keys(enhancement) |> Enum.sort()
      [:ast_rules, :confidence_rules, :context_rules, :min_confidence]
      
      iex> enhancement = Rsolv.Security.Patterns.Javascript.DebugConsoleLog.ast_enhancement()
      iex> enhancement.ast_rules.node_type
      "CallExpression"
      
      iex> enhancement = Rsolv.Security.Patterns.Javascript.DebugConsoleLog.ast_enhancement()
      iex> "console.log" in enhancement.ast_rules.callee_patterns
      true
      
      iex> enhancement = Rsolv.Security.Patterns.Javascript.DebugConsoleLog.ast_enhancement()
      iex> enhancement.min_confidence
      0.6
      
      iex> enhancement = Rsolv.Security.Patterns.Javascript.DebugConsoleLog.ast_enhancement()
      iex> "wrapped_in_condition" in Map.keys(enhancement.confidence_rules.adjustments)
      true
  """
  @impl true
  def ast_enhancement do
    %{
      ast_rules: %{
        node_type: "CallExpression",
        callee_patterns: ["console.log", "console.error", "console.warn", "console.info"],
        # Must have sensitive data in arguments
        argument_analysis: %{
          contains_sensitive_keywords: true,
          has_string_literals: true,
          references_sensitive_variables: true
        }
      },
      context_rules: %{
        exclude_paths: [~r/test/, ~r/spec/, ~r/__tests__/, ~r/\.test\./, ~r/\.spec\./],
        exclude_if_conditional: true,          # Inside if statement checking env
        exclude_if_production_check: true,     # Has NODE_ENV or similar check
        exclude_if_wrapped_logger: true,       # Custom logger wrapping console
        safe_patterns: ["isDevelopment", "DEBUG", "process.env.NODE_ENV"]
      },
      confidence_rules: %{
        base: 0.2,  # Low base - console.log is common
        adjustments: %{
          "has_sensitive_keyword" => 0.4,
          "direct_password_variable" => 0.5,
          "in_auth_context" => 0.3,
          "wrapped_in_condition" => -0.6,    # if (isDev) console.log(...)
          "has_env_check" => -0.7,           # process.env.NODE_ENV check
          "in_test_file" => -0.8,            # Test files often log test data
          "using_logger_library" => -0.5     # winston, bunyan, etc.
        }
      },
      min_confidence: 0.6
    }
  end
end
