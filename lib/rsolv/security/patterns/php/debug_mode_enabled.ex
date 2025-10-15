defmodule Rsolv.Security.Patterns.Php.DebugModeEnabled do
  @moduledoc """
  Pattern for detecting debug mode enabled in PHP applications.

  This pattern identifies when PHP applications have debug mode or verbose error
  reporting enabled in production environments, potentially exposing sensitive
  information like database credentials, file paths, and application internals.

  ## Vulnerability Details

  Debug mode configuration like `display_errors = 1` or `error_reporting(E_ALL)`
  can expose detailed error messages to end users, revealing sensitive information
  about the application's structure, database queries, file paths, and potential
  vulnerabilities.

  ### Attack Example
  ```php
  // Vulnerable configuration
  ini_set('display_errors', 1);
  error_reporting(E_ALL);

  // If an error occurs:
  // Fatal error: Uncaught PDOException: SQLSTATE[42S02]: Base table or view not found:
  // 1146 Table 'myapp.users' doesn't exist in /var/www/app/models/UserModel.php:45
  // Stack trace: #0 /var/www/app/controllers/LoginController.php:23: UserModel->findByEmail()
  ```
  """

  use Rsolv.Security.Patterns.PatternBase
  alias Rsolv.Security.Pattern

  @impl true
  def pattern do
    %Pattern{
      id: "php-debug-mode-enabled",
      name: "Debug Mode Enabled",
      description: "Debug settings that expose sensitive information",
      type: :information_disclosure,
      severity: :medium,
      languages: ["php"],
      regex:
        ~r/(ini_set\s*\(\s*['"]display_errors['"]\s*,\s*(['"]?1['"]?|true|['"]on['"]?))|error_reporting\s*\(\s*E_ALL/i,
      cwe_id: "CWE-489",
      owasp_category: "A05:2021",
      recommendation: "Disable debug mode and error display in production",
      test_cases: %{
        vulnerable: [
          ~s|ini_set('display_errors', 1);|,
          ~s|ini_set('display_errors', 'on');|,
          ~s|ini_set('display_errors', true);|
        ],
        safe: [
          ~s|ini_set('display_errors', 0);|,
          ~s|ini_set('display_errors', 'off');|,
          ~s|ini_set('log_errors', 1);|
        ]
      }
    }
  end

  @impl true
  def vulnerability_metadata do
    %{
      description: """
      Debug mode and verbose error reporting in production environments can expose
      sensitive information about your application's internal structure, potentially
      revealing database schemas, file paths, configuration details, and code logic
      to attackers. This information disclosure can be leveraged to craft more
      sophisticated attacks against the application.

      When PHP's display_errors is enabled or error_reporting is set to show all
      errors, detailed error messages including stack traces are sent to the browser.
      These messages often contain:

      **Information Exposed**:
      - Full file system paths revealing directory structure
      - Database table and column names
      - SQL queries with potential injection points
      - Framework and library versions
      - Internal function and class names
      - Server configuration details
      - Sensitive variable contents in stack traces

      **Attack Scenarios**:

      **Path Disclosure**: Error messages reveal full file paths like
      `/var/www/app/config/database.php`, helping attackers understand the
      application structure and potentially access configuration files.

      **Database Schema Enumeration**: SQL errors expose table names, column names,
      and relationships, allowing attackers to craft targeted SQL injection attacks.

      **Version Fingerprinting**: Stack traces reveal framework versions, making it
      easier to find known vulnerabilities specific to those versions.

      **Source Code Disclosure**: Parse errors can reveal portions of source code,
      including business logic and security checks.
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
          id: "CWE-209",
          title: "Generation of Error Message Containing Sensitive Information",
          url: "https://cwe.mitre.org/data/definitions/209.html"
        },
        %{
          type: :owasp,
          id: "A05:2021",
          title: "OWASP Top 10 2021 - A05 Security Misconfiguration",
          url: "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"
        },
        %{
          type: :php_manual,
          id: "errorfunc.configuration",
          title: "PHP Error Handling Configuration",
          url: "https://www.php.net/manual/en/errorfunc.configuration.php"
        }
      ],
      attack_vectors: [
        "Triggering errors through malformed input to reveal file paths",
        "Causing database errors to expose schema information",
        "Forcing parse errors to reveal source code snippets",
        "Exploiting missing files to disclose directory structure",
        "Using error messages to map application functionality",
        "Leveraging stack traces to understand code flow",
        "Identifying vulnerable components through version disclosure"
      ],
      real_world_impact: [
        "Full path disclosure leading to local file inclusion attacks",
        "Database schema exposure enabling SQL injection",
        "Source code leaks revealing business logic flaws",
        "Configuration disclosure exposing API keys or credentials",
        "Server information aiding in targeted exploits",
        "User data exposure through error context",
        "Compliance violations (PCI-DSS, GDPR) for data exposure"
      ],
      cve_examples: [
        %{
          id: "CVE-2023-30854",
          description: "Moodle debug mode information disclosure vulnerability",
          severity: "medium",
          cvss: 5.3,
          note: "Debug messages exposed sensitive user information"
        },
        %{
          id: "CVE-2022-31056",
          description: "Shopware error handling information disclosure",
          severity: "medium",
          cvss: 5.3,
          note: "Stack traces revealed internal paths and configuration"
        },
        %{
          id: "CVE-2021-21029",
          description: "Magento debug mode path disclosure vulnerability",
          severity: "medium",
          cvss: 5.3,
          note: "Error messages exposed full filesystem paths"
        },
        %{
          id: "CVE-2020-15906",
          description: "Joomla debug mode database structure disclosure",
          severity: "medium",
          cvss: 5.3,
          note: "SQL errors revealed complete database schema"
        }
      ],
      detection_notes: """
      This pattern detects debug mode configuration by identifying:

      1. **ini_set() calls**: Detects setting display_errors to enabled values
         - ini_set('display_errors', 1)
         - ini_set('display_errors', 'on')
         - ini_set('display_errors', true)

      2. **Common Values**: Matches various ways to enable errors
         - Numeric: 1
         - String: 'on', 'On', 'ON'
         - Boolean: true

      3. **Case Insensitive**: The /i flag ensures 'on', 'On', 'ON' all match

      The regex: ini_set\\s*\\(\\s*['\"]display_errors['\"]\\s*,\\s*(1|true|on)

      Note: This pattern focuses on display_errors. Additional patterns may be
      needed for error_reporting(E_ALL) and other debug configurations.
      """,
      safe_alternatives: [
        "Set display_errors = Off in php.ini for production",
        "Use ini_set('display_errors', 0) in production code",
        "Configure error_reporting(0) for production environments",
        "Log errors to files: ini_set('log_errors', 1)",
        "Use custom error handlers: set_error_handler()",
        "Implement environment-based configuration",
        "Use monitoring services for error tracking (Sentry, Rollbar)"
      ],
      additional_context: %{
        common_mistakes: [
          "Forgetting to disable debug mode after development",
          "Using the same configuration for dev and production",
          "Enabling debug mode temporarily and forgetting to disable",
          "Assuming error suppression (@) is sufficient",
          "Not testing error handling in production mode",
          "Exposing errors through API responses",
          "Logging sensitive data along with errors"
        ],
        environment_configuration: [
          "Use .env files: DEBUG_MODE=false for production",
          "PHP-FPM pools with different error settings per environment",
          "Apache/Nginx vhost configurations for error handling",
          "Docker environment variables for configuration",
          "Configuration management tools (Ansible, Puppet)"
        ],
        production_recommendations: [
          "display_errors = Off",
          "log_errors = On",
          "error_reporting = E_ALL & ~E_DEPRECATED & ~E_STRICT",
          "error_log = /var/log/php/error.log",
          "Custom error pages for user-friendly messages",
          "Centralized logging with proper access controls",
          "Regular log rotation and monitoring"
        ]
      }
    }
  end

  @doc """
  Returns test cases for the debug mode enabled pattern.

  ## Examples

      iex> test_cases = Rsolv.Security.Patterns.Php.DebugModeEnabled.test_cases()
      iex> length(test_cases.positive)
      8

      iex> test_cases = Rsolv.Security.Patterns.Php.DebugModeEnabled.test_cases()
      iex> length(test_cases.negative)
      8
  """
  def test_cases do
    %{
      positive: [
        %{
          code: ~s|ini_set('display_errors', 1);|,
          description: "Standard debug mode enable"
        },
        %{
          code: ~s|ini_set('display_errors', '1');|,
          description: "String value '1'"
        },
        %{
          code: ~s|ini_set("display_errors", 1);|,
          description: "Double quotes variant"
        },
        %{
          code: ~s|ini_set('display_errors', true);|,
          description: "Boolean true value"
        },
        %{
          code: ~s|ini_set('display_errors', 'on');|,
          description: "String 'on' value"
        },
        %{
          code: ~s|ini_set('display_errors', 'On');|,
          description: "Capitalized 'On'"
        },
        %{
          code: ~s|ini_set( 'display_errors', 1 );|,
          description: "With extra spacing"
        },
        %{
          code: ~s|@ini_set('display_errors', 1);|,
          description: "With error suppression operator"
        }
      ],
      negative: [
        %{
          code: ~s|ini_set('display_errors', 0);|,
          description: "Properly disabled"
        },
        %{
          code: ~s|ini_set('display_errors', '0');|,
          description: "Disabled with string '0'"
        },
        %{
          code: ~s|ini_set('display_errors', false);|,
          description: "Disabled with boolean false"
        },
        %{
          code: ~s|ini_set('display_errors', 'off');|,
          description: "Disabled with 'off'"
        },
        %{
          code: ~s|ini_set('log_errors', 1);|,
          description: "Different setting (log_errors)"
        },
        %{
          code: ~s|error_reporting(0);|,
          description: "Different function"
        },
        %{
          code: ~s|// ini_set('display_errors', 1);|,
          description: "Commented out"
        },
        %{
          code: ~s|$display_errors = 1;|,
          description: "Just variable assignment"
        }
      ]
    }
  end

  @doc """
  Returns examples of vulnerable and fixed code.

  ## Examples

      iex> examples = Rsolv.Security.Patterns.Php.DebugModeEnabled.examples()
      iex> Map.keys(examples)
      [:vulnerable, :fixed]
  """
  def examples do
    %{
      vulnerable: %{
        "Basic debug configuration" => """
        // VULNERABLE: Debug mode enabled
        ini_set('display_errors', 1);
        error_reporting(E_ALL);

        // Any error will expose sensitive information:
        $db = new PDO('mysql:host=localhost;dbname=app', $user, $pass);
        // Could reveal: Fatal error: Uncaught PDOException: SQLSTATE[HY000] [1045]
        // Access denied for user 'root'@'localhost' in /var/www/app/db.php:5
        """,
        "Development settings in production" => """
        // VULNERABLE: Development configuration
        if ($_SERVER['SERVER_NAME'] == 'myapp.com') {
            ini_set('display_errors', 'On');
            ini_set('display_startup_errors', 1);
            error_reporting(E_ALL);
        }

        // Parse errors expose source code:
        // Parse error: syntax error, unexpected '}' in /var/www/app/admin/users.php on line 45
        """,
        "Framework debug mode" => """
        // VULNERABLE: Framework debug enabled
        define('WP_DEBUG', true);
        define('WP_DEBUG_DISPLAY', true);
        ini_set('display_errors', 1);

        // Exposes WordPress paths and database queries:
        // WordPress database error Table 'wp_users' doesn't exist for query
        // SELECT * FROM wp_users WHERE user_email = 'admin@site.com'
        """
      },
      fixed: %{
        "Production configuration" => """
        // SECURE: Proper production settings
        ini_set('display_errors', 0);
        ini_set('log_errors', 1);
        ini_set('error_log', '/var/log/php/app-errors.log');
        error_reporting(E_ALL & ~E_DEPRECATED & ~E_STRICT);

        // Custom error handler for user-friendly messages
        set_error_handler(function($severity, $message, $file, $line) {
            error_log("Error [$severity]: $message in $file:$line");

            if (!headers_sent()) {
                http_response_code(500);
            }

            // Show generic message to user
            echo "An error occurred. Please try again later.";
            exit();
        });
        """,
        "Environment-based config" => """
        // SECURE: Environment-aware configuration
        $environment = $_ENV['APP_ENV'] ?? 'production';

        if ($environment === 'production') {
            ini_set('display_errors', 0);
            ini_set('log_errors', 1);
            error_reporting(E_ALL & ~E_NOTICE);
        } else {
            // Only in development
            ini_set('display_errors', 1);
            error_reporting(E_ALL);
        }

        // Use structured logging
        function logError($message, $context = []) {
            $log = [
                'timestamp' => date('c'),
                'message' => $message,
                'context' => $context,
                'environment' => $_ENV['APP_ENV']
            ];

            error_log(json_encode($log) . PHP_EOL, 3, '/var/log/app/errors.json');
        }
        """,
        "Error monitoring integration" => """
        // SECURE: Professional error handling
        use Sentry\\SentrySdk;
        use Sentry\\State\\Scope;

        // Disable display, enable logging
        ini_set('display_errors', 0);
        ini_set('log_errors', 1);

        // Initialize error monitoring
        SentrySdk::init([
            'dsn' => $_ENV['SENTRY_DSN'],
            'environment' => $_ENV['APP_ENV'],
            'traces_sample_rate' => 0.1,
        ]);

        // Custom exception handler
        set_exception_handler(function($exception) {
            // Log to monitoring service
            SentrySdk::getCurrentHub()->captureException($exception);

            // Log locally for backup
            error_log($exception->getMessage());

            // Show user-friendly error page
            include 'templates/error500.php';
            exit();
        });
        """
      }
    }
  end

  @doc """
  Returns educational description of the vulnerability.

  ## Examples

      iex> desc = Rsolv.Security.Patterns.Php.DebugModeEnabled.vulnerability_description()
      iex> desc =~ "debug"
      true

      iex> desc = Rsolv.Security.Patterns.Php.DebugModeEnabled.vulnerability_description()
      iex> desc =~ "information"
      true

      iex> desc = Rsolv.Security.Patterns.Php.DebugModeEnabled.vulnerability_description()
      iex> desc =~ "production"
      true
  """
  def vulnerability_description do
    """
    Debug mode and verbose error reporting in production environments represent a
    significant security misconfiguration that can expose sensitive information
    about your application's internal workings, making it easier for attackers
    to identify and exploit vulnerabilities.

    When display_errors is enabled in debug mode, PHP sends detailed error messages directly to
    the browser, including file paths, line numbers, function names, and sometimes
    even variable contents. This information disclosure can be catastrophic for
    application security.

    ## Security Impact

    **Information Disclosure**: Error messages reveal the application's directory
    structure, database schema, server configuration, and code organization,
    providing attackers with a roadmap for exploitation.

    **Attack Surface Mapping**: Stack traces expose the application's architecture,
    making it easier to identify components, libraries, and potential entry points
    for attacks.

    **Vulnerability Discovery**: Error messages can reveal specific vulnerabilities
    like SQL injection points, file inclusion paths, or authentication bypasses.

    ## Common Scenarios

    1. **Path Disclosure**:
       - Reveals full file system paths
       - Exposes directory structure
       - Shows configuration file locations

    2. **Database Exposure**:
       - Table and column names
       - Query structure
       - Connection details

    3. **Code Disclosure**:
       - Function and class names
       - Business logic flow
       - Security check implementations

    ## Prevention

    Always disable display_errors in production, use proper error logging,
    implement custom error handlers that show generic messages to users, and
    utilize professional error monitoring services to track issues without
    exposing sensitive information to potential attackers.
    """
  end

  @doc """
  Returns AST enhancement rules to reduce false positives.

  This enhancement helps distinguish between actual production vulnerabilities
  and legitimate development/testing configurations.

  ## Examples

      iex> enhancement = Rsolv.Security.Patterns.Php.DebugModeEnabled.ast_enhancement()
      iex> Map.keys(enhancement) |> Enum.sort()
      [:ast_rules, :min_confidence]

      iex> enhancement = Rsolv.Security.Patterns.Php.DebugModeEnabled.ast_enhancement()
      iex> enhancement.min_confidence
      0.7

      iex> enhancement = Rsolv.Security.Patterns.Php.DebugModeEnabled.ast_enhancement()
      iex> length(enhancement.ast_rules)
      4
  """
  @impl true
  def ast_enhancement do
    %{
      min_confidence: 0.7,
      ast_rules: [
        %{
          type: "debug_settings",
          description: "Identify debug-related configurations",
          dangerous_settings: [
            "display_errors",
            "display_startup_errors",
            "html_errors",
            "track_errors"
          ],
          dangerous_values: ["1", "on", "true", "yes"],
          safe_values: ["0", "off", "false", "no"],
          related_functions: [
            "error_reporting",
            "set_error_handler",
            "set_exception_handler",
            "ini_set",
            "ini_get"
          ]
        },
        %{
          type: "environment_detection",
          description: "Check for environment-based configuration",
          environment_checks: [
            "$_ENV",
            "$_SERVER",
            "getenv",
            "APP_ENV",
            "APPLICATION_ENV",
            "ENVIRONMENT"
          ],
          development_indicators: [
            "dev",
            "development",
            "local",
            "debug",
            "test",
            "staging",
            "localhost"
          ],
          production_indicators: [
            "prod",
            "production",
            "live",
            "master"
          ]
        },
        %{
          type: "production_indicators",
          description: "Detect production environment context",
          production_checks: [
            "production",
            "live",
            "prod",
            ".com",
            ".org",
            ".net"
          ],
          exclude_patterns: [
            "example.com",
            "test.com",
            "localhost",
            "127.0.0.1",
            "dev.",
            "staging."
          ]
        },
        %{
          type: "conditional_configuration",
          description: "Analyze conditional debug settings",
          safe_patterns: [
            "if.*production.*display_errors.*0",
            "if.*dev.*display_errors.*1",
            "getenv.*APP_ENV.*production"
          ],
          configuration_files: [
            "config",
            "settings",
            "bootstrap",
            "init",
            "env",
            ".env"
          ]
        }
      ]
    }
  end
end
